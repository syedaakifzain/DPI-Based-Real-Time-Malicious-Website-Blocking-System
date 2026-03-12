"""
connection_tracker.py
Per-FP connection/flow tracking.
Equivalent to include/connection_tracker.h + src/connection_tracker.cpp
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set

from types_ import (
    AppType, Connection, ConnectionState, FiveTuple, PacketAction,
    app_type_to_string
)


# ============================================================================
# ConnectionTracker
# ============================================================================
class ConnectionTracker:

    @dataclass
    class TrackerStats:
        active_connections:      int = 0
        total_connections_seen:  int = 0
        classified_connections:  int = 0
        blocked_connections:     int = 0

    # ------------------------------------------------------------------ #
    def __init__(self, fp_id: int, max_connections: int = 100_000):
        self._fp_id            = fp_id
        self._max_connections  = max_connections
        self._connections:     Dict[FiveTuple, Connection] = {}
        self._total_seen:      int = 0
        self._classified_count: int = 0
        self._blocked_count:   int = 0

    # ------------------------------------------------------------------ #
    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn

        if len(self._connections) >= self._max_connections:
            self._evict_oldest()

        conn = Connection(tuple_)
        conn.first_seen = time.monotonic()
        conn.last_seen  = conn.first_seen
        self._connections[tuple_] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn
        # Try reverse tuple (bidirectional)
        rev = self._connections.get(tuple_.reverse())
        return rev

    def update_connection(self, conn: Connection,
                          packet_size: int, is_outbound: bool) -> None:
        if conn is None:
            return
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out   += packet_size
        else:
            conn.packets_in  += 1
            conn.bytes_in    += packet_size

    def classify_connection(self, conn: Connection,
                             app: AppType, sni: str) -> None:
        if conn is None:
            return
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni      = sni
            conn.state    = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        if conn is None:
            return
        conn.state  = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        conn = self._connections.get(tuple_)
        if conn is not None:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        now     = time.monotonic()
        to_del  = [k for k, v in self._connections.items()
                   if (now - v.last_seen) > timeout_seconds
                   or v.state == ConnectionState.CLOSED]
        for k in to_del:
            del self._connections[k]
        return len(to_del)

    def get_all_connections(self) -> List[Connection]:
        return list(self._connections.values())

    def get_active_count(self) -> int:
        return len(self._connections)

    def get_stats(self) -> 'ConnectionTracker.TrackerStats':
        return ConnectionTracker.TrackerStats(
            active_connections      = len(self._connections),
            total_connections_seen  = self._total_seen,
            classified_connections  = self._classified_count,
            blocked_connections     = self._blocked_count,
        )

    def clear(self) -> None:
        self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in list(self._connections.values()):
            callback(conn)

    def _evict_oldest(self) -> None:
        if not self._connections:
            return
        oldest_key = min(self._connections, key=lambda k: self._connections[k].last_seen)
        del self._connections[oldest_key]


# ============================================================================
# GlobalConnectionTable
# ============================================================================
class GlobalConnectionTable:

    @dataclass
    class GlobalStats:
        total_active_connections: int = 0
        total_connections_seen:   int = 0
        app_distribution:         dict = None   # AppType -> int
        top_domains:              list = None   # [(domain, count)]

        def __post_init__(self):
            if self.app_distribution is None:
                self.app_distribution = {}
            if self.top_domains is None:
                self.top_domains = []

    # ------------------------------------------------------------------ #
    def __init__(self, num_fps: int):
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._mutex    = threading.Lock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        with self._mutex:
            if fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    def get_global_stats(self) -> 'GlobalConnectionTable.GlobalStats':
        with self._mutex:
            trackers = list(self._trackers)

        stats = GlobalConnectionTable.GlobalStats()
        domain_counts: Dict[str, int] = {}

        for tracker in trackers:
            if tracker is None:
                continue
            ts = tracker.get_stats()
            stats.total_active_connections += ts.active_connections
            stats.total_connections_seen   += ts.total_connections_seen

            def _collect(conn: Connection):
                stats.app_distribution[conn.app_type] = \
                    stats.app_distribution.get(conn.app_type, 0) + 1
                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

            tracker.for_each(_collect)

        sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1])
        stats.top_domains = sorted_domains[:20]
        return stats

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines = []
        lines.append("\n╔══════════════════════════════════════════════════════════════╗")
        lines.append("║               CONNECTION STATISTICS REPORT                    ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append(f"║ Active Connections:     {stats.total_active_connections:>10}                          ║")
        lines.append(f"║ Total Connections Seen: {stats.total_connections_seen:>10}                          ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║                    APPLICATION BREAKDOWN                      ║")
        lines.append("╠══════════════════════════════════════════════════════════════╣")

        total = sum(stats.app_distribution.values())
        sorted_apps = sorted(stats.app_distribution.items(), key=lambda x: -x[1])
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            line = (f"║ {app_type_to_string(app):<20}{count:>10}"
                    f" ({pct:>5.1f}%)           ║")
            lines.append(line)

        if stats.top_domains:
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            lines.append("║                      TOP DOMAINS                             ║")
            lines.append("╠══════════════════════════════════════════════════════════════╣")
            for domain, count in stats.top_domains:
                d = domain[:35] if len(domain) > 35 else domain
                lines.append(f"║ {d:<40}{count:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
