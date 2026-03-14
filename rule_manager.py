"""
rule_manager.py
Thread-safe blocking/filtering rule manager.
Equivalent to include/rule_manager.h + src/rule_manager.cpp
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Set

from types_ import AppType, app_type_to_string


# ============================================================================
# RuleManager
# ============================================================================
class RuleManager:

    class BlockReasonType(IntEnum):
        IP     = 0
        APP    = 1
        DOMAIN = 2
        PORT   = 3

    @dataclass
    class BlockReason:
        type:   'RuleManager.BlockReasonType'
        detail: str

    # ------------------------------------------------------------------ #
    def __init__(self):
        self._ip_lock     = threading.RLock()
        self._app_lock    = threading.RLock()
        self._domain_lock = threading.RLock()
        self._port_lock   = threading.RLock()

        self._blocked_ips:     Set[int] = set()
        self._blocked_apps:    Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._domain_patterns: List[str] = []
        self._blocked_ports:   Set[int] = set()

    # ======================== IP ======================== #
    def block_ip(self, ip) -> None:
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.add(ip)
        print(f"[RuleManager] Blocked IP: {self._ip_to_string(ip)}")

    def unblock_ip(self, ip) -> None:
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.discard(ip)
        print(f"[RuleManager] Unblocked IP: {self._ip_to_string(ip)}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._ip_lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._ip_lock:
            return [self._ip_to_string(ip) for ip in self._blocked_ips]

    # ======================== APP ======================== #
    def block_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType) -> None:
        with self._app_lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._app_lock:
            return list(self._blocked_apps)

    # ======================== DOMAIN ======================== #
    def block_domain(self, domain: str) -> None:
        with self._domain_lock:
            if '*' in domain:
                self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        with self._domain_lock:
            if '*' in domain:
                try:
                    self._domain_patterns.remove(domain)
                except ValueError:
                    pass
            else:
                self._blocked_domains.discard(domain)
        print(f"[RuleManager] Unblocked domain: {domain}")

    def is_domain_blocked(self, domain: str) -> bool:
        with self._domain_lock:
            if domain in self._blocked_domains:
                return True
            lower = domain.lower()
            for pattern in self._domain_patterns:
                if self._domain_matches_pattern(lower, pattern.lower()):
                    return True
        return False

    def get_blocked_domains(self) -> List[str]:
        with self._domain_lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    # ======================== PORT ======================== #
    def block_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._port_lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._port_lock:
            return port in self._blocked_ports

    # ======================== COMBINED ======================== #
    def should_block(self,
                     src_ip:   int,
                     dst_port: int,
                     app:      AppType,
                     domain:   str) -> Optional['RuleManager.BlockReason']:
        if self.is_ip_blocked(src_ip):
            return RuleManager.BlockReason(
                RuleManager.BlockReasonType.IP, self._ip_to_string(src_ip))

        if self.is_port_blocked(dst_port):
            return RuleManager.BlockReason(
                RuleManager.BlockReasonType.PORT, str(dst_port))

        if self.is_app_blocked(app):
            return RuleManager.BlockReason(
                RuleManager.BlockReasonType.APP, app_type_to_string(app))

        if domain and self.is_domain_blocked(domain):
            return RuleManager.BlockReason(
                RuleManager.BlockReasonType.DOMAIN, domain)

        return None

    # ======================== PERSISTENCE ======================== #
    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, 'w') as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(ip + "\n")

                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(app_type_to_string(app) + "\n")

                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(domain + "\n")

                f.write("\n[BLOCKED_PORTS]\n")
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(str(port) + "\n")
            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError:
            return False

    def load_rules(self, filename: str) -> bool:
        try:
            with open(filename, 'r') as f:
                current_section = ""
                for line in f:
                    line = line.rstrip('\n').rstrip('\r')
                    if not line:
                        continue
                    if line.startswith('['):
                        current_section = line
                        continue
                    if current_section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif current_section == "[BLOCKED_APPS]":
                        for i in range(int(AppType.APP_COUNT)):
                            if app_type_to_string(AppType(i)) == line:
                                self.block_app(AppType(i))
                                break
                    elif current_section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif current_section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))
            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError:
            return False

    def clear_all(self) -> None:
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    # ======================== STATS ======================== #
    @dataclass
    class RuleStats:
        blocked_ips:     int = 0
        blocked_apps:    int = 0
        blocked_domains: int = 0
        blocked_ports:   int = 0

    def get_stats(self) -> 'RuleManager.RuleStats':
        with self._ip_lock:
            ips = len(self._blocked_ips)
        with self._app_lock:
            apps = len(self._blocked_apps)
        with self._domain_lock:
            domains = len(self._blocked_domains) + len(self._domain_patterns)
        with self._port_lock:
            ports = len(self._blocked_ports)
        return RuleManager.RuleStats(ips, apps, domains, ports)

    # ======================== HELPERS ======================== #
    @staticmethod
    def _parse_ip(ip: str) -> int:
        result = 0
        octet  = 0
        shift  = 0
        for c in ip:
            if c == '.':
                result |= (octet << shift)
                shift += 8
                octet = 0
            elif c.isdigit():
                octet = octet * 10 + int(c)
        result |= (octet << shift)
        return result

    @staticmethod
    def _ip_to_string(ip: int) -> str:
        return (f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}."
                f"{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}")

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """Supports *.example.com wildcard patterns."""
        if len(pattern) >= 2 and pattern[0] == '*' and pattern[1] == '.':
            suffix = pattern[1:]   # .example.com
            if len(domain) >= len(suffix) and domain.endswith(suffix):
                return True
            bare = pattern[2:]     # example.com
            if domain == bare:
                return True
        return False
