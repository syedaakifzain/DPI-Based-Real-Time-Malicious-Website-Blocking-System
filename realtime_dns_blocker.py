"""
realtime_dns_blocker.py
Real-time DNS blocker that sniffs UDP port 53, matches queries against
RuleManager blocking rules, and spoofs a DNS reply (0.0.0.0) for blocked domains.

Requires:
  - scapy  (pip install scapy)
  - root / sudo on Linux

Usage (imported by run_realtime.py, or run standalone):
    sudo python3 realtime_dns_blocker.py [--block-domain example.com] \
                                         [--block-ip 1.2.3.4]        \
                                         [--rules rules.txt]          \
                                         [--iface eth0]
"""

from __future__ import annotations

import argparse
import sys
import signal
import socket
import struct
import threading
from typing import Optional

# ---------------------------------------------------------------------------
# Scapy import with a clear error message
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff, send,
        IP, UDP, DNS, DNSQR, DNSRR,
        conf as scapy_conf,
    )
    from scapy.layers.dns import DNS
except ImportError:
    print("[ERROR] Scapy is not installed.\n"
          "       Install it with:  pip install scapy\n"
          "       Then re-run with: sudo python3 realtime_dns_blocker.py",
          file=sys.stderr)
    sys.exit(1)

from rule_manager import RuleManager

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

BLOCKED_IP = "0.0.0.0"          # spoofed answer for blocked domains
DNS_PORT   = 53


# ===========================================================================
# RealtimeDNSBlocker
# ===========================================================================
class RealtimeDNSBlocker:
    """
    Sniffs live DNS queries on UDP/53, checks each queried domain (and the
    source IP) against a RuleManager instance, and injects a spoofed DNS
    reply that resolves the domain to 0.0.0.0 so the browser gets
    NXDOMAIN-equivalent behaviour instantly.
    """

    def __init__(
        self,
        rule_manager: RuleManager,
        iface: Optional[str] = None,
        verbose: bool = True,
    ) -> None:
        self._rm      = rule_manager
        self._iface   = iface          # None → sniff on all interfaces
        self._verbose = verbose
        self._running = False
        self._lock    = threading.Lock()

        # statistics
        self._total_queries  = 0
        self._blocked_count  = 0
        self._allowed_count  = 0

        # Suppress scapy's verbose output
        scapy_conf.verb = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start sniffing (blocking call – run in a thread or main thread)."""
        with self._lock:
            if self._running:
                return
            self._running = True

        iface_str = self._iface or "all interfaces"
        print(f"\n{_BOLD}{_CYAN}[DNS Blocker]{_RESET} "
              f"Listening on {_BOLD}{iface_str}{_RESET} – UDP port {DNS_PORT}")
        print(f"{_BOLD}{_CYAN}[DNS Blocker]{_RESET} "
              f"Spoofed reply → {BLOCKED_IP}  |  Press Ctrl+C to stop\n")

        kwargs: dict = dict(
            filter="udp port 53",
            prn=self._handle_packet,
            store=False,           # don't accumulate packets in RAM
            stop_filter=lambda _: not self._running,
        )
        if self._iface:
            kwargs["iface"] = self._iface

        sniff(**kwargs)

    def stop(self) -> None:
        """Signal the sniffer to stop."""
        with self._lock:
            self._running = False
        print(f"\n{_BOLD}{_CYAN}[DNS Blocker]{_RESET} Stopping…")
        self._print_stats()

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------
    def _handle_packet(self, pkt) -> None:
        """Called by Scapy for every captured DNS packet."""
        # We only care about DNS *query* packets (QR == 0)
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return

        dns_layer = pkt[DNS]

        # QR=0 → query; QR=1 → response (skip responses)
        if dns_layer.qr != 0:
            return

        # Must have at least one question
        if dns_layer.qdcount < 1 or not dns_layer.qd:
            return

        src_ip  = pkt[IP].src
        qname   = self._decode_qname(dns_layer.qd.qname)
        qtype   = dns_layer.qd.qtype    # e.g. 1 = A, 28 = AAAA

        self._total_queries += 1

        # ── check RuleManager ──────────────────────────────────────
        src_ip_int  = self._ip_str_to_int(src_ip)
        ip_blocked  = self._rm.is_ip_blocked(src_ip_int)
        dom_blocked = self._rm.is_domain_blocked(qname)

        if ip_blocked or dom_blocked:
            self._blocked_count += 1
            reason = src_ip if ip_blocked else qname
            print(f"{_RED}{_BOLD}[BLOCKED]{_RESET}  "
                  f"{_BOLD}{qname}{_RESET}  "
                  f"from {_YELLOW}{src_ip}{_RESET}  "
                  f"(matched: {_RED}{reason}{_RESET})")
            self._send_blocked_reply(pkt, dns_layer, qname, qtype)
        else:
            self._allowed_count += 1
            if self._verbose:
                print(f"{_GREEN}[ALLOWED]{_RESET}  "
                      f"{qname}  from {src_ip}")

    # ------------------------------------------------------------------
    # Spoofed reply builder
    # ------------------------------------------------------------------
    def _send_blocked_reply(
        self,
        pkt,
        dns_layer,
        qname: str,
        qtype: int,
    ) -> None:
        """
        Craft and inject a spoofed DNS reply that resolves *qname* to
        0.0.0.0 (for A queries) or an empty AAAA, effectively blocking
        the domain.
        """
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

        # Build the answer record
        if qtype == 28:   # AAAA – return empty, no answer
            answer = None
        else:             # A (and anything else) – return 0.0.0.0
            answer = DNSRR(
                rrname=dns_layer.qd.qname,
                type="A",
                ttl=1,
                rdata=BLOCKED_IP,
            )

        spoofed = (
            IP(src=dst_ip, dst=src_ip) /
            UDP(sport=dst_port, dport=src_port) /
            DNS(
                id=dns_layer.id,
                qr=1,           # this is a response
                aa=1,           # authoritative
                rd=dns_layer.rd,
                ra=1,
                qdcount=1,
                ancount=1 if answer else 0,
                qd=DNSQR(qname=dns_layer.qd.qname, qtype=qtype),
                an=answer,
            )
        )

        try:
            send(spoofed, verbose=False)
        except Exception as exc:
            print(f"[WARN] Failed to send spoofed reply: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_qname(raw) -> str:
        """Decode Scapy's bytes qname to a clean string without trailing dot."""
        if isinstance(raw, bytes):
            name = raw.decode("ascii", errors="replace")
        else:
            name = str(raw)
        return name.rstrip(".")

    @staticmethod
    def _ip_str_to_int(ip: str) -> int:
        """Convert '1.2.3.4' → little-endian packed int matching RuleManager."""
        parts = ip.split(".")
        if len(parts) != 4:
            return 0
        try:
            a, b, c, d = (int(x) for x in parts)
            return a | (b << 8) | (c << 16) | (d << 24)
        except ValueError:
            return 0

    def _print_stats(self) -> None:
        print(
            f"\n{_BOLD}{'─'*50}{_RESET}\n"
            f"  Total DNS queries : {self._total_queries}\n"
            f"  {_RED}Blocked{_RESET}           : {self._blocked_count}\n"
            f"  {_GREEN}Allowed{_RESET}           : {self._allowed_count}\n"
            f"{_BOLD}{'─'*50}{_RESET}"
        )


# ===========================================================================
# CLI entry-point (standalone usage)
# ===========================================================================
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="realtime_dns_blocker.py",
        description="Real-time DNS blocker – requires sudo on Linux",
    )
    p.add_argument("--block-domain", metavar="DOMAIN",  action="append",
                   default=[], help="Domain to block (repeatable, wildcards ok: *.example.com)")
    p.add_argument("--block-ip",     metavar="IP",       action="append",
                   default=[], help="Source IP to block (repeatable)")
    p.add_argument("--rules",        metavar="FILE",
                   help="Load rules from a saved rules file")
    p.add_argument("--iface",        metavar="IFACE",
                   help="Network interface to sniff on (default: all)")
    p.add_argument("--quiet",        action="store_true",
                   help="Don't print ALLOWED lines, only BLOCKED")
    return p


def main() -> None:
    args = _build_arg_parser().parse_args()

    rm = RuleManager()

    # Load persisted rules first
    if args.rules:
        rm.load_rules(args.rules)

    # Apply CLI rules on top
    for domain in args.block_domain:
        rm.block_domain(domain)
    for ip in args.block_ip:
        rm.block_ip(ip)

    stats = rm.get_stats()
    print(f"\n[RuleManager] Active rules → "
          f"IPs: {stats.blocked_ips}  "
          f"Domains: {stats.blocked_domains}  "
          f"Apps: {stats.blocked_apps}  "
          f"Ports: {stats.blocked_ports}")

    blocker = RealtimeDNSBlocker(
        rule_manager=rm,
        iface=args.iface,
        verbose=not args.quiet,
    )

    # Graceful shutdown on Ctrl+C / SIGTERM
    def _shutdown(sig, frame):
        blocker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    blocker.start()


if __name__ == "__main__":
    main()
