"""
run_realtime.py
Entry point for the Real-time DNS Blocker.

Loads blocking rules (from CLI flags and/or a saved rules file), then
starts sniffing UDP port 53 and spoofing replies for blocked domains.

Usage:
    sudo python3 run_realtime.py [options]

Examples:
    # Block a single domain
    sudo python3 run_realtime.py --block-domain youtube.com

    # Block multiple domains + wildcard
    sudo python3 run_realtime.py \
        --block-domain tiktok.com \
        --block-domain "*.facebook.com" \
        --block-domain instagram.com

    # Block a source IP
    sudo python3 run_realtime.py --block-ip 192.168.1.50

    # Load rules from a file saved by the DPI engine
    sudo python3 run_realtime.py --rules my_rules.txt

    # Restrict to one interface and suppress ALLOWED lines
    sudo python3 run_realtime.py --block-domain ads.com --iface eth0 --quiet

    # Save current rules back after running
    sudo python3 run_realtime.py --block-domain evil.com --save-rules my_rules.txt
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import textwrap

# ---------------------------------------------------------------------------
# Must be root on Linux for raw socket access
# ---------------------------------------------------------------------------
if os.name == "posix" and os.geteuid() != 0:
    print(
        "\n[ERROR] This script requires root privileges.\n"
        "        Please re-run with:  sudo python3 run_realtime.py\n",
        file=sys.stderr,
    )
    sys.exit(1)

from rule_manager import RuleManager
from realtime_dns_blocker import RealtimeDNSBlocker

# ANSI
_BOLD  = "\033[1m"
_CYAN  = "\033[96m"
_RESET = "\033[0m"

BANNER = r"""
  ____  _   _ ____    ____  _            _
 |  _ \| \ | / ___|  | __ )| | ___   ___| | _____ _ __
 | | | |  \| \___ \  |  _ \| |/ _ \ / __| |/ / _ \ '__|
 | |_| | |\  |___) | | |_) | | (_) | (__|   <  __/ |
 |____/|_| \_|____/  |____/|_|\___/ \___|_|\_\___|_|

  Real-time DNS Blocker  ·  spoofs 0.0.0.0 for blocked domains
"""


# ===========================================================================
# Argument parser
# ===========================================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_realtime.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Real-time DNS blocker – sniffs UDP/53, spoofs replies for
            blocked domains so browsers fail instantly.
            Must be run as root (sudo).
        """),
        epilog=textwrap.dedent("""\
            Supported wildcard syntax:  *.example.com
            This matches example.com AND any subdomain of it.
        """),
    )

    block_group = p.add_argument_group("Blocking rules")
    block_group.add_argument(
        "--block-domain", metavar="DOMAIN", action="append", default=[],
        help="Domain or wildcard pattern to block (repeatable)",
    )
    block_group.add_argument(
        "--block-ip", metavar="IP", action="append", default=[],
        help="Block all DNS queries that originate from this source IP (repeatable)",
    )
    block_group.add_argument(
        "--rules", metavar="FILE",
        help="Load rules from a file previously saved by the DPI engine",
    )

    output_group = p.add_argument_group("Output / persistence")
    output_group.add_argument(
        "--save-rules", metavar="FILE",
        help="Save all active rules to FILE before exiting",
    )
    output_group.add_argument(
        "--quiet", action="store_true",
        help="Only print [BLOCKED] lines; suppress [ALLOWED] output",
    )

    net_group = p.add_argument_group("Network")
    net_group.add_argument(
        "--iface", metavar="IFACE",
        help="Network interface to sniff on (default: all interfaces)",
    )

    return p


# ===========================================================================
# Main
# ===========================================================================
def main() -> None:
    print(_BOLD + _CYAN + BANNER + _RESET)

    parser = _build_parser()
    args   = parser.parse_args()

    # ── Build RuleManager ─────────────────────────────────────────────────
    rm = RuleManager()

    if args.rules:
        if not rm.load_rules(args.rules):
            print(f"[WARN] Could not load rules from '{args.rules}' – continuing anyway.")
    else:
        # Provide helpful hint when no rules are loaded
        if not args.block_domain and not args.block_ip:
            print(
                "[WARN] No blocking rules specified.\n"
                "       All DNS queries will be ALLOWED.\n"
                "       Use --block-domain, --block-ip, or --rules to add rules.\n"
            )

    for domain in args.block_domain:
        rm.block_domain(domain)

    for ip in args.block_ip:
        rm.block_ip(ip)

    # ── Print summary of active rules ─────────────────────────────────────
    stats = rm.get_stats()
    print(
        f"\n{_BOLD}Active blocking rules:{_RESET}\n"
        f"  Domains  : {stats.blocked_domains}\n"
        f"  IPs      : {stats.blocked_ips}\n"
        f"  Apps     : {stats.blocked_apps}\n"
        f"  Ports    : {stats.blocked_ports}\n"
    )

    if stats.blocked_domains or stats.blocked_ips:
        print("  Blocked domains :", rm.get_blocked_domains() or "(none)")
        print("  Blocked IPs     :", rm.get_blocked_ips()     or "(none)")
        print()

    # ── Create blocker ────────────────────────────────────────────────────
    blocker = RealtimeDNSBlocker(
        rule_manager=rm,
        iface=args.iface,
        verbose=not args.quiet,
    )

    # ── Graceful shutdown ─────────────────────────────────────────────────
    def _shutdown(sig, frame):
        blocker.stop()
        if args.save_rules:
            if rm.save_rules(args.save_rules):
                print(f"[RuleManager] Rules saved to '{args.save_rules}'")
            else:
                print(f"[WARN] Failed to save rules to '{args.save_rules}'", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Start blocking ────────────────────────────────────────────────────
    blocker.start()


if __name__ == "__main__":
    main()
