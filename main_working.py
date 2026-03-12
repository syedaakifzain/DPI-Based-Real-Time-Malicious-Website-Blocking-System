"""
main_working.py
Working DPI Engine – Simplified but functional (single-threaded).
Equivalent to src/main_working.cpp
"""

import sys
import struct
from typing import Dict, List, Set

from packet_parser import PacketParser, ParsedPacket
from pcap_reader import PcapPacketHeader, PcapReader, RawPacket
from sni_extractor import HTTPHostExtractor, SNIExtractor
from types_ import AppType, FiveTuple, app_type_to_string, sni_to_app_type


# ============================================================================
# Simplified flow
# ============================================================================
class Flow:
    def __init__(self):
        self.tuple:    FiveTuple = FiveTuple()
        self.app_type: AppType   = AppType.UNKNOWN
        self.sni:      str       = ""
        self.packets:  int       = 0
        self.bytes:    int       = 0
        self.blocked:  bool      = False


# ============================================================================
# Blocking rules
# ============================================================================
class BlockingRules:
    def __init__(self):
        self.blocked_ips:     Set[int] = set()
        self.blocked_apps:    Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(self._parse_ip(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        for i in range(int(AppType.APP_COUNT)):
            if app_type_to_string(AppType(i)) == app:
                self.blocked_apps.add(AppType(i))
                print(f"[Rules] Blocked app: {app}")
                return
        print(f"[Rules] Unknown app: {app}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for dom in self.blocked_domains:
            if dom in sni:
                return True
        return False

    @staticmethod
    def _parse_ip(ip: str) -> int:
        result = 0
        octet  = 0
        shift  = 0
        for c in ip:
            if c == '.':
                result |= (octet << shift)
                shift  += 8
                octet   = 0
            elif c.isdigit():
                octet = octet * 10 + int(c)
        result |= (octet << shift)
        return result


def _parse_ip(ip: str) -> int:
    return BlockingRules._parse_ip(ip)


def print_usage(prog: str) -> None:
    print(f"""
DPI Engine - Deep Packet Inspection System
==========================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main() -> int:
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        return 1

    input_file  = sys.argv[1]
    output_file = sys.argv[2]

    rules = BlockingRules()

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
        i += 1

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    # Open input
    reader = PcapReader()
    if not reader.open(input_file):
        return 1

    # Open output
    try:
        output = open(output_file, 'wb')
    except OSError:
        print("Error: Cannot open output file")
        return 1

    # Write PCAP global header verbatim
    header = reader.get_global_header()
    output.write(header.raw_bytes)

    flows:           Dict[FiveTuple, Flow] = {}
    total_packets:   int = 0
    forwarded:       int = 0
    dropped:         int = 0
    app_stats:       Dict[AppType, int] = {}

    raw    = RawPacket()
    parsed = ParsedPacket()

    print("[DPI] Processing packets...")

    while reader.read_next_packet(raw):
        total_packets += 1

        if not PacketParser.parse(raw, parsed):
            continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        # Build five-tuple
        tuple_ = FiveTuple(
            src_ip   = _parse_ip(parsed.src_ip),
            dst_ip   = _parse_ip(parsed.dest_ip),
            src_port = parsed.src_port,
            dst_port = parsed.dest_port,
            protocol = parsed.protocol,
        )

        # Get or create flow
        if tuple_ not in flows:
            flows[tuple_] = Flow()
            flows[tuple_].tuple = tuple_
        flow = flows[tuple_]
        flow.packets += 1
        flow.bytes   += len(raw.data)

        # -------- TLS SNI extraction --------
        if ((flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS)
                and not flow.sni and parsed.has_tcp and parsed.dest_port == 443):
            payload_offset = 14
            if len(raw.data) > 14:
                ip_ihl = raw.data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if payload_offset + 12 < len(raw.data):
                    tcp_off = (raw.data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                    if payload_offset < len(raw.data):
                        payload = raw.data[payload_offset:]
                        if len(payload) > 5:
                            sni = SNIExtractor.extract(payload, len(payload))
                            if sni:
                                flow.sni      = sni
                                flow.app_type = sni_to_app_type(sni)

        # -------- HTTP Host extraction --------
        if ((flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP)
                and not flow.sni and parsed.has_tcp and parsed.dest_port == 80):
            payload_offset = 14
            if len(raw.data) > 14:
                ip_ihl = raw.data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if payload_offset + 12 < len(raw.data):
                    tcp_off = (raw.data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_off * 4
                    if payload_offset < len(raw.data):
                        payload = raw.data[payload_offset:]
                        host = HTTPHostExtractor.extract(payload, len(payload))
                        if host:
                            flow.sni      = host
                            flow.app_type = sni_to_app_type(host)

        # -------- DNS --------
        if (flow.app_type == AppType.UNKNOWN and
                (parsed.dest_port == 53 or parsed.src_port == 53)):
            flow.app_type = AppType.DNS

        # -------- Port-based fallback --------
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # -------- Check blocking rules --------
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                info = appstr = app_type_to_string(flow.app_type)
                if flow.sni:
                    info += f": {flow.sni}"
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({info})")

        # -------- Update app stats --------
        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        # -------- Forward or drop --------
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            pkt_hdr = struct.pack('<IIII',
                                  raw.header.ts_sec,
                                  raw.header.ts_usec,
                                  len(raw.data),
                                  len(raw.data))
            output.write(pkt_hdr)
            output.write(raw.data)

    reader.close()
    output.close()

    # -------- Print report --------
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:>10}                             ║")
    print(f"║ Forwarded:          {forwarded:>10}                             ║")
    print(f"║ Dropped:            {dropped:>10}                             ║")
    print(f"║ Active Flows:       {len(flows):>10}                             ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda x: -x[1])
    for app, count in sorted_apps:
        pct     = 100.0 * count / total_packets if total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar     = '#' * bar_len
        print(f"║ {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

    print("╚══════════════════════════════════════════════════════════════╝")

    # -------- Detected SNIs --------
    print("\n[Detected Applications/Domains]")
    unique_snis: Dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type
    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
