"""
main_simple.py
Simple single-threaded test version – prints every packet with SNI if found.
Equivalent to src/main_simple.cpp
"""

import sys

from packet_parser import PacketParser, ParsedPacket
from pcap_reader import PcapReader, RawPacket
from sni_extractor import SNIExtractor
from types_ import AppType


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>", file=sys.stderr)
        return 1

    reader = PcapReader()
    if not reader.open(sys.argv[1]):
        return 1

    raw    = RawPacket()
    parsed = ParsedPacket()
    count     = 0
    tls_count = 0

    print("Processing packets...")

    while reader.read_next_packet(raw):
        count += 1

        if not PacketParser.parse(raw, parsed):
            continue

        if not parsed.has_ip:
            continue

        line = (f"Packet {count}: "
                f"{parsed.src_ip}:{parsed.src_port} -> "
                f"{parsed.dest_ip}:{parsed.dest_port}")

        # Try SNI extraction for HTTPS packets
        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            payload_offset = 14  # Ethernet
            if len(raw.data) > 14:
                ip_ihl = raw.data[14] & 0x0F
                payload_offset += ip_ihl * 4
                if payload_offset + 12 < len(raw.data):
                    tcp_offset_byte = (raw.data[payload_offset + 12] >> 4) & 0x0F
                    payload_offset += tcp_offset_byte * 4
                    if payload_offset < len(raw.data):
                        payload = raw.data[payload_offset:]
                        sni = SNIExtractor.extract(payload, len(payload))
                        if sni:
                            line += f" [SNI: {sni}]"
                            tls_count += 1

        print(line)

    print(f"\nTotal packets: {count}")
    print(f"SNI extracted: {tls_count}")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
