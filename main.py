"""
main.py
Packet Analyzer v1.0 – reads a PCAP and pretty-prints every packet.
Equivalent to src/main.cpp
"""

import sys
import time
from datetime import datetime

from packet_parser import EtherType, PacketParser, ParsedPacket
from pcap_reader import PcapReader, RawPacket


def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    dt = datetime.fromtimestamp(pkt.timestamp_sec)
    time_str = dt.strftime("%Y-%m-%d %H:%M:%S") + f".{pkt.timestamp_usec:06d}"

    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {time_str}")

    # Ethernet layer
    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    etype_label = ""
    if pkt.ether_type == EtherType.IPv4:
        etype_label = " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        etype_label = " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        etype_label = " (ARP)"
    print(f"  EtherType:       0x{pkt.ether_type:04x}{etype_label}")

    # IP layer
    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")

    # TCP layer
    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")

    # UDP layer
    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    # Payload info
    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview_len = min(pkt.payload_length, 32)
        preview = " ".join(f"{b:02x}" for b in pkt.payload_data[:preview_len])
        if pkt.payload_length > 32:
            preview += " ..."
        print(f"  Preview: {preview}")


def print_usage(program_name: str) -> None:
    print(f"Usage: {program_name} <pcap_file> [max_packets]")
    print("\nArguments:")
    print("  pcap_file   - Path to a .pcap file captured by Wireshark")
    print("  max_packets - (Optional) Maximum number of packets to display")
    print("\nExample:")
    print(f"  {program_name} capture.pcap")
    print(f"  {program_name} capture.pcap 10")


def main() -> int:
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    if len(sys.argv) < 2:
        print_usage(sys.argv[0])
        return 1

    filename    = sys.argv[1]
    max_packets = -1
    if len(sys.argv) >= 3:
        max_packets = int(sys.argv[2])

    reader = PcapReader()
    if not reader.open(filename):
        return 1

    print("\n--- Reading packets ---")

    raw_packet    = RawPacket()
    parsed_packet = ParsedPacket()
    packet_count  = 0
    parse_errors  = 0

    while reader.read_next_packet(raw_packet):
        packet_count += 1

        if PacketParser.parse(raw_packet, parsed_packet):
            print_packet_summary(parsed_packet, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
