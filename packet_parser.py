"""
packet_parser.py
Network protocol header parsing (Ethernet / IPv4 / TCP / UDP).
Equivalent to include/packet_parser.h + src/packet_parser.cpp
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from pcap_reader import RawPacket
from platform_utils import net_to_host16, net_to_host32


# ============================================================================
# TCP Flag constants
# ============================================================================
class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


# ============================================================================
# Protocol numbers
# ============================================================================
class Protocol:
    ICMP = 1
    TCP  = 6
    UDP  = 17


# ============================================================================
# EtherType values
# ============================================================================
class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP  = 0x0806


# ============================================================================
# Parsed packet
# ============================================================================
@dataclass
class ParsedPacket:
    # Timestamps
    timestamp_sec:  int = 0
    timestamp_usec: int = 0

    # Ethernet layer
    src_mac:    str   = ""
    dest_mac:   str   = ""
    ether_type: int   = 0

    # IP layer
    has_ip:     bool  = False
    ip_version: int   = 0
    src_ip:     str   = ""
    dest_ip:    str   = ""
    protocol:   int   = 0
    ttl:        int   = 0

    # Transport layer
    has_tcp:    bool  = False
    has_udp:    bool  = False
    src_port:   int   = 0
    dest_port:  int   = 0

    # TCP-specific
    tcp_flags:  int   = 0
    seq_number: int   = 0
    ack_number: int   = 0

    # Payload
    payload_length: int   = 0
    payload_data:   bytes = b''   # slice of packet data


# ============================================================================
# PacketParser
# ============================================================================
class PacketParser:

    @staticmethod
    def parse(raw: RawPacket, parsed: ParsedPacket) -> bool:
        # Reset
        parsed.__init__()
        parsed.timestamp_sec  = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data = raw.data
        length = len(data)
        offset = 0

        if not PacketParser._parse_ethernet(data, length, parsed, offset):
            return False
        offset = 14  # Ethernet header is always 14 bytes

        if parsed.ether_type == EtherType.IPv4:
            new_offset = [offset]
            if not PacketParser._parse_ipv4(data, length, parsed, new_offset):
                return False
            offset = new_offset[0]

            if parsed.protocol == Protocol.TCP:
                new_offset = [offset]
                if not PacketParser._parse_tcp(data, length, parsed, new_offset):
                    return False
                offset = new_offset[0]
            elif parsed.protocol == Protocol.UDP:
                new_offset = [offset]
                if not PacketParser._parse_udp(data, length, parsed, new_offset):
                    return False
                offset = new_offset[0]

        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data   = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data   = b''

        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_ethernet(data: bytes, length: int,
                        parsed: ParsedPacket, offset: int) -> bool:
        ETH_HEADER_LEN = 14
        if length < ETH_HEADER_LEN:
            return False

        parsed.dest_mac  = PacketParser.mac_to_string(data[0:6])
        parsed.src_mac   = PacketParser.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack_from('>H', data, 12)[0]
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_ipv4(data: bytes, length: int,
                   parsed: ParsedPacket, offset_ref: list) -> bool:
        offset = offset_ref[0]
        MIN_IP = 20
        if length < offset + MIN_IP:
            return False

        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False

        ip_header_len = ihl * 4
        if ip_header_len < MIN_IP or length < offset + ip_header_len:
            return False

        parsed.ttl      = data[offset + 8]
        parsed.protocol = data[offset + 9]

        src_ip_raw  = struct.unpack_from('>I', data, offset + 12)[0]
        dest_ip_raw = struct.unpack_from('>I', data, offset + 16)[0]

        parsed.src_ip  = PacketParser.ip_to_string_be(src_ip_raw)
        parsed.dest_ip = PacketParser.ip_to_string_be(dest_ip_raw)

        parsed.has_ip = True
        offset_ref[0] = offset + ip_header_len
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_tcp(data: bytes, length: int,
                  parsed: ParsedPacket, offset_ref: list) -> bool:
        offset = offset_ref[0]
        MIN_TCP = 20
        if length < offset + MIN_TCP:
            return False

        parsed.src_port  = struct.unpack_from('>H', data, offset)[0]
        parsed.dest_port = struct.unpack_from('>H', data, offset + 2)[0]
        parsed.seq_number = struct.unpack_from('>I', data, offset + 4)[0]
        parsed.ack_number = struct.unpack_from('>I', data, offset + 8)[0]

        data_offset = (data[offset + 12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4
        parsed.tcp_flags = data[offset + 13]

        if tcp_header_len < MIN_TCP or length < offset + tcp_header_len:
            return False

        parsed.has_tcp = True
        offset_ref[0] = offset + tcp_header_len
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_udp(data: bytes, length: int,
                  parsed: ParsedPacket, offset_ref: list) -> bool:
        offset = offset_ref[0]
        UDP_HEADER_LEN = 8
        if length < offset + UDP_HEADER_LEN:
            return False

        parsed.src_port  = struct.unpack_from('>H', data, offset)[0]
        parsed.dest_port = struct.unpack_from('>H', data, offset + 2)[0]
        parsed.has_udp = True
        offset_ref[0] = offset + UDP_HEADER_LEN
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in mac[:6])

    @staticmethod
    def ip_to_string(ip: int) -> str:
        """ip stored in little-endian uint32 (as C++ does after memcpy from network)."""
        return (f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}."
                f"{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}")

    @staticmethod
    def ip_to_string_be(ip: int) -> str:
        """ip stored in big-endian uint32 (direct from struct.unpack '>I')."""
        return (f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}."
                f"{(ip >> 8) & 0xFF}.{ip & 0xFF}")

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return mapping.get(protocol, f"Unknown({protocol})")

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN: parts.append("SYN")
        if flags & TCPFlags.ACK: parts.append("ACK")
        if flags & TCPFlags.FIN: parts.append("FIN")
        if flags & TCPFlags.RST: parts.append("RST")
        if flags & TCPFlags.PSH: parts.append("PSH")
        if flags & TCPFlags.URG: parts.append("URG")
        return " ".join(parts) if parts else "none"
