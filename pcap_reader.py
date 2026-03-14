"""
pcap_reader.py
PCAP file reading.
Equivalent to include/pcap_reader.h + src/pcap_reader.cpp
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from typing import Optional, Tuple


# ============================================================================
# PCAP Global Header (24 bytes)
# ============================================================================
@dataclass
class PcapGlobalHeader:
    magic_number: int = 0
    version_major: int = 0
    version_minor: int = 0
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 0
    network: int = 0

    # Raw bytes of the header as read from file (for verbatim re-writing)
    raw_bytes: bytes = field(default=b'', repr=False)

    STRUCT_FMT = '<IHHiIII'   # little-endian (native); re-checked after magic
    SIZE = 24


# ============================================================================
# PCAP Packet Header (16 bytes)
# ============================================================================
@dataclass
class PcapPacketHeader:
    ts_sec: int = 0
    ts_usec: int = 0
    incl_len: int = 0
    orig_len: int = 0

    STRUCT_FMT_LE = '<IIII'
    STRUCT_FMT_BE = '>IIII'
    SIZE = 16


# ============================================================================
# Raw Packet
# ============================================================================
@dataclass
class RawPacket:
    header: PcapPacketHeader = field(default_factory=PcapPacketHeader)
    data: bytes = b''


# ============================================================================
# Magic numbers
# ============================================================================
PCAP_MAGIC_NATIVE  = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1


# ============================================================================
# PcapReader
# ============================================================================
class PcapReader:
    def __init__(self):
        self._file = None
        self._global_header = PcapGlobalHeader()
        self._needs_byte_swap: bool = False

    def __del__(self):
        self.close()

    def open(self, filename: str) -> bool:
        self.close()

        try:
            self._file = open(filename, 'rb')
        except OSError as e:
            print(f"Error: Could not open file: {filename}")
            return False

        # Read the global header (24 bytes)
        raw = self._file.read(PcapGlobalHeader.SIZE)
        if len(raw) < PcapGlobalHeader.SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        # Read magic number first (always little-endian in file for native, big for swapped)
        magic = struct.unpack_from('<I', raw, 0)[0]

        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
            fmt = '<IHHiIII'
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            fmt = '>IHHiIII'
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
            self.close()
            return False

        fields = struct.unpack_from(fmt, raw, 0)
        gh = PcapGlobalHeader(
            magic_number  = fields[0],
            version_major = fields[1],
            version_minor = fields[2],
            thiszone      = fields[3],
            sigfigs       = fields[4],
            snaplen       = fields[5],
            network       = fields[6],
            raw_bytes     = raw,
        )
        self._global_header = gh

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {gh.version_major}.{gh.version_minor}")
        print(f"  Snaplen: {gh.snaplen} bytes")
        link_label = " (Ethernet)" if gh.network == 1 else ""
        print(f"  Link type: {gh.network}{link_label}")

        return True

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False

    def read_next_packet(self, packet: RawPacket) -> bool:
        if self._file is None:
            return False

        # Read packet header (16 bytes)
        raw_hdr = self._file.read(PcapPacketHeader.SIZE)
        if len(raw_hdr) < PcapPacketHeader.SIZE:
            return False  # EOF or error

        fmt = '>IIII' if self._needs_byte_swap else '<IIII'
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, raw_hdr)

        # Sanity check
        if incl_len > self._global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return False

        # Read packet data
        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return False

        packet.header.ts_sec = ts_sec
        packet.header.ts_usec = ts_usec
        packet.header.incl_len = incl_len
        packet.header.orig_len = orig_len
        packet.data = data

        return True

    def get_global_header(self) -> PcapGlobalHeader:
        return self._global_header

    def is_open(self) -> bool:
        return self._file is not None

    def needs_byte_swap(self) -> bool:
        return self._needs_byte_swap

    def _maybe_swap16(self, value: int) -> int:
        if not self._needs_byte_swap:
            return value
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)

    def _maybe_swap32(self, value: int) -> int:
        if not self._needs_byte_swap:
            return value
        return (
            ((value & 0xFF000000) >> 24) |
            ((value & 0x00FF0000) >> 8)  |
            ((value & 0x0000FF00) << 8)  |
            ((value & 0x000000FF) << 24)
        )
