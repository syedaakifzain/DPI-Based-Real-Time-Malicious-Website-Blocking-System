"""
types.py
Core data structures and enumerations.
Equivalent to include/types.h + src/types.cpp
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import time


# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
class FiveTuple:
    __slots__ = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol')

    def __init__(self,
                 src_ip: int = 0,
                 dst_ip: int = 0,
                 src_port: int = 0,
                 dst_port: int = 0,
                 protocol: int = 0):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def __eq__(self, other) -> bool:
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def __hash__(self) -> int:
        h = 0
        for val in (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol):
            h ^= hash(val) + 0x9e3779b9 + (h << 6) + (h >> 2)
            h &= 0xFFFFFFFFFFFFFFFF
        return h

    def reverse(self) -> 'FiveTuple':
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def to_string(self) -> str:
        def fmt_ip(ip):
            return (f"{(ip >> 0) & 0xFF}.{(ip >> 8) & 0xFF}."
                    f"{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}")

        proto = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else "?")
        return f"{fmt_ip(self.src_ip)}:{self.src_port} -> {fmt_ip(self.dst_ip)}:{self.dst_port} ({proto})"

    def __repr__(self) -> str:
        return f"FiveTuple({self.to_string()})"


# ============================================================================
# Application Classification
# ============================================================================
class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


def app_type_to_string(app_type: AppType) -> str:
    mapping = {
        AppType.UNKNOWN:    "Unknown",
        AppType.HTTP:       "HTTP",
        AppType.HTTPS:      "HTTPS",
        AppType.DNS:        "DNS",
        AppType.TLS:        "TLS",
        AppType.QUIC:       "QUIC",
        AppType.GOOGLE:     "Google",
        AppType.FACEBOOK:   "Facebook",
        AppType.YOUTUBE:    "YouTube",
        AppType.TWITTER:    "Twitter/X",
        AppType.INSTAGRAM:  "Instagram",
        AppType.NETFLIX:    "Netflix",
        AppType.AMAZON:     "Amazon",
        AppType.MICROSOFT:  "Microsoft",
        AppType.APPLE:      "Apple",
        AppType.WHATSAPP:   "WhatsApp",
        AppType.TELEGRAM:   "Telegram",
        AppType.TIKTOK:     "TikTok",
        AppType.SPOTIFY:    "Spotify",
        AppType.ZOOM:       "Zoom",
        AppType.DISCORD:    "Discord",
        AppType.GITHUB:     "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return mapping.get(app_type, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # Google (check before YouTube because YouTube CDN domains contain 'ggpht')
    if any(x in lower_sni for x in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # YouTube
    if any(x in lower_sni for x in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # Facebook/Meta
    if any(x in lower_sni for x in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # Instagram
    if any(x in lower_sni for x in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp
    if any(x in lower_sni for x in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # Twitter/X
    if any(x in lower_sni for x in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    # Netflix
    if any(x in lower_sni for x in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Amazon
    if any(x in lower_sni for x in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Microsoft
    if any(x in lower_sni for x in ("microsoft", "msn.com", "office", "azure",
                                     "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Apple
    if any(x in lower_sni for x in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(x in lower_sni for x in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(x in lower_sni for x in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(x in lower_sni for x in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM

    # Discord
    if any(x in lower_sni for x in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(x in lower_sni for x in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(x in lower_sni for x in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # SNI present but unrecognized → HTTPS
    return AppType.HTTPS


# ============================================================================
# Connection State
# ============================================================================
class ConnectionState(IntEnum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


# ============================================================================
# Packet Action
# ============================================================================
class PacketAction(IntEnum):
    FORWARD = 0
    DROP = 1
    INSPECT = 2
    LOG_ONLY = 3


# ============================================================================
# Connection Entry
# ============================================================================
class Connection:
    __slots__ = (
        'tuple', 'state', 'app_type', 'sni',
        'packets_in', 'packets_out', 'bytes_in', 'bytes_out',
        'first_seen', 'last_seen', 'action',
        'syn_seen', 'syn_ack_seen', 'fin_seen',
    )

    def __init__(self, five_tuple: Optional[FiveTuple] = None):
        self.tuple: FiveTuple = five_tuple if five_tuple else FiveTuple()
        self.state: ConnectionState = ConnectionState.NEW
        self.app_type: AppType = AppType.UNKNOWN
        self.sni: str = ""
        self.packets_in: int = 0
        self.packets_out: int = 0
        self.bytes_in: int = 0
        self.bytes_out: int = 0
        self.first_seen: float = time.monotonic()
        self.last_seen: float = self.first_seen
        self.action: PacketAction = PacketAction.FORWARD
        self.syn_seen: bool = False
        self.syn_ack_seen: bool = False
        self.fin_seen: bool = False


# ============================================================================
# Packet wrapper for queue passing
# ============================================================================
class PacketJob:
    __slots__ = (
        'packet_id', 'tuple', 'data',
        'eth_offset', 'ip_offset', 'transport_offset',
        'payload_offset', 'payload_length', 'tcp_flags',
        'ts_sec', 'ts_usec',
    )

    def __init__(self):
        self.packet_id: int = 0
        self.tuple: FiveTuple = FiveTuple()
        self.data: bytes = b''
        self.eth_offset: int = 0
        self.ip_offset: int = 0
        self.transport_offset: int = 0
        self.payload_offset: int = 0
        self.payload_length: int = 0
        self.tcp_flags: int = 0
        self.ts_sec: int = 0
        self.ts_usec: int = 0


# ============================================================================
# Statistics
# ============================================================================
class DPIStats:
    """Thread-safe statistics using locks around int counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.forwarded_packets: int = 0
        self.dropped_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.other_packets: int = 0
        self.active_connections: int = 0

    def increment(self, field: str, amount: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field) + amount)

    def get(self, field: str) -> int:
        with self._lock:
            return getattr(self, field)
