"""
platform_utils.py
Portable byte-order conversion functions.
Equivalent to include/platform.h
"""

import sys
import struct


def swap_bytes16(value: int) -> int:
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)


def swap_bytes32(value: int) -> int:
    return (
        ((value & 0xFF000000) >> 24) |
        ((value & 0x00FF0000) >> 8)  |
        ((value & 0x0000FF00) << 8)  |
        ((value & 0x000000FF) << 24)
    )


def is_little_endian() -> bool:
    return sys.byteorder == 'little'


def net_to_host16(net_value: int) -> int:
    if is_little_endian():
        return swap_bytes16(net_value)
    return net_value


def net_to_host32(net_value: int) -> int:
    if is_little_endian():
        return swap_bytes32(net_value)
    return net_value


def host_to_net16(host_value: int) -> int:
    return net_to_host16(host_value)


def host_to_net32(host_value: int) -> int:
    return net_to_host32(host_value)
