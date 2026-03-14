"""
sni_extractor.py
TLS SNI, HTTP Host header, DNS query, and QUIC SNI extractors.
Equivalent to include/sni_extractor.h + src/sni_extractor.cpp
"""

from __future__ import annotations

import struct
from typing import Optional, List, Tuple


# ============================================================================
# SNIExtractor – parses TLS Client Hello to find SNI
# ============================================================================
class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI          = 0x0000
    SNI_TYPE_HOSTNAME      = 0x00

    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_uint16_be(data: bytes, offset: int) -> int:
        return (data[offset] << 8) | data[offset + 1]

    @staticmethod
    def _read_uint24_be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    # ------------------------------------------------------------------ #
    @staticmethod
    def is_tls_client_hello(payload: bytes, length: int) -> bool:
        if length < 9:
            return False

        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False

        version = SNIExtractor._read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False

        record_length = SNIExtractor._read_uint16_be(payload, 3)
        if record_length > length - 5:
            return False

        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    # ------------------------------------------------------------------ #
    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload, length):
            return None

        # Skip TLS record header (5 bytes)
        offset = 5

        # Skip handshake header: type (1) + length (3)
        # handshake_length = SNIExtractor._read_uint24_be(payload, offset + 1)
        offset += 4

        # Skip Client version (2 bytes)
        offset += 2

        # Skip Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        # Cipher suites
        if offset + 2 > length:
            return None
        cipher_suites_length = SNIExtractor._read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length

        # Compression methods
        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        # Extensions length
        if offset + 2 > length:
            return None
        extensions_length = SNIExtractor._read_uint16_be(payload, offset)
        offset += 2

        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length  # truncated – try anyway

        # Walk extensions
        while offset + 4 <= extensions_end:
            extension_type   = SNIExtractor._read_uint16_be(payload, offset)
            extension_length = SNIExtractor._read_uint16_be(payload, offset + 2)
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == SNIExtractor.EXTENSION_SNI:
                # SNI Extension:
                #   SNI List Length (2) | SNI Type (1) | SNI Length (2) | SNI Value
                if extension_length < 5:
                    break

                sni_list_length = SNIExtractor._read_uint16_be(payload, offset)
                if sni_list_length < 3:
                    break

                sni_type   = payload[offset + 2]
                sni_length = SNIExtractor._read_uint16_be(payload, offset + 3)

                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break

                sni = payload[offset + 5: offset + 5 + sni_length].decode('ascii', errors='replace')
                return sni

            offset += extension_length

        return None

    # ------------------------------------------------------------------ #
    @staticmethod
    def extract_extensions(payload: bytes, length: int) -> List[Tuple[int, str]]:
        """Extract all TLS extensions (for debug/logging)."""
        extensions: List[Tuple[int, str]] = []
        # Abbreviated – returns empty list (mirrors the C++ stub)
        return extensions


# ============================================================================
# HTTPHostExtractor
# ============================================================================
class HTTPHostExtractor:
    HTTP_METHODS = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]

    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        if length < 4:
            return False
        prefix = payload[:4]
        return any(prefix == m for m in HTTPHostExtractor.HTTP_METHODS)

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload, length):
            return None

        i = 0
        while i + 5 < length:
            if (payload[i:i+1].upper() == b'H' and
                payload[i+1:i+2].upper() == b'O' and
                payload[i+2:i+3].upper() == b'S' and
                payload[i+3:i+4].upper() == b'T' and
                payload[i+4:i+5] == b':'):

                start = i + 5
                # Skip whitespace
                while start < length and payload[start:start+1] in (b' ', b'\t'):
                    start += 1

                # Find end of line
                end = start
                while end < length and payload[end:end+1] not in (b'\r', b'\n'):
                    end += 1

                if end > start:
                    host = payload[start:end].decode('ascii', errors='replace')
                    # Remove port if present
                    colon = host.find(':')
                    if colon != -1:
                        host = host[:colon]
                    return host
            i += 1

        return None


# ============================================================================
# DNSExtractor
# ============================================================================
class DNSExtractor:

    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        if length < 12:
            return False
        flags = payload[2]
        if flags & 0x80:
            return False  # This is a response
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0

    @staticmethod
    def extract_query(payload: bytes, length: int) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload, length):
            return None

        offset = 12
        domain_parts = []

        while offset < length:
            label_length = payload[offset]

            if label_length == 0:
                break

            if label_length > 63:
                break  # Compression pointer or invalid

            offset += 1
            if offset + label_length > length:
                break

            label = payload[offset:offset + label_length].decode('ascii', errors='replace')
            domain_parts.append(label)
            offset += label_length

        domain = '.'.join(domain_parts)
        return domain if domain else None


# ============================================================================
# QUICSNIExtractor (simplified)
# ============================================================================
class QUICSNIExtractor:

    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        if length < 5:
            return False
        first_byte = payload[0]
        # Long header form: most-significant bit set
        return (first_byte & 0x80) != 0

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload, length):
            return None

        # Search for TLS Client Hello pattern within the QUIC packet
        for i in range(length - 50):
            if payload[i] == 0x01:  # Client Hello handshake type
                start = max(0, i - 5)
                result = SNIExtractor.extract(payload[start:], length - start)
                if result:
                    return result

        return None
