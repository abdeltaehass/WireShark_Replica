"""Reader for the pcapng file format, which Wireshark saves by default.

A pcapng file is a sequence of blocks. Every block starts with its type and
total length and repeats the total length at the end::

    block type (4) | total length (4) | body (padded to 4 bytes) | total length (4)

A file has one or more sections. Each section starts with a Section Header
Block whose byte-order magic sets the byte order for the whole section, then
Interface Description Blocks describe the interfaces its packets were captured
on. Each interface has its own link type and timestamp resolution. Packets
arrive in Enhanced Packet Blocks, Simple Packet Blocks or the obsolete Packet
Block. Other block types are skipped.

Reference: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.formats.pcap import ByteOrder
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND

SECTION_HEADER_MAGIC = b"\x0a\x0d\x0d\x0a"

BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_PACKET = 0x00000002
BLOCK_SIMPLE_PACKET = 0x00000003
BLOCK_ENHANCED_PACKET = 0x00000006

BYTE_ORDER_MAGIC = 0x1A2B3C4D

OPTION_END = 0
OPTION_IF_NAME = 2
OPTION_IF_TSRESOL = 9
OPTION_IF_TSOFFSET = 14

# Smallest body each block type can have, excluding the 12 bytes of framing.
_MIN_BODY = {
    BLOCK_SECTION_HEADER: 16,
    BLOCK_INTERFACE_DESCRIPTION: 8,
    BLOCK_PACKET: 20,
    BLOCK_SIMPLE_PACKET: 4,
    BLOCK_ENHANCED_PACKET: 20,
}
_FRAMING = 12


def _structs(fmt: str) -> dict[ByteOrder, struct.Struct]:
    return {"<": struct.Struct("<" + fmt), ">": struct.Struct(">" + fmt)}


_U32 = _structs("I")
_BLOCK_HEADER = _structs("II")
_SECTION_HEADER = _structs("IHHq")
_INTERFACE = _structs("HHI")
_ENHANCED_PACKET = _structs("IIIII")
_PACKET = _structs("HHIIII")
_OPTION = _structs("HH")
_I64 = _structs("q")


@dataclass(frozen=True, slots=True)
class Interface:
    """An interface described by an Interface Description Block."""

    link_type: int
    snaplen: int
    units_per_second: int = 1_000_000
    """Timestamp resolution from ``if_tsresol``; microseconds when the option is absent."""
    offset_seconds: int = 0
    """Seconds added to every timestamp, from ``if_tsoffset``."""
    name: str | None = None

    def timestamp_ns(self, ticks: int) -> int:
        return ticks * NS_PER_SECOND // self.units_per_second + self.offset_seconds * NS_PER_SECOND


class PcapngReader:
    """Iterates over the packets of a pcapng file held in memory."""

    def __init__(self, data: memoryview) -> None:
        if len(data) < 4 or data[:4] != SECTION_HEADER_MAGIC:
            raise CaptureFileError("not a pcapng file (no Section Header Block at the start)")
        self._data = data

    def __iter__(self) -> Iterator[Packet]:
        data = self._data
        end = len(data)
        byte_order: ByteOrder = "<"
        interfaces: list[Interface] = []
        offset = 0
        while offset < end:
            if end - offset < _FRAMING:
                raise CaptureFileError(f"block at offset {offset} is cut short")
            block_type, total_length = _BLOCK_HEADER[byte_order].unpack_from(data, offset)
            if block_type == BLOCK_SECTION_HEADER:
                # The type reads the same in either byte order; the magic after
                # the length says which order this section uses.
                byte_order = _section_byte_order(data, offset)
                (total_length,) = _U32[byte_order].unpack_from(data, offset + 4)
                interfaces = []
            body_start, body_end = _check_block(data, offset, block_type, total_length, byte_order)

            if block_type == BLOCK_ENHANCED_PACKET:
                interface_id, high, low, captured_length, original_length = _ENHANCED_PACKET[
                    byte_order
                ].unpack_from(data, body_start)
                interface = _interface(interfaces, interface_id, offset)
                yield Packet(
                    timestamp_ns=interface.timestamp_ns((high << 32) | low),
                    original_length=original_length,
                    link_type=interface.link_type,
                    data=_packet_data(data, body_start + 20, body_end, captured_length, offset),
                    interface_id=interface_id,
                )
            elif block_type == BLOCK_SIMPLE_PACKET:
                # No interface ID or timestamp: the packet belongs to interface 0,
                # and the capture length is the original length cut to its snap length.
                (original_length,) = _U32[byte_order].unpack_from(data, body_start)
                interface = _interface(interfaces, 0, offset)
                captured_length = original_length
                if interface.snaplen:
                    captured_length = min(captured_length, interface.snaplen)
                yield Packet(
                    timestamp_ns=None,
                    original_length=original_length,
                    link_type=interface.link_type,
                    data=_packet_data(data, body_start + 4, body_end, captured_length, offset),
                )
            elif block_type == BLOCK_PACKET:
                interface_id, _drops, high, low, captured_length, original_length = _PACKET[
                    byte_order
                ].unpack_from(data, body_start)
                interface = _interface(interfaces, interface_id, offset)
                yield Packet(
                    timestamp_ns=interface.timestamp_ns((high << 32) | low),
                    original_length=original_length,
                    link_type=interface.link_type,
                    data=_packet_data(data, body_start + 20, body_end, captured_length, offset),
                    interface_id=interface_id,
                )
            elif block_type == BLOCK_INTERFACE_DESCRIPTION:
                interfaces.append(_parse_interface(data, body_start, body_end, byte_order))
            elif block_type == BLOCK_SECTION_HEADER:
                _, major, minor, _ = _SECTION_HEADER[byte_order].unpack_from(data, body_start)
                if major != 1:
                    raise CaptureFileError(
                        f"section at offset {offset} has unsupported pcapng version {major}.{minor}"
                    )
            offset += total_length

    def close(self) -> None:
        self._data.release()


def _section_byte_order(data: memoryview, offset: int) -> ByteOrder:
    (magic,) = _U32["<"].unpack_from(data, offset + 8)
    if magic == BYTE_ORDER_MAGIC:
        return "<"
    (magic,) = _U32[">"].unpack_from(data, offset + 8)
    if magic == BYTE_ORDER_MAGIC:
        return ">"
    raise CaptureFileError(f"section header at offset {offset} has a bad byte-order magic")


def _check_block(
    data: memoryview, offset: int, block_type: int, total_length: int, byte_order: ByteOrder
) -> tuple[int, int]:
    """Validate a block's framing and return where its body starts and ends."""
    if total_length % 4:
        raise CaptureFileError(
            f"block at offset {offset} has length {total_length}, which isn't a multiple of 4"
        )
    minimum = _FRAMING + _MIN_BODY.get(block_type, 0)
    if total_length < minimum:
        raise CaptureFileError(
            f"block at offset {offset} has length {total_length}; this type needs {minimum}"
        )
    if offset + total_length > len(data):
        raise CaptureFileError(
            f"block at offset {offset} is cut short: {len(data) - offset} of {total_length} bytes"
        )
    (trailing_length,) = _U32[byte_order].unpack_from(data, offset + total_length - 4)
    if trailing_length != total_length:
        raise CaptureFileError(
            f"block at offset {offset} starts with length {total_length} "
            f"but ends with {trailing_length}"
        )
    return offset + 8, offset + total_length - 4


def _interface(interfaces: list[Interface], interface_id: int, offset: int) -> Interface:
    if interface_id >= len(interfaces):
        count = len(interfaces)
        raise CaptureFileError(
            f"packet at offset {offset} refers to interface {interface_id}, "
            f"but its section describes {count} interface{'' if count == 1 else 's'}"
        )
    return interfaces[interface_id]


def _packet_data(
    data: memoryview, start: int, body_end: int, captured_length: int, offset: int
) -> memoryview:
    if start + captured_length > body_end:
        raise CaptureFileError(
            f"packet at offset {offset} claims {captured_length} bytes, more than its block holds"
        )
    return data[start : start + captured_length]


def _parse_interface(
    data: memoryview, body_start: int, body_end: int, byte_order: ByteOrder
) -> Interface:
    link_type, _, snaplen = _INTERFACE[byte_order].unpack_from(data, body_start)
    units_per_second = 1_000_000
    offset_seconds = 0
    name = None
    for code, value in _options(data, body_start + 8, body_end, byte_order):
        if code == OPTION_IF_TSRESOL and len(value) >= 1:
            # High bit clear: resolution is 10**-n seconds. Set: 2**-n seconds.
            exponent = value[0] & 0x7F
            units_per_second = 2**exponent if value[0] & 0x80 else 10**exponent
        elif code == OPTION_IF_TSOFFSET and len(value) >= 8:
            (offset_seconds,) = _I64[byte_order].unpack_from(value)
        elif code == OPTION_IF_NAME:
            name = bytes(value).decode("utf-8", errors="replace").rstrip("\0")
    return Interface(link_type, snaplen, units_per_second, offset_seconds, name)


def _options(
    data: memoryview, start: int, end: int, byte_order: ByteOrder
) -> Iterator[tuple[int, memoryview]]:
    """Yield (code, value) for each option between ``start`` and ``end``."""
    header = _OPTION[byte_order]
    offset = start
    while end - offset >= 4:
        code, length = header.unpack_from(data, offset)
        if code == OPTION_END:
            return
        value_start = offset + 4
        if value_start + length > end:
            raise CaptureFileError(f"option at offset {offset} runs past the end of its block")
        yield code, data[value_start : value_start + length]
        offset = value_start + ((length + 3) & ~3)
