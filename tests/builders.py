"""Build pcap and pcapng files in memory, including deliberately broken ones."""

import struct
from typing import Literal

type ByteOrder = Literal["<", ">"]


def pcap_header(
    order: ByteOrder = "<",
    *,
    nanosecond: bool = False,
    snaplen: int = 65535,
    link_type: int = 1,
    version: tuple[int, int] = (2, 4),
) -> bytes:
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    return struct.pack(order + "IHHiIII", magic, *version, 0, 0, snaplen, link_type)


def pcap_record(
    order: ByteOrder,
    seconds: int,
    fraction: int,
    data: bytes,
    original_length: int | None = None,
) -> bytes:
    length = len(data) if original_length is None else original_length
    return struct.pack(order + "IIII", seconds, fraction, len(data), length) + data


def _pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def block(order: ByteOrder, block_type: int, body: bytes) -> bytes:
    body = _pad(body)
    length = len(body) + 12
    return struct.pack(order + "II", block_type, length) + body + struct.pack(order + "I", length)


def option(order: ByteOrder, code: int, value: bytes) -> bytes:
    return struct.pack(order + "HH", code, len(value)) + _pad(value)


def options(order: ByteOrder, *items: bytes) -> bytes:
    return b"".join(items) + option(order, 0, b"") if items else b""


def section_header(
    order: ByteOrder = "<", *, version: tuple[int, int] = (1, 0), opts: bytes = b""
) -> bytes:
    body = struct.pack(order + "IHHq", 0x1A2B3C4D, *version, -1) + opts
    return block(order, 0x0A0D0D0A, body)


def interface_description(
    order: ByteOrder = "<",
    *,
    link_type: int = 1,
    snaplen: int = 0,
    tsresol: int | None = None,
    tsoffset: int | None = None,
    name: str | None = None,
) -> bytes:
    items = []
    if name is not None:
        items.append(option(order, 2, name.encode()))
    if tsresol is not None:
        items.append(option(order, 9, bytes([tsresol])))
    if tsoffset is not None:
        items.append(option(order, 14, struct.pack(order + "q", tsoffset)))
    body = struct.pack(order + "HHI", link_type, 0, snaplen) + options(order, *items)
    return block(order, 1, body)


def enhanced_packet(
    order: ByteOrder,
    interface_id: int,
    ticks: int,
    data: bytes,
    original_length: int | None = None,
    opts: bytes = b"",
) -> bytes:
    length = len(data) if original_length is None else original_length
    header = struct.pack(
        order + "IIIII", interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), length
    )
    return block(order, 6, header + _pad(data) + opts)


def packet_block(
    order: ByteOrder, interface_id: int, ticks: int, data: bytes, original_length: int | None = None
) -> bytes:
    length = len(data) if original_length is None else original_length
    header = struct.pack(
        order + "HHIIII", interface_id, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), length
    )
    return block(order, 2, header + data)


def simple_packet(order: ByteOrder, data: bytes, original_length: int | None = None) -> bytes:
    length = len(data) if original_length is None else original_length
    return block(order, 3, struct.pack(order + "I", length) + data)
