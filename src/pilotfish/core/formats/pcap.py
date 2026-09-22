"""Reader for the classic libpcap file format.

All integers are in the byte order of the machine that wrote the file::

    global header, 24 bytes   magic, version major and minor, thiszone,
                              sigfigs, snap length, link type
    each packet, 16 bytes     seconds, fraction of a second, captured length,
                              original length, then the captured bytes

The magic number gives both the timestamp resolution and the byte order:
0xa1b2c3d4 means microseconds and 0xa1b23c4d nanoseconds, and finding either
one byte-swapped means the file came from a machine of the other endianness.

Reference: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.packet import Packet

type ByteOrder = Literal["<", ">"]

MAGIC_MICROSECONDS = 0xA1B2C3D4
MAGIC_NANOSECONDS = 0xA1B23C4D
# Alexey Kuznetzov's patched libpcap used this magic with a longer record header.
MAGIC_MODIFIED = 0xA1B2CD34

HEADER_SIZE = 24
RECORD_SIZE = 16

# The low 16 bits of the header's link type field hold the LINKTYPE value; the
# high bits can carry the length of a frame check sequence.
_LINK_TYPE_MASK = 0xFFFF

_MAGIC = struct.Struct("<I")
_HEADERS: dict[ByteOrder, struct.Struct] = {
    "<": struct.Struct("<IHHiIII"),
    ">": struct.Struct(">IHHiIII"),
}
_RECORDS: dict[ByteOrder, struct.Struct] = {
    "<": struct.Struct("<IIII"),
    ">": struct.Struct(">IIII"),
}


def _swapped(magic: int) -> int:
    return int.from_bytes(magic.to_bytes(4, "little"), "big")


# Magic as read in little-endian order -> (file byte order, nanosecond timestamps).
_MAGICS: dict[int, tuple[ByteOrder, bool]] = {
    MAGIC_MICROSECONDS: ("<", False),
    MAGIC_NANOSECONDS: ("<", True),
    _swapped(MAGIC_MICROSECONDS): (">", False),
    _swapped(MAGIC_NANOSECONDS): (">", True),
}


def is_pcap_magic(first_four_bytes: bytes) -> bool:
    (magic,) = _MAGIC.unpack(first_four_bytes)
    return magic in _MAGICS or magic in {MAGIC_MODIFIED, _swapped(MAGIC_MODIFIED)}


@dataclass(frozen=True, slots=True)
class PcapHeader:
    byte_order: ByteOrder
    version: tuple[int, int]
    nanosecond: bool
    snaplen: int
    link_type: int


class PcapReader:
    """Iterates over the packets of a pcap file held in memory."""

    def __init__(self, data: memoryview) -> None:
        if len(data) < HEADER_SIZE:
            raise CaptureFileError(
                f"pcap header needs {HEADER_SIZE} bytes but the file has {len(data)}"
            )
        (magic,) = _MAGIC.unpack_from(data)
        if magic in {MAGIC_MODIFIED, _swapped(MAGIC_MODIFIED)}:
            raise CaptureFileError("modified (Kuznetzov) pcap files aren't supported")
        if magic not in _MAGICS:
            raise CaptureFileError(f"not a pcap file (magic number 0x{magic:08x})")
        byte_order, nanosecond = _MAGICS[magic]
        _, major, minor, _, _, snaplen, link_type = _HEADERS[byte_order].unpack_from(data)
        if major != 2:
            raise CaptureFileError(f"unsupported pcap version {major}.{minor}")
        self.header = PcapHeader(
            byte_order=byte_order,
            version=(major, minor),
            nanosecond=nanosecond,
            snaplen=snaplen,
            link_type=link_type & _LINK_TYPE_MASK,
        )
        self._data = data

    def __iter__(self) -> Iterator[Packet]:
        data = self._data
        end = len(data)
        record = _RECORDS[self.header.byte_order]
        ns_per_tick = 1 if self.header.nanosecond else 1_000
        link_type = self.header.link_type
        offset = HEADER_SIZE
        while offset < end:
            if end - offset < RECORD_SIZE:
                raise CaptureFileError(
                    f"record header at offset {offset} is cut short: "
                    f"{end - offset} of {RECORD_SIZE} bytes"
                )
            seconds, fraction, captured_length, original_length = record.unpack_from(data, offset)
            start = offset + RECORD_SIZE
            stop = start + captured_length
            if stop > end:
                raise CaptureFileError(
                    f"packet at offset {offset} is cut short: "
                    f"{end - start} of {captured_length} bytes"
                )
            yield Packet(
                timestamp_ns=seconds * 1_000_000_000 + fraction * ns_per_tick,
                original_length=original_length,
                link_type=link_type,
                data=data[start:stop],
            )
            offset = stop

    def close(self) -> None:
        self._data.release()
