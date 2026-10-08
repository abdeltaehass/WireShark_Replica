"""Writing packets to pcap and pcapng files.

Both writers take packets one at a time and put each one on the stream as it
comes, so a live capture can be written as it runs and a reader at the other
end of a pipe sees packets as they arrive. Timestamps are written in
nanoseconds, the resolution pilotfish holds them in, so nothing is rounded
away.

A pcap file has one link type, set in its header. A pcapng file describes
each interface in a block of its own, so packets from interfaces with
different link types can share it, which is why pcapng is the default.
"""

import struct
from collections.abc import Mapping
from typing import BinaryIO, Protocol

from pilotfish import __version__
from pilotfish.core.formats.pcap import MAGIC_NANOSECONDS
from pilotfish.core.formats.pcapng import (
    BLOCK_ENHANCED_PACKET,
    BLOCK_INTERFACE_DESCRIPTION,
    BLOCK_SECTION_HEADER,
    BYTE_ORDER_MAGIC,
    OPTION_END,
    OPTION_IF_NAME,
    OPTION_IF_TSRESOL,
)
from pilotfish.core.formats.reader import FileFormat
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND

APPLICATION = f"pilotfish {__version__}"
"""What a pcapng file says wrote it."""

DEFAULT_LINK_TYPE = 1
"""The link type a pcap file is given when no packet ever says otherwise: Ethernet."""

SNAPLEN = 262_144
"""The snapshot length written into headers: libpcap's largest."""

OPTION_SHB_USERAPPL = 4
NANOSECONDS = 9
"""``if_tsresol`` for timestamps in units of 10**-9 seconds."""


class WriteError(Exception):
    """Packets can't be written in the format asked for."""


class CaptureWriter(Protocol):
    """Somewhere packets are written, in one file format or another."""

    def write(self, packet: Packet) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None:
        """Finish the file. The stream itself is left open for its owner to close."""
        ...


def open_writer(
    stream: BinaryIO,
    file_format: FileFormat,
    *,
    link_type: int | None = None,
    interface_names: Mapping[int, str] | None = None,
) -> CaptureWriter:
    """A writer of ``file_format`` onto ``stream``.

    ``link_type`` is what a pcap file's header says when it is known before
    the first packet arrives, as it is for a live capture. Interface names
    go into a pcapng file's interface descriptions.
    """
    if file_format is FileFormat.PCAP:
        return PcapWriter(stream, link_type)
    return PcapngWriter(stream, interface_names)


class PcapWriter:
    """The classic libpcap format, with nanosecond timestamps.

    Its header holds the link type, and so it is written once the first
    packet shows what that is, or when the file is closed with none.
    """

    _HEADER = struct.Struct("<IHHiIII")
    _RECORD = struct.Struct("<IIII")

    def __init__(self, stream: BinaryIO, link_type: int | None = None) -> None:
        self._stream = stream
        self._link_type = link_type
        self._started = False

    def write(self, packet: Packet) -> None:
        if not self._started:
            if self._link_type is None:
                self._link_type = packet.link_type
            self._start()
        if packet.link_type != self._link_type:
            raise WriteError(
                f"a pcap file holds packets of one link type, and this capture has "
                f"{self._link_type} and {packet.link_type}; write pcapng instead"
            )
        # A packet the capture gave no time to has to be given one here,
        # since every pcap record has one.
        seconds, nanoseconds = divmod(packet.timestamp_ns or 0, NS_PER_SECOND)
        record = self._RECORD.pack(
            seconds, nanoseconds, packet.captured_length, packet.original_length
        )
        self._stream.write(record)
        self._stream.write(packet.data)

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        if not self._started:
            self._start()
        self._stream.flush()

    def _start(self) -> None:
        link_type = DEFAULT_LINK_TYPE if self._link_type is None else self._link_type
        self._stream.write(self._HEADER.pack(MAGIC_NANOSECONDS, 2, 4, 0, 0, SNAPLEN, link_type))
        self._started = True


class PcapngWriter:
    """The pcapng format, one interface description for each interface seen.

    The section header goes out straight away, and each interface's
    description just before its first packet. An interface is told apart by
    the number it had in the capture and its link type, since a live capture
    calls its only interface 0 whatever it is.
    """

    _BLOCK_HEADER = struct.Struct("<II")
    _SECTION = struct.Struct("<IHHq")
    _INTERFACE = struct.Struct("<HHI")
    _ENHANCED = struct.Struct("<IIIII")
    _OPTION = struct.Struct("<HH")

    def __init__(self, stream: BinaryIO, interface_names: Mapping[int, str] | None = None) -> None:
        self._stream = stream
        self._names = dict(interface_names or {})
        self._interfaces: dict[tuple[int, int], int] = {}
        # Section length -1: not given, so readers don't rely on it.
        section = self._SECTION.pack(BYTE_ORDER_MAGIC, 1, 0, -1)
        options = self._option(OPTION_SHB_USERAPPL, APPLICATION.encode()) + self._end()
        self._block(BLOCK_SECTION_HEADER, section + options)

    def write(self, packet: Packet) -> None:
        interface = self._interface(packet)
        ticks = packet.timestamp_ns or 0
        body = self._ENHANCED.pack(
            interface,
            ticks >> 32,
            ticks & 0xFFFFFFFF,
            packet.captured_length,
            packet.original_length,
        )
        self._block(BLOCK_ENHANCED_PACKET, body + _padded(bytes(packet.data)))

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self._stream.flush()

    def _interface(self, packet: Packet) -> int:
        """The number of the interface description this packet's interface has here."""
        key = (packet.interface_id, packet.link_type)
        number = self._interfaces.get(key)
        if number is None:
            number = self._interfaces[key] = len(self._interfaces)
            # Snapshot length 0: no limit is recorded.
            body = self._INTERFACE.pack(packet.link_type, 0, 0)
            name = self._names.get(packet.interface_id)
            if name is not None:
                body += self._option(OPTION_IF_NAME, name.encode())
            body += self._option(OPTION_IF_TSRESOL, bytes([NANOSECONDS])) + self._end()
            self._block(BLOCK_INTERFACE_DESCRIPTION, body)
        return number

    def _block(self, block_type: int, body: bytes) -> None:
        total = len(body) + 12
        length = total.to_bytes(4, "little")
        self._stream.write(self._BLOCK_HEADER.pack(block_type, total) + body + length)

    def _option(self, code: int, value: bytes) -> bytes:
        return self._OPTION.pack(code, len(value)) + _padded(value)

    def _end(self) -> bytes:
        return self._OPTION.pack(OPTION_END, 0)


def _padded(data: bytes) -> bytes:
    """``data`` followed by zeros up to a multiple of four bytes, as pcapng wants."""
    return data + bytes(-len(data) % 4)
