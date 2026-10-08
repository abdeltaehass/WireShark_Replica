"""Writing packets to pcap and pcapng files.

Both writers take packets one at a time and put each one on the stream as it
comes, so a live capture can be written as it runs and a reader at the other
end of a pipe sees packets as they arrive.

A packet read from a file points at the interface that file described, and
the writer describes it the same way: the same name, the same snapshot
length, and timestamps counted in the same units. So a file written from
another reads back with the same bytes, the same times and the same
comments. What is left out is what isn't about packets: name resolution,
interface statistics and custom blocks.

A pcap file has one link type and one timestamp resolution, both in its
header. A pcapng file describes each interface in a block of its own, so
packets from interfaces of different kinds can share it, which is why pcapng
is the default.
"""

import struct
from collections.abc import Mapping
from dataclasses import replace
from typing import BinaryIO, Protocol

from pilotfish import __version__
from pilotfish.core.formats.pcap import MAGIC_MICROSECONDS, MAGIC_NANOSECONDS
from pilotfish.core.formats.pcapng import (
    BLOCK_ENHANCED_PACKET,
    BLOCK_INTERFACE_DESCRIPTION,
    BLOCK_SECTION_HEADER,
    BLOCK_SIMPLE_PACKET,
    BYTE_ORDER_MAGIC,
    OPTION_COMMENT,
    OPTION_END,
    OPTION_IF_DESCRIPTION,
    OPTION_IF_NAME,
    OPTION_IF_TSOFFSET,
    OPTION_IF_TSRESOL,
)
from pilotfish.core.formats.reader import FileFormat
from pilotfish.core.packet import Interface, Packet
from pilotfish.core.timestamps import NS_PER_SECOND

APPLICATION = f"pilotfish {__version__}"
"""What a pcapng file says wrote it."""

DEFAULT_LINK_TYPE = 1
"""The link type a pcap file is given when no packet ever says otherwise: Ethernet."""

SNAPLEN = 262_144
"""The snapshot length written when nothing says what it was: libpcap's largest."""

MICROSECONDS = 1_000_000
NANOSECONDS = 1_000_000_000

OPTION_SHB_USERAPPL = 4


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
    nanoseconds: bool | None = None,
) -> CaptureWriter:
    """A writer of ``file_format`` onto ``stream``.

    ``link_type`` and ``nanoseconds`` are what a pcap file's header says,
    when they are known before the first packet arrives. Interface names are
    for packets that don't say which interface they came from.
    """
    if file_format is FileFormat.PCAP:
        return PcapWriter(stream, link_type, nanoseconds=nanoseconds)
    return PcapngWriter(stream, interface_names)


class PcapWriter:
    """The classic libpcap format.

    Its header holds the link type, the snapshot length and whether times
    are in microseconds or nanoseconds, and so it is written once the first
    packet shows what those are, or when the file is closed with none. A
    packet read from a microsecond file is written in microseconds again,
    and anything finer in nanoseconds.
    """

    _HEADER = struct.Struct("<IHHiIII")
    _RECORD = struct.Struct("<IIII")

    def __init__(
        self, stream: BinaryIO, link_type: int | None = None, *, nanoseconds: bool | None = None
    ) -> None:
        self._stream = stream
        self._link_type = link_type
        self._nanoseconds = nanoseconds
        self._snaplen = SNAPLEN
        self._started = False

    def write(self, packet: Packet) -> None:
        if not self._started:
            self._start(packet)
        if packet.link_type != self._link_type:
            raise WriteError(
                f"a pcap file holds packets of one link type, and this capture has "
                f"{self._link_type} and {packet.link_type}; write pcapng instead"
            )
        # A packet the capture gave no time to has to be given one here,
        # since every pcap record has one.
        seconds, nanoseconds = divmod(packet.timestamp_ns or 0, NS_PER_SECOND)
        if not self._nanoseconds:
            if nanoseconds % 1_000:
                raise WriteError(
                    "this pcap file counts microseconds, and a packet's time has nanoseconds "
                    "in it; write pcapng, which keeps each interface's own resolution"
                )
            nanoseconds //= 1_000
        record = self._RECORD.pack(
            seconds, nanoseconds, packet.captured_length, packet.original_length
        )
        self._stream.write(record)
        self._stream.write(packet.data)

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        if not self._started:
            self._start(None)
        self._stream.flush()

    def _start(self, first: Packet | None) -> None:
        interface = None if first is None else first.interface
        if self._link_type is None:
            self._link_type = DEFAULT_LINK_TYPE if first is None else first.link_type
        if self._nanoseconds is None:
            # Microseconds only when the packets were counted in them, so
            # that nothing finer is lost.
            self._nanoseconds = interface is None or interface.units_per_second != MICROSECONDS
        if interface is not None and interface.snaplen:
            self._snaplen = interface.snaplen
        magic = MAGIC_NANOSECONDS if self._nanoseconds else MAGIC_MICROSECONDS
        self._stream.write(self._HEADER.pack(magic, 2, 4, 0, 0, self._snaplen, self._link_type))
        self._started = True


class PcapngWriter:
    """The pcapng format, one interface description for each interface seen.

    The section header goes out straight away, and each interface's
    description just before its first packet. Interfaces that describe
    themselves the same way share a description, which is how packets from
    several files merged into one end up on the interfaces they had.

    A packet the capture gave no time to goes back into a Simple Packet
    Block, which can only be on a section's first interface. When it is on
    another, a new section starts, with its interface described first, as
    the file it came from must have done.
    """

    _BLOCK_HEADER = struct.Struct("<II")
    _SECTION = struct.Struct("<IHHq")
    _INTERFACE = struct.Struct("<HHI")
    _ENHANCED = struct.Struct("<IIIII")
    _OPTION = struct.Struct("<HH")

    def __init__(self, stream: BinaryIO, interface_names: Mapping[int, str] | None = None) -> None:
        self._stream = stream
        self._names = dict(interface_names or {})
        self._interfaces: dict[tuple[Interface, int], int] = {}
        """Each interface described in this section, by what it is, and its number."""
        self._section()

    def write(self, packet: Packet) -> None:
        interface, key = self._interface_of(packet)
        data = _padded(bytes(packet.data))
        options = b"".join(self._option(OPTION_COMMENT, text.encode()) for text in packet.comments)
        if options:
            options += self._end()
        if packet.timestamp_ns is None and self._simple(packet, interface, options):
            # The capture recorded no time, so the packet goes back into the
            # one block that has none, which belongs to the first interface.
            if self._interfaces.get(key, len(self._interfaces)) != 0:
                self._section()
            self._describe(interface, key)
            self._block(BLOCK_SIMPLE_PACKET, struct.pack("<I", packet.original_length) + data)
            return
        number = self._describe(interface, key)
        ticks = 0 if packet.timestamp_ns is None else interface.ticks(packet.timestamp_ns)
        body = self._ENHANCED.pack(
            number,
            ticks >> 32 & 0xFFFFFFFF,
            ticks & 0xFFFFFFFF,
            packet.captured_length,
            packet.original_length,
        )
        self._block(BLOCK_ENHANCED_PACKET, body + data + options)

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self._stream.flush()

    def _interface_of(self, packet: Packet) -> tuple[Interface, tuple[Interface, int]]:
        """The packet's interface, and what tells it apart from the others.

        A packet that doesn't say what its interface was gets one made up, in
        nanoseconds so that no time is rounded, and is told apart from other
        such packets by its interface number.
        """
        interface = packet.interface
        if interface is not None:
            time = packet.timestamp_ns
            if time is not None and interface.timestamp_ns(interface.ticks(time)) != time:
                # A time finer than the interface counts, as a packet whose
                # time was changed can have. Writing it as it is would round
                # it, so it goes on a copy of the interface that counts
                # nanoseconds.
                interface = replace(interface, units_per_second=NANOSECONDS)
            return interface, (interface, -1)
        name = self._names.get(packet.interface_id)
        interface = Interface(packet.link_type, 0, NANOSECONDS, name=name)
        return interface, (interface, packet.interface_id)

    def _section(self) -> None:
        """Start a section, which describes its interfaces afresh."""
        self._interfaces = {}
        # Section length -1: not given, so readers don't rely on it.
        section = self._SECTION.pack(BYTE_ORDER_MAGIC, 1, 0, -1)
        options = self._option(OPTION_SHB_USERAPPL, APPLICATION.encode()) + self._end()
        self._block(BLOCK_SECTION_HEADER, section + options)

    def _describe(self, interface: Interface, key: tuple[Interface, int]) -> int:
        """The number of the interface's description, written first if it is new."""
        number = self._interfaces.get(key)
        if number is not None:
            return number
        number = self._interfaces[key] = len(self._interfaces)
        body = self._INTERFACE.pack(interface.link_type, 0, interface.snaplen)
        if interface.name is not None:
            body += self._option(OPTION_IF_NAME, interface.name.encode())
        if interface.description is not None:
            body += self._option(OPTION_IF_DESCRIPTION, interface.description.encode())
        if interface.units_per_second != MICROSECONDS:
            body += self._option(OPTION_IF_TSRESOL, bytes([_resolution(interface)]))
        if interface.offset_seconds:
            body += self._option(OPTION_IF_TSOFFSET, struct.pack("<q", interface.offset_seconds))
        self._block(BLOCK_INTERFACE_DESCRIPTION, body + self._end())
        return number

    @staticmethod
    def _simple(packet: Packet, interface: Interface, options: bytes) -> bool:
        """Whether a Simple Packet Block can carry the packet as it is.

        It has no options and no captured length: its bytes have to be all
        of the packet, or as many as the snapshot length allows.
        """
        whole = packet.original_length
        if interface.snaplen:
            whole = min(whole, interface.snaplen)
        return not options and packet.captured_length == whole

    def _block(self, block_type: int, body: bytes) -> None:
        total = len(body) + 12
        length = total.to_bytes(4, "little")
        self._stream.write(self._BLOCK_HEADER.pack(block_type, total) + body + length)

    def _option(self, code: int, value: bytes) -> bytes:
        return self._OPTION.pack(code, len(value)) + _padded(value)

    def _end(self) -> bytes:
        return self._OPTION.pack(OPTION_END, 0)


def _resolution(interface: Interface) -> int:
    """``if_tsresol`` for an interface's units: 10**-n seconds as n, 2**-n as 0x80 | n."""
    units = interface.units_per_second
    exponent = len(str(units)) - 1
    if 10**exponent == units:
        return exponent
    if units & (units - 1) == 0:
        return 0x80 | (units.bit_length() - 1)
    raise WriteError(f"a timestamp resolution of 1/{units} second can't be written to pcapng")


def _padded(data: bytes) -> bytes:
    """``data`` followed by zeros up to a multiple of four bytes, as pcapng wants."""
    return data + bytes(-len(data) % 4)
