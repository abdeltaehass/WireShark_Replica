"""The packet record shared by capture files and live capture."""

from dataclasses import dataclass, field

from pilotfish.core.timestamps import NS_PER_SECOND

MICROSECONDS = 1_000_000
"""``units_per_second`` for times counted in microseconds, as libpcap counts them."""


@dataclass(frozen=True, slots=True)
class Interface:
    """The interface packets were captured on, as a capture file describes it.

    Each packet points at its interface, so a file written from them can
    describe the interface the way the one they were read from did: the same
    name, the same snapshot length, and timestamps in the same resolution.
    """

    link_type: int
    """LINKTYPE value from the tcpdump.org registry."""
    snaplen: int = 0
    """Most bytes kept from a packet. 0 means no limit was recorded."""
    units_per_second: int = MICROSECONDS
    """Timestamp resolution: microseconds unless the file says otherwise."""
    offset_seconds: int = 0
    """Seconds added to every timestamp, from pcapng's ``if_tsoffset``."""
    name: str | None = None
    description: str | None = None

    def timestamp_ns(self, ticks: int) -> int:
        """A timestamp as the file counts it, in nanoseconds since the epoch."""
        offset = self.offset_seconds * NS_PER_SECOND
        return ticks * NS_PER_SECOND // self.units_per_second + offset

    def ticks(self, timestamp_ns: int) -> int:
        """A timestamp counted in this interface's units, to write to a file.

        The exact inverse of :meth:`timestamp_ns` for any resolution up to a
        nanosecond: rounding up recovers the tick that rounding down came
        from, because no two ticks round down to the same nanosecond.
        """
        since = timestamp_ns - self.offset_seconds * NS_PER_SECOND
        return -(-since * self.units_per_second // NS_PER_SECOND)


@dataclass(frozen=True, slots=True)
class Packet:
    """One captured frame.

    Readers of memory-mapped files hand out ``data`` as a ``memoryview`` into the
    mapping, so reading a packet copies nothing. The view stays valid after the
    file is closed; the mapping is released once no packet refers to it.
    """

    timestamp_ns: int | None
    """Nanoseconds since the Unix epoch, or ``None`` when the file records no
    time for the packet, as with pcapng Simple Packet Blocks."""

    original_length: int
    """Length of the frame on the wire, which can exceed the bytes captured."""

    link_type: int
    """LINKTYPE value from the tcpdump.org registry, saying what ``data`` starts with."""

    data: bytes | memoryview
    """The captured bytes."""

    interface_id: int = 0
    """Index of the capture interface within its pcapng section; always 0 for pcap."""

    interface: Interface | None = field(default=None, compare=False)
    """What the capture said about the interface, when it said anything.
    Where a packet came from rather than what it is, so two packets with the
    same bytes and time are equal whatever their files said about it."""

    comments: tuple[str, ...] = ()
    """Comments the capture file attached to the packet."""

    @property
    def captured_length(self) -> int:
        return len(self.data)
