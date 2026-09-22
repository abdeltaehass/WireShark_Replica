"""The packet record shared by capture files and live capture."""

from dataclasses import dataclass


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

    @property
    def captured_length(self) -> int:
        return len(self.data)
