"""What every live capture source provides, however it talks to the kernel."""

from dataclasses import dataclass
from typing import Protocol

from pilotfish.core.packet import Packet

MAX_SNAPLEN = 262_144
"""libpcap's largest snapshot length, enough for any whole frame."""


@dataclass(frozen=True, slots=True)
class CaptureOptions:
    snaplen: int = MAX_SNAPLEN
    """Bytes kept from the start of each packet."""
    promiscuous: bool = True
    """Ask the interface for every frame it sees, not only those addressed to this Mac."""
    buffer_size: int = 2 * 1024 * 1024
    """Bytes for the kernel's capture buffer. macOS lowers larger requests to
    the ``debug.bpf_bufsize_cap`` sysctl, 32 MiB by default."""
    immediate: bool = True
    """Deliver each packet as it arrives rather than when the kernel buffer fills."""
    timeout_ms: int = 100
    """Longest a read waits when no packets arrive, which bounds how long stopping takes."""


@dataclass(frozen=True, slots=True)
class KernelStats:
    """The kernel's counters for one capture. They are 32 bits wide and wrap around."""

    received: int
    """Packets the kernel's BPF filter accepted."""
    dropped: int
    """Packets the kernel discarded because the capture buffer was full."""


class PacketSource(Protocol):
    """An open capture on one interface. Only one thread may use it at a time."""

    interface: str
    link_type: int
    """LINKTYPE value of every packet from this source."""
    warning: str | None
    """A problem that didn't stop the capture from starting, such as an
    interface that can't enter promiscuous mode."""

    def read(self) -> Packet | None:
        """Wait for the next packet. ``None`` means the timeout passed without one."""
        ...

    def stats(self) -> KernelStats: ...

    def close(self) -> None: ...
