"""Live capture from this Mac's network interfaces.

Two sources read packets from the kernel's BPF devices. :class:`PcapSource`
goes through the system libpcap, and :class:`BpfSource` opens ``/dev/bpf*``
itself. :class:`LiveCapture` runs either one on a background thread.

The BPF devices belong to root, so capturing needs sudo unless the user has
been given access to them, as Wireshark's ChmodBPF does.
"""

from pilotfish.core.capture.bpf import BpfSource
from pilotfish.core.capture.errors import CaptureError, CapturePermissionError
from pilotfish.core.capture.interfaces import Device, default_device, list_devices
from pilotfish.core.capture.libpcap import PcapSource
from pilotfish.core.capture.live import DEFAULT_QUEUE_SIZE, LiveCapture
from pilotfish.core.capture.source import (
    MAX_SNAPLEN,
    CaptureOptions,
    KernelStats,
    PacketSource,
)

__all__ = [
    "DEFAULT_QUEUE_SIZE",
    "MAX_SNAPLEN",
    "BpfSource",
    "CaptureError",
    "CaptureOptions",
    "CapturePermissionError",
    "Device",
    "KernelStats",
    "LiveCapture",
    "PacketSource",
    "PcapSource",
    "default_device",
    "list_devices",
]
