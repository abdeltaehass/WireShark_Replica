"""The network interfaces this Mac can capture on.

On a MacBook en0 is usually the Wi-Fi card and lo0 is loopback. utun
interfaces are tunnels, used by VPNs and by some macOS services. Other en
interfaces are wired: Ethernet adapters and Thunderbolt ports.
"""

import ctypes
from collections.abc import Iterator
from ctypes import POINTER, byref
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from pilotfish.core.capture import libpcap
from pilotfish.core.capture.errors import CaptureError
from pilotfish.core.capture.systemconfiguration import display_names

# Address families from <sys/socket.h> on macOS. Linux numbers AF_INET6 differently.
AF_INET = 2
AF_INET6 = 30

# Interfaces System Settings doesn't list, described by name prefix.
_PREFIX_DESCRIPTIONS = (
    ("utun", "Tunnel"),
    ("awdl", "Apple Wireless Direct Link"),  # AirDrop, AirPlay and Sidecar
    ("llw", "Low-latency WLAN"),
    ("ap", "Wi-Fi access point"),  # sharing this Mac's connection over Wi-Fi
)


@dataclass(frozen=True, slots=True)
class Device:
    """An interface as ``pcap_findalldevs`` reports it."""

    name: str
    flags: int
    """``PCAP_IF_*`` flags."""
    addresses: tuple[str, ...] = ()
    """The interface's IPv4 and IPv6 addresses."""
    description: str | None = None

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & libpcap.PCAP_IF_LOOPBACK)

    @property
    def is_usable(self) -> bool:
        """Up, running and not loopback: a candidate for the default interface."""
        up_and_running = libpcap.PCAP_IF_UP | libpcap.PCAP_IF_RUNNING
        return self.flags & up_and_running == up_and_running and not self.is_loopback

    @property
    def status(self) -> str:
        if not self.flags & libpcap.PCAP_IF_UP:
            return "down"
        if not self.flags & libpcap.PCAP_IF_RUNNING:
            return "not running"
        connection = self.flags & libpcap.PCAP_IF_CONNECTION_STATUS
        if connection == libpcap.PCAP_IF_CONNECTION_STATUS_CONNECTED:
            return "connected"
        if connection == libpcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            return "disconnected"
        return "up"


def describe(name: str, flags: int, known_names: dict[str, str]) -> str | None:
    """A short description, from System Settings when it lists the interface."""
    if name in known_names:
        return known_names[name]
    if flags & libpcap.PCAP_IF_LOOPBACK:
        return "Loopback"
    for prefix, description in _PREFIX_DESCRIPTIONS:
        if name.startswith(prefix) and name[len(prefix) :].isdigit():
            return description
    if flags & libpcap.PCAP_IF_WIRELESS:
        return "Wi-Fi"
    return None


def format_sockaddr(raw: bytes) -> str | None:
    """The IP address in a BSD socket address, or ``None`` for other families.

    ``struct sockaddr_in`` holds an IPv4 address at offset 4. ``struct
    sockaddr_in6`` holds an IPv6 address at offset 8.
    """
    if len(raw) < 2:
        return None
    family = raw[1]
    if family == AF_INET and len(raw) >= 8:
        return str(IPv4Address(raw[4:8]))
    if family == AF_INET6 and len(raw) >= 24:
        return str(IPv6Address(raw[8:24]))
    return None


def list_devices() -> list[Device]:
    """Every interface libpcap can capture on, in its order: those that are up
    and connected come first."""
    lib = libpcap.load()
    errbuf = libpcap.error_buffer()
    head = POINTER(libpcap.PcapIf)()
    if lib.pcap_findalldevs(byref(head), errbuf) != 0:
        raise CaptureError(libpcap.text(errbuf.value))
    known_names = display_names()
    devices: list[Device] = []
    try:
        node = head
        # ctypes makes a NULL pointer false, which ends the list.
        while bool(node):
            entry = node.contents
            name = libpcap.text(entry.name)
            devices.append(
                Device(
                    name=name,
                    flags=entry.flags,
                    # IPv4 first; libpcap lists IPv6 first on some interfaces.
                    addresses=tuple(sorted(_addresses(entry.addresses), key=_is_ipv6)),
                    description=describe(name, entry.flags, known_names),
                )
            )
            node = entry.next
    finally:
        lib.pcap_freealldevs(head)
    return devices


def _addresses(node: "ctypes._Pointer[libpcap.PcapAddr]") -> Iterator[str]:
    while bool(node):
        entry = node.contents
        sockaddr = entry.addr
        # BSD socket addresses carry their own length, so the whole structure
        # can be copied out without knowing its type first.
        if sockaddr and sockaddr.contents.sa_len >= 2:
            address = format_sockaddr(ctypes.string_at(sockaddr, sockaddr.contents.sa_len))
            if address is not None:
                yield address
        node = entry.next


def _is_ipv6(address: str) -> bool:
    return ":" in address


def default_device(devices: list[Device]) -> Device:
    """The first interface that's up, running and not loopback, else the first of all.

    libpcap sorts connected interfaces with addresses first, so this is
    usually the one carrying this Mac's traffic.
    """
    if not devices:
        raise CaptureError("no interfaces to capture on")
    return next((device for device in devices if device.is_usable), devices[0])
