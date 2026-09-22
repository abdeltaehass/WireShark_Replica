import pytest

from pilotfish.core.capture import CaptureError, Device, default_device, list_devices
from pilotfish.core.capture.interfaces import describe, format_sockaddr
from pilotfish.core.capture.systemconfiguration import display_names

# Flags pcap_findalldevs reported on a MacBook: PCAP_IF_* bits.
EN8_ETHERNET = 0x16  # up, running, connected
EN0_WIFI = 0x1E  # up, running, wireless, connected
UTUN = 0x36  # up, running, connection status not applicable
LO0 = 0x37  # loopback, up, running, not applicable
ANPI = 0x26  # up, running, disconnected
GIF0 = 0x30  # down
UP_NOT_RUNNING = 0x02


@pytest.mark.parametrize(
    ("raw", "address"),
    [
        # Laid out as macOS returns them for lo0 and en0.
        ("100200007f0000010000000000000000", "127.0.0.1"),
        ("1c1e0000000000000000000000000000000000000000000100000000", "::1"),
        (
            "1c1e000000000000fe80000000000000123456789abcdef00f000000",
            "fe80::1234:5678:9abc:def0",
        ),
        ("14120f0006030600656e30020000000001000000", None),  # AF_LINK: a MAC address
        ("1002", None),  # AF_INET, cut short
        ("", None),
    ],
)
def test_format_sockaddr(raw: str, address: str | None) -> None:
    assert format_sockaddr(bytes.fromhex(raw)) == address


@pytest.mark.parametrize(
    ("name", "flags", "description"),
    [
        ("en0", EN0_WIFI, "Wi-Fi"),  # from System Settings
        ("lo0", LO0, "Loopback"),
        ("utun3", UTUN, "Tunnel"),
        ("awdl0", EN0_WIFI, "Apple Wireless Direct Link"),
        ("llw0", UTUN, "Low-latency WLAN"),
        ("ap1", 0x2E, "Wi-Fi access point"),
        ("en9", EN0_WIFI, "Wi-Fi"),  # wireless, but System Settings doesn't list it
        ("apple0", ANPI, None),  # "ap" and a number only
        ("gif0", GIF0, None),
    ],
)
def test_describe(name: str, flags: int, description: str | None) -> None:
    assert describe(name, flags, {"en0": "Wi-Fi"}) == description


@pytest.mark.parametrize(
    ("flags", "status"),
    [
        (EN8_ETHERNET, "connected"),
        (ANPI, "disconnected"),
        (UTUN, "up"),
        (GIF0, "down"),
        (UP_NOT_RUNNING, "not running"),
    ],
)
def test_status(flags: int, status: str) -> None:
    assert Device("en0", flags).status == status


def test_default_device_skips_loopback_and_idle_interfaces() -> None:
    devices = [Device("lo0", LO0), Device("gif0", GIF0), Device("en8", EN8_ETHERNET)]
    assert default_device(devices).name == "en8"


def test_default_device_falls_back_to_the_first() -> None:
    assert default_device([Device("gif0", GIF0), Device("lo0", LO0)]).name == "gif0"


def test_default_device_needs_an_interface() -> None:
    with pytest.raises(CaptureError, match="no interfaces"):
        default_device([])


@pytest.mark.macos
def test_lists_loopback() -> None:
    devices = {device.name: device for device in list_devices()}
    loopback = devices["lo0"]
    assert loopback.is_loopback
    assert loopback.description == "Loopback"
    assert "127.0.0.1" in loopback.addresses
    assert "::1" in loopback.addresses


@pytest.mark.macos
def test_display_names_are_keyed_by_bsd_name() -> None:
    names = display_names()
    assert names, "SystemConfiguration listed no interfaces"
    assert all(name.isascii() and name[-1].isdigit() for name in names)
