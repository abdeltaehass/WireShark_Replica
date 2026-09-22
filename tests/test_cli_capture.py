import io
import signal
import subprocess
import sys
import threading
from collections.abc import Callable

import pytest

from fakes import FakeSource, fake_packet
from loopback import LoopbackTraffic
from pilotfish.cli import capture, interfaces
from pilotfish.cli.main import main
from pilotfish.core.capture import CaptureOptions, CapturePermissionError, Device, PacketSource

HEADER = "    No.  Time                   Length  Captured  Link type\n"


def row(number: int) -> str:
    """How ``fake_packet(number)`` is listed as row ``number``."""
    return f"{number:>7}  {number}.000000000{'':<9}  {60 + number:>7}        60  ETHERNET\n"


class Output(io.StringIO):
    """Collects output and calls ``on_row(n)`` after packet row ``n`` is written."""

    def __init__(self, on_row: Callable[[int], None]) -> None:
        super().__init__()
        self._on_row = on_row
        self.rows = 0

    def write(self, text: str) -> int:
        written = super().write(text)
        if text[:7].strip().isdigit():
            self.rows += 1
            self._on_row(self.rows)
        return written


def ctrl_c_at(source: FakeSource, *rows: int) -> Callable[[int], None]:
    """Press Ctrl+C after each of ``rows``, once every packet is already queued."""

    def on_row(number: int) -> None:
        if number == 1:
            assert source.exhausted.wait(5)
        if number in rows:
            signal.raise_signal(signal.SIGINT)

    return on_row


def test_stops_after_count() -> None:
    source = FakeSource([fake_packet(number) for number in range(1, 6)])
    out, err = Output(ctrl_c_at(source)), io.StringIO()
    assert capture.run(source, count=3, out=out, err=err) == 0
    assert out.getvalue() == HEADER + row(1) + row(2) + row(3)
    assert err.getvalue() == (
        "3 packets captured\n"
        "5 packets received by filter\n"
        "0 packets dropped by kernel\n"
        "0 packets dropped by pilotfish (queue full)\n"
    )
    assert source.closed


def test_ctrl_c_stops_capturing_but_shows_what_was_captured() -> None:
    source = FakeSource([fake_packet(number) for number in range(1, 11)])
    out, err = Output(ctrl_c_at(source, 2)), io.StringIO()
    assert capture.run(source, out=out, err=err) == 0
    assert out.rows == 10
    assert err.getvalue().startswith("\n10 packets captured\n10 packets received by filter\n")


def test_second_ctrl_c_skips_the_rest() -> None:
    source = FakeSource([fake_packet(number) for number in range(1, 11)])
    out, err = Output(ctrl_c_at(source, 2, 3)), io.StringIO()
    assert capture.run(source, out=out, err=err) == 0
    assert out.rows == 3
    assert err.getvalue() == (
        "\n"
        "3 packets captured\n"
        "10 packets received by filter\n"
        "0 packets dropped by kernel\n"
        "0 packets dropped by pilotfish (queue full)\n"
        "7 packets not shown after a second Ctrl+C\n"
    )


def test_restores_the_ctrl_c_handler() -> None:
    before = signal.getsignal(signal.SIGINT)
    capture.run(FakeSource([fake_packet(1)]), count=1, out=io.StringIO(), err=io.StringIO())
    assert signal.getsignal(signal.SIGINT) is before


def test_capture_error_after_some_packets() -> None:
    source = FakeSource([fake_packet(number) for number in range(1, 6)], fail_after=2)
    out, err = io.StringIO(), io.StringIO()
    assert capture.run(source, out=out, err=err) == 1
    assert out.getvalue() == HEADER + row(1) + row(2)
    assert err.getvalue().startswith("2 packets captured\n")
    assert err.getvalue().endswith("pilotfish: fake0: the interface went away\n")


def test_one_packet_is_singular() -> None:
    err = io.StringIO()
    capture.run(FakeSource([fake_packet(1)]), count=1, out=io.StringIO(), err=err)
    assert err.getvalue().startswith("1 packet captured\n1 packet received by filter\n")


def use_sources(
    monkeypatch: pytest.MonkeyPatch, source: Callable[[str, CaptureOptions], PacketSource]
) -> None:
    devices = [Device("fake0", 0x16, description="Fake Ethernet")]
    monkeypatch.setattr(capture, "list_devices", lambda: devices)
    monkeypatch.setitem(capture._SOURCES, "libpcap", source)


def test_command_captures_on_the_default_interface(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened: list[tuple[str, CaptureOptions]] = []

    def open_source(interface: str, options: CaptureOptions) -> PacketSource:
        opened.append((interface, options))
        return FakeSource([fake_packet(1), fake_packet(2)], warning="no promiscuous mode")

    use_sources(monkeypatch, open_source)
    assert main(["capture", "-c", "2", "-s", "96", "-p", "-B", "512", "--no-immediate-mode"]) == 0
    assert opened == [
        (
            "fake0",
            CaptureOptions(snaplen=96, promiscuous=False, buffer_size=512 * 1024, immediate=False),
        )
    ]
    output = capsys.readouterr()
    assert output.out == HEADER + row(1) + row(2)
    assert output.err.startswith(
        "pilotfish: fake0: warning: no promiscuous mode\nCapturing on fake0 (Fake Ethernet)\n"
    )


def test_command_explains_permission_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def open_source(interface: str, options: CaptureOptions) -> PacketSource:
        raise CapturePermissionError(f"{interface}: /dev/bpf0: Permission denied")

    use_sources(monkeypatch, open_source)
    assert main(["capture"]) == 1
    assert capsys.readouterr().err == (
        f"pilotfish: fake0: /dev/bpf0: Permission denied\npilotfish: {capture.PERMISSION_HINT}\n"
    )


@pytest.mark.parametrize("length", ["0", "262145", "lots"])
def test_rejects_bad_snapshot_lengths(length: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["capture", "-s", length])
    assert exc_info.value.code == 2
    assert "--snapshot-length" in capsys.readouterr().err


def test_interfaces_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    devices = [
        Device("en0", 0x1E, ("192.0.2.10", "fe80::1"), "Wi-Fi"),
        Device("utun0", 0x36, (), "Tunnel"),
        Device("gif0", 0x30),
    ]
    monkeypatch.setattr(interfaces, "list_devices", lambda: devices)
    assert main(["interfaces"]) == 0
    assert capsys.readouterr().out == (
        "Name   Description  Status     Addresses\n"
        "en0    Wi-Fi        connected  192.0.2.10, fe80::1\n"
        "utun0  Tunnel       up\n"
        "gif0                down\n"
    )


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
@pytest.mark.parametrize("backend", ["libpcap", "bpf"])
def test_ctrl_c_ends_a_real_capture(backend: str) -> None:
    process = subprocess.Popen(
        [sys.executable, "-m", "pilotfish", "capture", "-i", "lo0", "--backend", backend],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    watchdog = threading.Timer(15, process.kill)
    watchdog.start()
    try:
        assert process.stderr is not None
        assert process.stdout is not None
        assert process.stderr.readline() == "Capturing on lo0 (Loopback)\n"
        assert process.stdout.readline() == HEADER
        with LoopbackTraffic() as traffic:
            traffic.send()
            assert process.stdout.readline().endswith("  NULL\n")
        process.send_signal(signal.SIGINT)
        _, err = process.communicate()
    finally:
        watchdog.cancel()
    assert process.returncode == 0
    assert "packets captured\n" in err or "packet captured\n" in err
    assert "dropped by kernel\n" in err
    assert err.endswith(" dropped by pilotfish (queue full)\n")
