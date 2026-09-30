import io
import signal
import subprocess
import sys
import threading
from collections.abc import Callable

import pytest

from fakes import FakeSource, fake_packet
from loopback import LoopbackTraffic
from packets import DNS_OVER_ETHERNET, DNS_OVER_ETHERNET_IMAGE
from pilotfish.cli import capture, interfaces
from pilotfish.cli.main import main
from pilotfish.core.capture import (
    CaptureOptions,
    CapturePermissionError,
    Device,
    PacketSource,
    PcapSource,
)
from pilotfish.core.filters import FilterError

HEADER = (
    "    No.  Time                  Source                 Destination            "
    "Protocol  Length  Info\n"
)


def row(number: int) -> str:
    """How ``fake_packet(number)`` is listed as row ``number``."""
    return (
        f"{number:>7}  {number}.000000000{'':<9}  {'192.0.2.1':<21}  {'192.0.2.2':<21}  "
        f"{'UDP':<8}      47  {1024 + number} → 9 Len=5\n"
    )


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
            assert "127.0.0.1" in process.stdout.readline()
        process.send_signal(signal.SIGINT)
        _, err = process.communicate()
    finally:
        watchdog.cancel()
    assert process.returncode == 0
    assert "packets captured\n" in err or "packet captured\n" in err
    assert "dropped by kernel\n" in err
    assert err.endswith(" dropped by pilotfish (queue full)\n")


def test_print_filter_prints_the_program(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = FakeSource(program=DNS_OVER_ETHERNET)
    use_sources(monkeypatch, lambda interface, options: source)
    assert main(["capture", "-f", "udp port 53", "-d"]) == 0
    output = capsys.readouterr()
    assert output.out == "".join(f"{line}\n" for line in DNS_OVER_ETHERNET_IMAGE)
    assert output.err == ""  # nothing is captured, so nothing is reported
    assert source.closed


def test_print_filter_needs_a_filter(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["capture", "-d"])
    assert exc_info.value.code == 2
    assert "--print-filter needs a filter" in capsys.readouterr().err


def test_the_filter_reaches_the_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened: list[CaptureOptions] = []

    def open_source(interface: str, options: CaptureOptions) -> PacketSource:
        opened.append(options)
        return FakeSource([fake_packet(1)])

    use_sources(monkeypatch, open_source)
    assert main(["capture", "-c", "1", "-f", "udp port 53"]) == 0
    assert [options.filter for options in opened] == ["udp port 53"]
    assert 'Capturing on fake0 (Fake Ethernet), filter "udp port 53"' in capsys.readouterr().err


def test_a_filter_that_will_not_compile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def open_source(interface: str, options: CaptureOptions) -> PacketSource:
        raise FilterError('capture filter "udp porrt 53": syntax error')

    use_sources(monkeypatch, open_source)
    assert main(["capture", "-f", "udp porrt 53"]) == 1
    assert capsys.readouterr().err == ('pilotfish: capture filter "udp porrt 53": syntax error\n')


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
def test_a_live_filter_lists_only_matching_packets() -> None:
    with LoopbackTraffic() as wanted, LoopbackTraffic() as other:
        source = PcapSource("lo0", CaptureOptions(filter=f"udp port {wanted.port}"))
        for _ in range(3):
            other.send()
        payloads = [wanted.send(), wanted.send()]
        out, err = io.StringIO(), io.StringIO()
        assert capture.run(source, count=len(payloads), out=out, err=err) == 0
    rows = out.getvalue().splitlines()[1:]
    assert len(rows) == len(payloads)
    # Loopback traffic, decoded: the addresses are there rather than the link type.
    assert all("127.0.0.1" in row for row in rows)
    assert err.getvalue().startswith("2 packets captured\n")
