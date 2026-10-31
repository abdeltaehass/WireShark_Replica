"""The capture helper: a process of its own that captures and writes pcapng.

These run the real helper, capturing loopback, so they need macOS and access
to /dev/bpf*.
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from loopback import LoopbackTraffic
from pilotfish.core.formats import PcapngStream

pytestmark = pytest.mark.macos


class Helper:
    """The helper running, its output read as it comes."""

    def __init__(self, spool: Path, *arguments: str) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "pilotfish.helper", *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.stream = PcapngStream(spool)
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._readers = [
            threading.Thread(target=self._read_output, daemon=True),
            threading.Thread(target=self._read_events, daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def _read_output(self) -> None:
        assert self.process.stdout is not None
        while chunk := os.read(self.process.stdout.fileno(), 65536):
            with self._lock:
                self.stream.feed(chunk)

    def _read_events(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.events.append(json.loads(line))

    def wait_for(self, event: str, timeout: float = 10) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = [each for each in self.events if each["event"] == event]
            if found:
                return found[-1]
            time.sleep(0.02)
        raise AssertionError(f"no {event} event; got {self.events}")

    def packets_with(self, payload: bytes, timeout: float = 5) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if any(payload in bytes(packet.data) for packet in self.stream):
                    return len(self.stream)
            time.sleep(0.02)
        raise AssertionError(f"{payload.hex()} never arrived")

    def stop(self) -> int:
        self.process.send_signal(signal.SIGTERM)
        status = self.process.wait(10)
        self.close()
        self.stream.finish()
        return status

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(10)
        for reader in self._readers:
            reader.join(5)
        for pipe in (self.process.stdout, self.process.stderr):
            if pipe is not None:
                pipe.close()

    def __enter__(self) -> "Helper":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
        self.stream.close()


@pytest.fixture
def spool(tmp_path: Path) -> Path:
    return tmp_path / "live.pcapng"


@pytest.mark.usefixtures("capture_access")
def test_it_streams_what_it_captures_as_pcapng(spool: Path) -> None:
    with (
        LoopbackTraffic() as traffic,
        Helper(spool, "-i", "lo0", "-f", f"udp port {traffic.port}") as helper,
    ):
        started = helper.wait_for("started")
        assert started["interface"] == "lo0"
        sent = [traffic.send() for _ in range(50)]
        helper.packets_with(sent[-1])
        assert helper.stop() == 0
        packets = list(helper.stream)
    stream = packets
    # Only this traffic, through the capture filter, in the order it was sent.
    assert [packet for packet in stream if not any(p in bytes(packet.data) for p in sent)] == []
    assert len(stream) == 50
    assert stream[0].interface is not None
    assert stream[0].interface.name == "lo0"
    stopped = next(event for event in helper.events if event["event"] == "stopped")
    assert stopped["captured"] == 50
    assert stopped["dropped"] == 0
    # The spool is a capture file of everything that came through.
    assert spool.read_bytes()[:4] == b"\n\r\r\n"


@pytest.mark.usefixtures("capture_access")
def test_it_reports_counts_as_it_goes(spool: Path) -> None:
    with (
        LoopbackTraffic() as traffic,
        Helper(
            spool, "-i", "lo0", "-f", f"udp port {traffic.port}", "--stats-every", "0.1"
        ) as helper,
    ):
        helper.wait_for("started")
        for _ in range(10):
            last = traffic.send()
        helper.packets_with(last)
        deadline = time.monotonic() + 5
        while helper.wait_for("stats")["captured"] < 10:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        helper.stop()


def test_an_interface_that_isnt_there_is_reported(spool: Path) -> None:
    with Helper(spool, "-i", "nosuch0") as helper:
        error = helper.wait_for("error")
        assert error["kind"] in {"interface", "permission"}
        assert helper.process.wait(10) == 1


@pytest.mark.usefixtures("capture_access")
def test_a_filter_that_doesnt_compile_is_reported(spool: Path) -> None:
    with Helper(spool, "-i", "lo0", "-f", "udp porrt 53") as helper:
        error = helper.wait_for("error")
        assert error["kind"] == "filter"
        assert "syntax error" in error["message"]
        assert helper.process.wait(10) == 1


@pytest.mark.usefixtures("capture_access")
def test_it_stops_when_the_reader_goes_away(spool: Path) -> None:
    with LoopbackTraffic() as traffic:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pilotfish.helper",
                "-i",
                "lo0",
                "-f",
                f"udp port {traffic.port}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert process.stdout is not None
        process.stdout.read(4)  # the section header has started
        process.stdout.close()
        # Writing what is captured now fails, which ends the capture.
        deadline = time.monotonic() + 10
        while process.poll() is None:
            assert time.monotonic() < deadline, "the helper kept running"
            traffic.send()
            time.sleep(0.05)
    assert process.returncode == 0
