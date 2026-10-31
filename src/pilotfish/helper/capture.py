"""Capture from one interface and write it to standard output as pcapng."""

import argparse
import json
import os
import signal
import sys
import threading
from collections.abc import Sequence
from types import FrameType
from typing import BinaryIO, TextIO

from pilotfish.core.capture import (
    MAX_SNAPLEN,
    BpfSource,
    CaptureError,
    CaptureOptions,
    CapturePermissionError,
    LiveCapture,
    PacketSource,
    PcapSource,
    list_devices,
)
from pilotfish.core.filters import FilterError
from pilotfish.core.formats import PcapngWriter

STATS_EVERY = 0.5
"""Seconds between reports of how many packets were captured and dropped."""

BUFFER_SIZE = 16 * 1024 * 1024
"""Bytes for the kernel's capture buffer. A download comes in bursts, and a
large buffer rides them out where the default 2 MiB would drop packets."""

QUEUE_SIZE = 100_000
"""Packets waiting between the capture thread and the writer at most."""


class Events:
    """Reports on standard error, one JSON object a line."""

    def __init__(self, out: TextIO) -> None:
        self._out = out
        self._lock = threading.Lock()

    def send(self, event: str, **fields: object) -> None:
        line = json.dumps({"event": event, **fields})
        with self._lock:
            try:
                self._out.write(f"{line}\n")
                self._out.flush()
            except (BrokenPipeError, ValueError):
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pilotfish.helper",
        description="Capture from an interface and write pcapng to standard output.",
    )
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-f", "--filter", help="a capture filter, such as 'tcp port 443'")
    parser.add_argument("-s", "--snaplen", type=int, default=MAX_SNAPLEN)
    parser.add_argument("--backend", choices=("libpcap", "bpf"), default="libpcap")
    parser.add_argument("--stats-every", type=float, default=STATS_EVERY)
    arguments = parser.parse_args(argv)
    events = Events(sys.stderr)
    options = CaptureOptions(
        snaplen=arguments.snaplen, buffer_size=BUFFER_SIZE, filter=arguments.filter
    )
    source = _open(arguments.interface, arguments.backend, options, events)
    if source is None:
        return 1
    events.send(
        "started",
        interface=source.interface,
        link_type=source.link_type,
        warning=source.warning,
    )
    return run(source, sys.stdout.buffer, events, stats_every=arguments.stats_every)


def run(source: PacketSource, out: BinaryIO, events: Events, *, stats_every: float) -> int:
    """Write what ``source`` captures to ``out`` until told to stop."""
    capture = LiveCapture(source, QUEUE_SIZE, stats_every=stats_every)
    stopped = threading.Event()

    def stop(signum: int, frame: FrameType | None) -> None:
        capture.stop()

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)
    written = 0

    def report(event: str) -> None:
        kernel = capture.kernel_stats
        events.send(
            event,
            captured=written,
            dropped=capture.dropped + (kernel.dropped if kernel else 0),
            dropped_by_kernel=kernel.dropped if kernel else 0,
            dropped_by_helper=capture.dropped,
            received_by_filter=kernel.received if kernel else None,
        )

    def keep_reporting() -> None:
        while not stopped.wait(stats_every):
            report("stats")

    reporter = threading.Thread(target=keep_reporting, name="stats", daemon=True)
    failure: str | None = None
    try:
        writer = PcapngWriter(out)
        out.flush()
        capture.start()
        reporter.start()
        for packet in capture:
            writer.write(packet)
            written += 1
            # Flush whenever it has caught up, so the window sees packets
            # as they come, but a burst goes out in large writes.
            if not capture.pending:
                out.flush()
        out.flush()
    except BrokenPipeError:
        # Whatever was reading went away, so there is no one to tell. Point
        # standard output at /dev/null, so the interpreter's last flush of it
        # can't fail too as it exits.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, out.fileno())
    except CaptureError as error:
        failure = str(error)
    finally:
        capture.stop()
        capture.join()
        stopped.set()
    if failure is not None:
        events.send("error", kind="capture", message=failure)
        return 1
    report("stopped")
    return 0


def _open(
    interface: str, backend: str, options: CaptureOptions, events: Events
) -> PacketSource | None:
    """Open the interface, or say why it can't be opened."""
    try:
        if backend == "bpf":
            return BpfSource(interface, options)
        return PcapSource(interface, options)
    except FilterError as error:
        events.send("error", kind="filter", message=str(error))
    except CapturePermissionError as error:
        events.send("error", kind="permission", message=str(error))
    except CaptureError as error:
        names = {device.name for device in list_devices()}
        if interface not in names:
            events.send(
                "error", kind="interface", message=f'there is no interface named "{interface}"'
            )
        else:
            events.send("error", kind="capture", message=str(error))
    return None
