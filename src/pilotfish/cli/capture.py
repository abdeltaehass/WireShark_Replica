"""``pilotfish capture``: list packets from a network interface as they arrive."""

import io
import signal
import sys
from collections.abc import Callable
from types import FrameType
from typing import Literal, TextIO

from pilotfish.cli.table import PacketTable, TimeFormat
from pilotfish.core.capture import (
    DEFAULT_QUEUE_SIZE,
    BpfSource,
    CaptureError,
    CaptureOptions,
    CapturePermissionError,
    LiveCapture,
    PacketSource,
    PcapSource,
    default_device,
    list_devices,
)

type Backend = Literal["libpcap", "bpf"]

BACKENDS: tuple[Backend, ...] = ("libpcap", "bpf")

_SOURCES: dict[Backend, Callable[[str, CaptureOptions], PacketSource]] = {
    "libpcap": PcapSource,
    "bpf": BpfSource,
}

PERMISSION_HINT = (
    "capturing needs access to /dev/bpf*, which only root has by default. Run pilotfish with sudo."
)


def main(
    interface: str | None,
    *,
    backend: Backend,
    options: CaptureOptions,
    time_format: TimeFormat,
    count: int | None,
    queue_size: int,
) -> int:
    """Open the interface, then capture until Ctrl+C or ``count`` packets."""
    try:
        devices = list_devices()
        name = interface or default_device(devices).name
        source = _SOURCES[backend](name, options)
    except CaptureError as error:
        print(f"pilotfish: {error}", file=sys.stderr)
        if isinstance(error, CapturePermissionError):
            print(f"pilotfish: {PERMISSION_HINT}", file=sys.stderr)
        return 1
    if source.warning:
        print(f"pilotfish: {name}: warning: {source.warning}", file=sys.stderr)
    description = next((d.description for d in devices if d.name == name), None)
    print(f"Capturing on {name}" + (f" ({description})" if description else ""), file=sys.stderr)
    # A terminal gets a write per line by default. Packets arrive in bursts,
    # so run() flushes itself whenever it has caught up.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(line_buffering=False)
    return run(source, time_format=time_format, count=count, queue_size=queue_size)


def run(
    source: PacketSource,
    *,
    time_format: TimeFormat = "epoch",
    count: int | None = None,
    queue_size: int = DEFAULT_QUEUE_SIZE,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Print packets from ``source`` as they arrive, then report what was dropped.

    The first Ctrl+C stops the capture, and packets already captured are
    still printed. A second Ctrl+C skips those too.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    capture = LiveCapture(source, queue_size)
    interrupts = 0

    def interrupt(signum: int, frame: FrameType | None) -> None:
        nonlocal interrupts
        interrupts += 1
        capture.stop()

    table = PacketTable(out, time_format)
    shown = 0
    failure: CaptureError | None = None
    previous = signal.signal(signal.SIGINT, interrupt)
    try:
        table.write_header()
        out.flush()
        capture.start()
        for packet in capture:
            if interrupts > 1:
                break
            shown += 1
            table.write_row(shown, packet)
            if shown == count:
                break
            if not capture.pending:
                out.flush()
    except CaptureError as error:
        failure = error
    finally:
        capture.stop()
        capture.join()
        signal.signal(signal.SIGINT, previous if previous is not None else signal.SIG_DFL)
        out.flush()

    if interrupts:
        # Start the report below the ^C the terminal echoed.
        err.write("\n")
    skipped = capture.received - capture.dropped - shown if interrupts > 1 else 0
    _report(err, capture, shown, skipped)
    if failure is not None:
        print(f"pilotfish: {failure}", file=err)
        return 1
    return 0


def _report(err: TextIO, capture: LiveCapture, shown: int, skipped: int) -> None:
    """Counts in tcpdump's wording, plus the packets pilotfish itself dropped."""
    lines = [f"{_packets(shown)} captured"]
    if capture.kernel_stats is not None:
        lines.append(f"{_packets(capture.kernel_stats.received)} received by filter")
        lines.append(f"{_packets(capture.kernel_stats.dropped)} dropped by kernel")
    lines.append(f"{_packets(capture.dropped)} dropped by pilotfish (queue full)")
    if skipped:
        lines.append(f"{_packets(skipped)} not shown after a second Ctrl+C")
    err.write("".join(f"{line}\n" for line in lines))


def _packets(number: int) -> str:
    return f"{number} packet{'' if number == 1 else 's'}"
