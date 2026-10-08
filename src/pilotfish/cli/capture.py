"""Capturing live: ``pilotfish -i en0``, or ``pilotfish capture``."""

import io
import signal
import sys
from collections.abc import Callable
from types import FrameType
from typing import Literal, TextIO

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.cli.pipeline import Pipeline, TextPrinter
from pilotfish.cli.status import CommandError, Exit
from pilotfish.cli.table import TimeFormat
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
from pilotfish.core.filters import FilterError

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
    pipeline: Callable[[PacketSource], Pipeline],
    *,
    backend: Backend,
    options: CaptureOptions,
    count: int | None,
    queue_size: int,
    print_filter: bool = False,
) -> Exit:
    """Open the interface, then capture until Ctrl+C or ``count`` packets.

    ``pipeline`` makes what the packets go through once the interface is
    open, since writing a capture file needs to know its link type.
    """
    try:
        devices = list_devices()
        name = interface or default_device(devices).name
        source = _SOURCES[backend](name, options)
    except FilterError as error:
        raise CommandError(Exit.INVALID_FILTER, str(error)) from None
    except CapturePermissionError as error:
        raise CommandError(Exit.NO_PERMISSION, str(error), (PERMISSION_HINT,)) from None
    except CaptureError as error:
        if interface is not None and interface not in {device.name for device in devices}:
            raise CommandError(
                Exit.INVALID_INTERFACE,
                f'there is no interface named "{interface}"; `pilotfish -D` lists them',
            ) from None
        raise CommandError(Exit.CAPTURE_ERROR, str(error)) from None
    if print_filter:
        # The filter had to be compiled for this interface's link type, which
        # is why the interface is opened even though nothing is captured.
        program = source.program
        source.close()
        for line in program.disassemble() if program else []:
            print(line)
        return Exit.OK
    if source.warning:
        print(f"pilotfish: {name}: warning: {source.warning}", file=sys.stderr)
    description = next((d.description for d in devices if d.name == name), None)
    where = f"{name}" + (f" ({description})" if description else "")
    filtering = f', filter "{options.filter}"' if options.filter else ""
    print(f"Capturing on {where}{filtering}", file=sys.stderr)
    # A terminal gets a write per line by default. Packets arrive in bursts,
    # so run() flushes itself whenever it has caught up.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(line_buffering=False)
    return run(source, pipeline(source), count=count, queue_size=queue_size)


def run(
    source: PacketSource,
    pipeline: Pipeline | None = None,
    *,
    time_format: TimeFormat = "epoch",
    count: int | None = None,
    queue_size: int = DEFAULT_QUEUE_SIZE,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> Exit:
    """Hand packets from ``source`` to ``pipeline`` as they arrive, then report
    what was dropped.

    Without a pipeline, the packets are listed on ``out``. The first Ctrl+C
    stops the capture, and packets already captured are still handled. A
    second Ctrl+C skips those too. ``count`` stops after that many packets
    have been captured, whether or not a display filter lets them through,
    as tshark's -c does.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    if pipeline is None:
        pipeline = Pipeline(out, printer=TextPrinter(out, time_format))
    capture = LiveCapture(source, queue_size)
    interrupts = 0

    def interrupt(signum: int, frame: FrameType | None) -> None:
        nonlocal interrupts
        interrupts += 1
        capture.stop()

    taken = 0
    failure: CaptureError | None = None
    previous = signal.signal(signal.SIGINT, interrupt)
    try:
        pipeline.begin()
        pipeline.flush()
        capture.start()
        for packet in capture:
            if interrupts > 1:
                break
            taken += 1
            pipeline.packet(taken, packet)
            if taken == count:
                break
            if not capture.pending:
                pipeline.flush()
    except CaptureError as error:
        failure = error
    finally:
        capture.stop()
        capture.join()
        signal.signal(signal.SIGINT, previous if previous is not None else signal.SIG_DFL)
        pipeline.end()

    if interrupts:
        # Start the report below the ^C the terminal echoed.
        err.write("\n")
    skipped = capture.received - capture.dropped - taken if interrupts > 1 else 0
    _report(err, capture, taken, skipped)
    if failure is not None:
        print(f"pilotfish: {failure}", file=err)
        return Exit.CAPTURE_ERROR
    return Exit.OK


def _report(err: TextIO, capture: LiveCapture, taken: int, skipped: int) -> None:
    """Counts in tcpdump's wording, plus the packets pilotfish itself dropped."""
    lines = [f"{_packets(taken)} captured"]
    if capture.kernel_stats is not None:
        lines.append(f"{_packets(capture.kernel_stats.received)} received by filter")
        lines.append(f"{_packets(capture.kernel_stats.dropped)} dropped by kernel")
    lines.append(f"{_packets(capture.dropped)} dropped by pilotfish (queue full)")
    if skipped:
        lines.append(f"{_packets(skipped)} not shown after a second Ctrl+C")
    err.write("".join(f"{line}\n" for line in lines))


def _packets(number: int) -> str:
    return f"{number} packet{'' if number == 1 else 's'}"
