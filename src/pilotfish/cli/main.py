"""Entry point for the ``pilotfish`` command."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pilotfish import __version__
from pilotfish.cli import capture, interfaces, read
from pilotfish.cli.table import TIME_FORMATS
from pilotfish.core.capture import DEFAULT_QUEUE_SIZE, MAX_SNAPLEN, CaptureOptions

_DEFAULT_BUFFER_KIB = CaptureOptions().buffer_size // 1024


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, not {value}")
    return value


def _snapshot_length(text: str) -> int:
    value = _positive_int(text)
    if value > MAX_SNAPLEN:
        raise argparse.ArgumentTypeError(f"must be at most {MAX_SNAPLEN}, not {value}")
    return value


def _add_time_format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-t",
        "--time-format",
        choices=TIME_FORMATS,
        default="epoch",
        help="epoch: seconds since 1970, as tshark's frame.time_epoch (default); "
        "utc: date and time in UTC",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilotfish",
        description="Capture and analyze network packets.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    read_parser = commands.add_parser(
        "read",
        help="list the packets in a pcap or pcapng file",
        description="List the packets in a pcap or pcapng file.",
    )
    read_parser.add_argument("file", type=Path, help="capture file to read")
    _add_time_format(read_parser)

    capture_parser = commands.add_parser(
        "capture",
        help="list packets from a network interface as they arrive",
        description="List packets from a network interface as they arrive, until "
        "Ctrl+C. Needs sudo unless you can open /dev/bpf*. Capture only on "
        "networks you own or have written permission to monitor.",
    )
    capture_parser.add_argument(
        "-i",
        "--interface",
        help="interface to capture on, such as en0 (default: the first connected "
        "one; see `pilotfish interfaces`)",
    )
    capture_parser.add_argument(
        "-c", "--count", type=_positive_int, help="stop after this many packets"
    )
    capture_parser.add_argument(
        "-s",
        "--snapshot-length",
        type=_snapshot_length,
        default=MAX_SNAPLEN,
        metavar="BYTES",
        help=f"bytes to keep from each packet (default: {MAX_SNAPLEN})",
    )
    capture_parser.add_argument(
        "-p",
        "--no-promiscuous-mode",
        action="store_true",
        help="capture only traffic to and from this Mac, plus broadcast and multicast",
    )
    capture_parser.add_argument(
        "-B",
        "--buffer-size",
        type=_positive_int,
        default=_DEFAULT_BUFFER_KIB,
        metavar="KiB",
        help=f"kernel capture buffer in KiB (default: {_DEFAULT_BUFFER_KIB})",
    )
    capture_parser.add_argument(
        "--no-immediate-mode",
        action="store_true",
        help="let the kernel hold packets until its buffer fills or 100 ms pass, "
        "which costs less CPU under heavy traffic",
    )
    capture_parser.add_argument(
        "--queue-size",
        type=_positive_int,
        default=DEFAULT_QUEUE_SIZE,
        metavar="PACKETS",
        help="packets held between the capture thread and the display; packets "
        f"that arrive when it's full are dropped and counted (default: {DEFAULT_QUEUE_SIZE})",
    )
    capture_parser.add_argument(
        "--backend",
        choices=capture.BACKENDS,
        default="libpcap",
        help="libpcap: through the system libpcap (default); "
        "bpf: read /dev/bpf directly without libpcap",
    )
    _add_time_format(capture_parser)

    commands.add_parser(
        "interfaces",
        help="list the interfaces you can capture on",
        description="List the interfaces you can capture on.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "read":
            return read.run(args.file, args.time_format)
        if args.command == "capture":
            options = CaptureOptions(
                snaplen=args.snapshot_length,
                promiscuous=not args.no_promiscuous_mode,
                buffer_size=args.buffer_size * 1024,
                immediate=not args.no_immediate_mode,
            )
            return capture.main(
                args.interface,
                backend=args.backend,
                options=options,
                time_format=args.time_format,
                count=args.count,
                queue_size=args.queue_size,
            )
        if args.command == "interfaces":
            return interfaces.run()
        parser.print_help()
        return 0
    except BrokenPipeError:
        # Whatever read our output has gone away, as with `pilotfish read f | head`.
        # Point stdout at /dev/null so the interpreter's final flush can't fail too.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 1
    except KeyboardInterrupt:
        return 130
