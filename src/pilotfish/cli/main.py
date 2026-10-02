"""Entry point for the ``pilotfish`` command."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pilotfish import __version__
from pilotfish.cli import capture, explain, fields, follow, interfaces, read
from pilotfish.cli.table import TIME_FORMATS
from pilotfish.core.capture import DEFAULT_QUEUE_SIZE, MAX_SNAPLEN, CaptureOptions

_DEFAULT_BUFFER_KIB = CaptureOptions().buffer_size // 1024


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, not {value}")
    return value


def _stream_number(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more, not {value}")
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
    read_parser.add_argument(
        "-V",
        "--tree",
        action="store_true",
        help="print each packet's protocol tree instead of one line per packet",
    )
    read_parser.add_argument(
        "-f",
        "--filter",
        metavar="EXPRESSION",
        help="list only the packets a capture filter keeps, such as 'udp port 53'; "
        "pilotfish runs the compiled program itself",
    )
    read_parser.add_argument(
        "-Y",
        "--display-filter",
        metavar="EXPRESSION",
        help="list only the packets a display filter matches, such as "
        "'tcp.port == 443 and not ip.addr == 10.0.0.0/8'; it asks about decoded "
        "fields, which `pilotfish fields` lists",
    )
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
        "-f",
        "--filter",
        metavar="EXPRESSION",
        help="capture filter in libpcap syntax, such as 'udp port 53' or "
        "'host 192.0.2.5 and not port 22'; the kernel drops everything else",
    )
    capture_parser.add_argument(
        "-d",
        "--print-filter",
        action="store_true",
        help="print the filter's compiled BPF program, as tcpdump -d does, and exit",
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

    follow_parser = commands.add_parser(
        "follow",
        help="print one TCP connection as the conversation it carried",
        description="Put one TCP connection's bytes back in the order they were "
        "sent and print what each end said. `pilotfish read -V` shows each "
        "packet's stream number as its stream index.",
    )
    follow_parser.add_argument("file", type=Path, help="capture file to read")
    follow_parser.add_argument(
        "stream", type=_stream_number, help="number of the TCP stream to follow, counting from 0"
    )
    follow_parser.add_argument(
        "--raw",
        choices=follow.SIDES,
        help="write only the bytes this end sent, exactly as it sent them, "
        "to save to a file or pipe into a hash",
    )

    filter_parser = commands.add_parser(
        "filter",
        help="check a display filter and show what it compiles to",
        description="Check a display filter without reading a capture. Prints how "
        "the filter was parsed, the fields it looks up and the Python function it "
        "was compiled to, or what is wrong with it and where.",
    )
    filter_parser.add_argument("expression", help="display filter, such as 'tcp.port == 80'")

    commands.add_parser(
        "fields",
        help="list the fields pilotfish can decode",
        description="List every field name pilotfish can decode, with its type. "
        "These are the names display filters use.",
    )

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
            return read.run(
                args.file,
                args.time_format,
                filter_text=args.filter,
                display_text=args.display_filter,
                tree=args.tree,
            )
        if args.command == "capture":
            if args.print_filter and args.filter is None:
                parser.error("--print-filter needs a filter to print: pass -f EXPRESSION")
            options = CaptureOptions(
                snaplen=args.snapshot_length,
                promiscuous=not args.no_promiscuous_mode,
                buffer_size=args.buffer_size * 1024,
                immediate=not args.no_immediate_mode,
                filter=args.filter,
            )
            return capture.main(
                args.interface,
                backend=args.backend,
                options=options,
                time_format=args.time_format,
                count=args.count,
                queue_size=args.queue_size,
                print_filter=args.print_filter,
            )
        if args.command == "follow":
            return follow.run(args.file, args.stream, raw=args.raw)
        if args.command == "filter":
            return explain.run(args.expression)
        if args.command == "fields":
            return fields.run()
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
