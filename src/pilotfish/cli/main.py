"""Entry point for the ``pilotfish`` command.

pilotfish takes tshark's flags. ``pilotfish -r FILE`` reads a capture file,
``pilotfish -i en0`` captures live, and the same flags decide what happens to
the packets either way: which are kept (-c, -f, -Y), how they are printed
(-V, -x, -T, -e), and where they are saved (-w).

``pilotfish read FILE`` and ``pilotfish capture`` say the same thing with a
command, and take the same flags. The other commands do what tshark has no
flag for, or one that is hard to remember: follow a stream, list the fields,
list the interfaces, explain a display filter.

Every failure prints one line starting ``pilotfish:`` to standard error and
exits with the status tshark would, listed in :mod:`pilotfish.cli.status`.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import NoReturn, TextIO

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish import __version__
from pilotfish.cli import capture, explain, fields, follow, interfaces, merge, read
from pilotfish.cli.export import FieldPicker, FieldsFormat, FieldsPrinter, JsonPrinter
from pilotfish.cli.pipeline import Pipeline, Printer, TextPrinter, open_output
from pilotfish.cli.status import CommandError, Exit
from pilotfish.cli.table import TIME_FORMATS
from pilotfish.core.capture import DEFAULT_QUEUE_SIZE, MAX_SNAPLEN, CaptureOptions, PacketSource
from pilotfish.core.dissect import REGISTRY
from pilotfish.core.formats import CaptureWriter, FileFormat, RingBuffer, RingLimits, open_writer

COMMANDS = ("read", "capture", "merge", "follow", "fields", "interfaces", "filter")

OUTPUT_TYPES = ("text", "fields", "json")

LIVE_OPTIONS = {
    "snapshot_length": "-s",
    "no_promiscuous_mode": "-p",
    "buffer_size": "-B",
    "no_immediate_mode": "--no-immediate-mode",
    "queue_size": "--queue-size",
    "backend": "--backend",
}
"""The flags that only mean something while capturing, by where argparse keeps them."""

_DEFAULT_BUFFER_KIB = CaptureOptions().buffer_size // 1024

EXIT_STATUSES = """\
exit status:
  0    success
  1    the command line doesn't make sense
  2    there is no interface by that name
  3    the file to read is missing or isn't a capture file
  4    a display or capture filter doesn't compile
  5    capturing needs access to /dev/bpf*
  9    the file to write can't be created
  14   the file being read is cut short or damaged
  15   writing the capture file failed
  17   live capture failed
  130  interrupted
  141  whatever was reading the output went away
"""


class Parser(argparse.ArgumentParser):
    """An argument parser whose usage errors exit with 1, as tshark's do."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(Exit.INVALID_OPTION, f"pilotfish: {message}\n")


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} isn't a whole number") from None
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


def _add_packet_options(parser: argparse.ArgumentParser) -> None:
    """The flags that say what happens to packets, wherever they come from."""
    which = parser.add_argument_group("which packets")
    which.add_argument(
        "-c",
        "--count",
        type=_positive_int,
        metavar="N",
        help="stop after reading or capturing N packets, whether or not -Y keeps them",
    )
    which.add_argument(
        "-f",
        "--filter",
        metavar="EXPRESSION",
        help="capture filter in libpcap's syntax, such as 'udp port 53'; live, the kernel "
        "drops everything else, and over a file pilotfish runs the compiled program itself",
    )
    which.add_argument(
        "-d",
        "--print-filter",
        action="store_true",
        help="print the capture filter's compiled BPF program, as tcpdump -d does, and exit",
    )
    which.add_argument(
        "-Y",
        "--display-filter",
        metavar="EXPRESSION",
        help="keep only the packets a display filter matches, such as "
        "'tcp.port == 443 and not ip.addr == 10.0.0.0/8'",
    )

    printed = parser.add_argument_group("what is printed")
    printed.add_argument(
        "-V", "--tree", action="store_true", help="print each packet's protocol tree"
    )
    printed.add_argument(
        "-x", "--hex", action="store_true", help="print each packet's bytes as a hex dump"
    )
    printed.add_argument(
        "-T",
        "--output-type",
        choices=OUTPUT_TYPES,
        help="text: the packet list, or what -V and -x ask for (default); "
        "fields: the fields named by -e, one line per packet; "
        "json: every packet as JSON, or only the fields named by -e",
    )
    printed.add_argument(
        "-e",
        "--field",
        dest="fields",
        action="append",
        metavar="FIELD",
        help="a field for -T fields or -T json to print, such as ip.src or "
        "_ws.col.info; give -e once for each",
    )
    printed.add_argument(
        "-E",
        dest="field_options",
        action="append",
        metavar="OPTION=VALUE",
        help="how -T fields lays out its values: header=y|n, separator=/t|/s|CHARACTER, "
        "occurrence=f|l|a, aggregator=,|/s|CHARACTER, quote=d|s|n",
    )
    printed.add_argument(
        "-P",
        "--print",
        dest="print_packets",
        action="store_true",
        help="print packets while writing them with -w, which otherwise prints nothing",
    )
    printed.add_argument(
        "-q", "--quiet", action="store_true", help="print no packets, only errors and counts"
    )
    printed.add_argument(
        "-l",
        "--line-buffered",
        action="store_true",
        help="send each packet's output on as soon as it is printed, for a pipe",
    )
    printed.add_argument(
        "-n",
        dest="no_resolution",
        action="store_true",
        help="accepted so that tshark command lines work; pilotfish never resolves names",
    )
    printed.add_argument(
        "-t",
        "--time-format",
        choices=TIME_FORMATS,
        default="epoch",
        help="epoch: seconds since 1970, as tshark's frame.time_epoch (default); "
        "utc: date and time in UTC",
    )

    saved = parser.add_argument_group("saving")
    saved.add_argument(
        "-w",
        "--write",
        metavar="FILE",
        help="write the packets that are kept to FILE, or to standard output with -",
    )
    saved.add_argument(
        "-F",
        "--format",
        choices=tuple(FileFormat),
        help="the format -w writes: pcapng (default) or pcap",
    )
    saved.add_argument(
        "-b",
        "--ring-buffer",
        dest="ring",
        action="append",
        metavar="KEY:VALUE",
        help="write a ring of files instead of one, as dumpcap does: filesize:KB starts a "
        "new file once one holds that many kilobytes, duration:SECONDS once its packets "
        "span that long, and files:N keeps only the newest N",
    )


def _add_live_options(parser: argparse.ArgumentParser) -> None:
    """The flags that only mean something while capturing."""
    live = parser.add_argument_group("live capture")
    live.add_argument(
        "-s",
        "--snapshot-length",
        type=_snapshot_length,
        metavar="BYTES",
        help=f"bytes to keep from each packet (default: {MAX_SNAPLEN})",
    )
    live.add_argument(
        "-p",
        "--no-promiscuous-mode",
        action="store_true",
        default=None,
        help="capture only traffic to and from this Mac, plus broadcast and multicast",
    )
    live.add_argument(
        "-B",
        "--buffer-size",
        type=_positive_int,
        metavar="KiB",
        help=f"kernel capture buffer in KiB (default: {_DEFAULT_BUFFER_KIB})",
    )
    live.add_argument(
        "--no-immediate-mode",
        action="store_true",
        default=None,
        help="let the kernel hold packets until its buffer fills or 100 ms pass, "
        "which costs less CPU under heavy traffic",
    )
    live.add_argument(
        "--queue-size",
        type=_positive_int,
        metavar="PACKETS",
        help="packets held between the capture thread and the output; packets that "
        f"arrive when it's full are dropped and counted (default: {DEFAULT_QUEUE_SIZE})",
    )
    live.add_argument(
        "--backend",
        choices=capture.BACKENDS,
        help="libpcap: through the system libpcap (default); "
        "bpf: read /dev/bpf directly without libpcap",
    )


INTERFACE_HELP = (
    "interface to capture on, such as en0 (default: the first connected one; -D lists them)"
)


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="pilotfish",
        usage="pilotfish [-r FILE | -i INTERFACE] [options]\n       pilotfish COMMAND ...",
        description="Capture and analyze network packets. pilotfish takes tshark's flags: "
        "-r reads a capture file, -i captures live (on the first connected interface if "
        "none is named), and the rest decide what is done with the packets.",
        epilog=EXIT_STATUSES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    source = parser.add_argument_group("where packets come from")
    source.add_argument(
        "-r",
        "--read-file",
        dest="file",
        metavar="FILE",
        help="read packets from a capture file, or from standard input with -",
    )
    source.add_argument("-i", "--interface", help=INTERFACE_HELP)
    source.add_argument(
        "-D",
        "--list-interfaces",
        action="store_true",
        help="list the interfaces to capture on, numbered as tshark lists them, and exit",
    )
    _add_packet_options(parser)
    _add_live_options(parser)

    commands = parser.add_subparsers(
        dest="command", metavar="COMMAND", title="commands", prog="pilotfish"
    )
    read_parser = commands.add_parser(
        "read",
        help="read a capture file: the same as pilotfish -r FILE",
        description="Read the packets in a pcap or pcapng file. The same as pilotfish -r FILE, "
        "and takes the same flags.",
        epilog=EXIT_STATUSES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    read_parser.add_argument("file", help="capture file to read, or - for standard input")
    _add_packet_options(read_parser)

    capture_parser = commands.add_parser(
        "capture",
        help="capture live: the same as pilotfish -i INTERFACE",
        description="Capture packets from a network interface as they arrive, until Ctrl+C "
        "or -c. Needs sudo unless you can open /dev/bpf*. Capture only on networks you own "
        "or have written permission to monitor.",
        epilog=EXIT_STATUSES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    capture_parser.add_argument("-i", "--interface", help=INTERFACE_HELP)
    _add_packet_options(capture_parser)
    _add_live_options(capture_parser)

    follow_parser = commands.add_parser(
        "follow",
        help="print one TCP connection as the conversation it carried",
        description="Put one TCP connection's bytes back in the order they were "
        "sent and print what each end said. `pilotfish -r FILE -V` shows each "
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

    commands.add_parser(
        "fields",
        help="list the fields pilotfish can decode",
        description="List every field name pilotfish can decode, with its type. "
        "These are the names display filters and -e use.",
    )
    commands.add_parser(
        "interfaces",
        help="list the interfaces you can capture on, with their addresses",
        description="List the interfaces you can capture on.",
    )
    filter_parser = commands.add_parser(
        "filter",
        help="check a display filter and show what it compiles to",
        description="Check a display filter without reading a capture. Prints how "
        "the filter was parsed, the fields it looks up and the Python function it "
        "was compiled to, or what is wrong with it and where.",
    )
    filter_parser.add_argument("expression", help="display filter, such as 'tcp.port == 80'")

    merge_parser = commands.add_parser(
        "merge",
        help="merge capture files into one, in time order, as mergecap does",
        description="Merge capture files into one, their packets in the order they were "
        "captured. Every interface keeps its description and every packet its comments.",
        epilog=EXIT_STATUSES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    merge_parser.add_argument("files", nargs="+", metavar="FILE", help="capture files to merge")
    merge_parser.add_argument(
        "-w",
        "--write",
        required=True,
        metavar="FILE",
        help="the file to write, or - for standard output",
    )
    merge_parser.add_argument(
        "-F",
        "--format",
        choices=tuple(FileFormat),
        help="the format to write: pcapng (default) or pcap",
    )
    merge_parser.add_argument(
        "-a",
        "--concatenate",
        action="store_true",
        help="put the files one after another, in the order given, instead of merging by time",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not arguments:
        parser.print_help()
        return Exit.OK
    args = parser.parse_args(arguments)
    if args.command is not None and arguments[0] not in COMMANDS:
        parser.error(f"flags go after the command: pilotfish {args.command} ...")
    try:
        return _run(args)
    except CommandError as failure:
        sys.stdout.flush()
        print(f"pilotfish: {failure.message}", file=sys.stderr)
        for line in failure.details:
            print(f"    {line}", file=sys.stderr)
        return failure.status
    except BrokenPipeError:
        # Whatever read our output has gone away, as with `pilotfish -r f | head`.
        # Point stdout at /dev/null so the interpreter's final flush can't fail too.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return Exit.BROKEN_PIPE
    except KeyboardInterrupt:
        return Exit.INTERRUPTED


def _run(args: argparse.Namespace) -> Exit:
    match args.command:
        case "follow":
            return follow.run(args.file, args.stream, raw=args.raw)
        case "fields":
            return Exit(fields.run())
        case "interfaces":
            return interfaces.run()
        case "filter":
            return explain.run(args.expression)
        case "merge":
            return merge.run(
                args.files,
                args.write,
                FileFormat(args.format or FileFormat.PCAPNG),
                concatenate=args.concatenate,
            )
        case "read":
            return _packets(args, live=False)
        case "capture":
            return _packets(args, live=True)
    if args.list_interfaces:
        return interfaces.run_numbered()
    if args.file is not None and args.interface is not None:
        raise _usage("-r reads a file and -i captures live; give one or the other")
    return _packets(args, live=args.file is None)


def _packets(args: argparse.Namespace, *, live: bool) -> Exit:
    """Read or capture packets, and do with them what the flags say."""
    _check(args, live=live)
    display = None
    if args.display_filter is not None:
        display = explain.display_filter(args.display_filter)
    out = sys.stdout
    printer = _printer(args, out)
    # Opened before anything is written, so a missing file leaves no empty
    # output file behind.
    capture_file = None if live else read.open_capture(args.file)
    with ExitStack() as stack:

        def pipeline(source: PacketSource | None = None) -> Pipeline:
            writer: CaptureWriter | None = None
            name = ""
            file_format = FileFormat(args.format or FileFormat.PCAPNG)
            if args.ring:
                name = args.write
                writer = RingBuffer(
                    Path(args.write),
                    file_format,
                    _ring_limits(args.ring),
                    link_type=None if source is None else source.link_type,
                )
            elif args.write is not None:
                stream, name = open_output(args.write)
                if stream is not sys.stdout.buffer:
                    stack.enter_context(stream)
                writer = open_writer(
                    stream,
                    file_format,
                    link_type=None if source is None else source.link_type,
                    interface_names={} if source is None else {0: source.interface},
                )
            return Pipeline(
                out,
                display=display,
                printer=printer,
                writer=writer,
                writing_to=name,
                flush_each=args.line_buffered,
            )

        if capture_file is None:
            return capture.main(
                args.interface,
                pipeline,
                backend=args.backend or "libpcap",
                options=_capture_options(args),
                count=args.count,
                queue_size=args.queue_size or DEFAULT_QUEUE_SIZE,
                print_filter=args.print_filter,
            )
        if args.print_filter:
            return read.run(capture_file, Pipeline(out), filter_text=args.filter, print_filter=True)
        return read.run(capture_file, pipeline(), filter_text=args.filter, count=args.count)


def _capture_options(args: argparse.Namespace) -> CaptureOptions:
    buffer_kib = args.buffer_size or _DEFAULT_BUFFER_KIB
    return CaptureOptions(
        snaplen=args.snapshot_length or MAX_SNAPLEN,
        promiscuous=not args.no_promiscuous_mode,
        buffer_size=buffer_kib * 1024,
        immediate=not args.no_immediate_mode,
        filter=args.filter,
    )


def _printer(args: argparse.Namespace, out: TextIO) -> Printer | None:
    """How packets are printed, or ``None`` when they aren't.

    Writing a capture file prints nothing unless the flags ask for output,
    so that ``-w`` on its own is quiet, as it is for tshark.
    """
    # The fields and their layout are checked even when nothing will be
    # printed, so a mistake in them is found whatever else the flags say.
    picker = None
    if args.fields:
        picker = FieldPicker(args.fields, REGISTRY.fields, args.time_format)
    layout = FieldsFormat()
    for option in args.field_options or ():
        layout.set(option)
    if args.quiet or (args.write is not None and not _asked_to_print(args)):
        return None
    if args.output_type == "json":
        return JsonPrinter(out, picker)
    if args.output_type == "fields":
        assert picker is not None  # _check made sure -T fields came with -e
        return FieldsPrinter(out, picker, layout)
    return TextPrinter(out, args.time_format, tree=args.tree, hex_dump=args.hex)


def _asked_to_print(args: argparse.Namespace) -> bool:
    """Whether the flags ask for packets to be printed in so many words."""
    return bool(args.print_packets or args.output_type is not None or args.tree or args.hex)


def _check(args: argparse.Namespace, *, live: bool) -> None:
    """Refuse flags that contradict each other, before anything is opened."""
    output = args.output_type or "text"
    if not live:
        given = [flag for name, flag in LIVE_OPTIONS.items() if getattr(args, name, None)]
        if given:
            verb = "means" if len(given) == 1 else "mean"
            raise _usage(
                f"{', '.join(given)} only {verb} something when capturing live, not with -r"
            )
    if args.fields and output == "text":
        raise _usage("-e names fields for -T fields or -T json to print; add one of those")
    if output == "fields" and not args.fields:
        raise _usage("-T fields prints the fields named with -e, and none were")
    if args.field_options and output != "fields":
        raise _usage("-E sets how -T fields lays out its values; add -T fields")
    if args.hex and output != "text":
        raise _usage(f"-x prints a hex dump, which goes with the text output, not -T {output}")
    if args.tree and output == "fields":
        raise _usage("-V prints the protocol tree, and -T fields prints only the fields")
    if args.format is not None and args.write is None:
        raise _usage("-F says which format -w writes; add -w FILE")
    if args.ring:
        if args.write is None or args.write == "-":
            raise _usage("-b writes a ring of files, so it needs -w FILE to name them by")
        _ring_limits(args.ring)
        folder = Path(args.write).parent
        if not folder.is_dir():
            raise CommandError(Exit.OPEN_ERROR, f"{folder}: No such directory")
    if args.print_filter and args.filter is None:
        raise _usage("-d prints a capture filter's program; give the filter with -f")
    if args.write == "-" and not args.quiet and _asked_to_print(args):
        raise _usage(
            "-w - writes the capture to standard output, so packets can't be printed there "
            "too; write it to a file, or drop -P, -T, -V and -x"
        )


def _ring_limits(options: list[str]) -> RingLimits:
    """The ring buffer's limits from dumpcap's -b KEY:VALUE flags."""
    values: dict[str, int] = {}
    for option in options:
        key, colon, text = option.partition(":")
        if not colon or key not in {"filesize", "duration", "files"}:
            raise _usage(
                f'"{option}" isn\'t a -b option; they are filesize:KB, duration:SECONDS and files:N'
            )
        if not text.isdecimal() or int(text) < 1:
            raise _usage(f'-b {key} takes a whole number above 0, not "{text}"')
        values[key] = int(text)
    if "filesize" not in values and "duration" not in values:
        raise _usage("-b needs filesize:KB or duration:SECONDS to know when to start a new file")
    size = values.get("filesize")
    return RingLimits(
        max_bytes=None if size is None else size * 1_000,
        max_seconds=values.get("duration"),
        max_files=values.get("files"),
    )


def _usage(message: str) -> CommandError:
    return CommandError(Exit.INVALID_OPTION, message)
