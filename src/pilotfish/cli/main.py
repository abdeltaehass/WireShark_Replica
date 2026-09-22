"""Entry point for the ``pilotfish`` command."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pilotfish import __version__
from pilotfish.cli import read


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
        "-t",
        "--time-format",
        choices=read.TIME_FORMATS,
        default="epoch",
        help="epoch: seconds since 1970, as tshark's frame.time_epoch (default); "
        "utc: date and time in UTC",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "read":
            return read.run(args.file, args.time_format)
        parser.print_help()
        return 0
    except BrokenPipeError:
        # Whatever read our output has gone away, as with `pilotfish read f | head`.
        # Point stdout at /dev/null so the interpreter's final flush can't fail too.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 1
