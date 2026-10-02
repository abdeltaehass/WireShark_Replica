"""Record what tshark and capinfos report for each sample capture.

For every capture file under samples/, this writes answer keys beside it:

    <capture>.tshark.tsv      one row per packet, from ``tshark -T fields``
    <capture>.capinfos.tsv    packet count and earliest and latest packet time
    <capture>.tshark.json.gz  every field tshark decodes, for the dissectors
    <capture>.filters.json    the packets each display filter in
                              samples/display-filters.txt matches, for the
                              captures pilotfish decodes

The tests compare pilotfish with these files, so CI doesn't need Wireshark
installed. Run it after adding a sample:

    uv run scripts/update_answer_keys.py              # every sample
    uv run scripts/update_answer_keys.py FILE [FILE ...]

and after adding a display filter to the list, when only those answers have
changed:

    uv run scripts/update_answer_keys.py --filters
"""

import gzip
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.dissect import LINK_TYPE, REGISTRY
from pilotfish.core.formats import CaptureFile

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURE_SUFFIXES = frozenset({".cap", ".ntar", ".pcap", ".pcapng"})

TSHARK_FIELDS = ("frame.time_epoch", "frame.len", "frame.cap_len", "frame.interface_id")
# tshark lists pcapng Custom Blocks as frames even though they aren't packets.
# They're the only records with a Private Enterprise Number, so filter on it.
TSHARK_FILTER = "not frame.cb_pen"
# Table output, exact counts, packet count, earliest and latest time, epoch seconds.
CAPINFOS_FLAGS = ("-T", "-M", "-c", "-a", "-e", "-S")

# Wireshark leaves checksums unchecked unless it is asked, and the dissector
# tests compare pilotfish's checksum flags with its. It also hands a segment
# that arrives ahead of a gap straight to the next protocol unless it is asked
# to wait for the gap to fill, which pilotfish always does.
TSHARK_PREFERENCES = (
    "-o",
    "ip.check_checksum:TRUE",
    "-o",
    "udp.check_checksum:TRUE",
    "-o",
    "tcp.check_checksum:TRUE",
    "-o",
    "tcp.reassemble_out_of_order:TRUE",
)

# The dissector tests compare against every field tshark decodes. That output
# is large, so it is stored gzipped, and only for the captures that carry
# protocols worth comparing: the pcapng-test-generator files exercise the file
# format instead, and pcapng-example.pcapng alone decodes to 1.6 MB.
NO_JSON_KEY = ("pcapng-test-generator", "pcapng-example.pcapng")

FILTERS_FILE = SAMPLES_DIR / "display-filters.txt"


def find_captures() -> list[Path]:
    return sorted(p for p in SAMPLES_DIR.rglob("*") if p.suffix in CAPTURE_SUFFIXES)


def run_tool(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"{' '.join(command)} failed in {cwd}:\n{result.stderr}")
    return result.stdout


def decodes(capture: Path) -> bool:
    """Whether the capture carries protocols worth comparing, not only a file format."""
    return not any(part in NO_JSON_KEY for part in (*capture.parts, capture.name))


def display_filters() -> list[str]:
    lines = FILTERS_FILE.read_text().splitlines()
    return [line for line in lines if line and not line.startswith("#")]


def as_ranges(numbers: list[int]) -> str:
    """Packet numbers as runs, ``1-3,7``, which keeps a filter that matches
    most of a capture to a line."""
    runs: list[list[int]] = []
    for number in numbers:
        if runs and number == runs[-1][1] + 1:
            runs[-1][1] = number
        else:
            runs.append([number, number])
    return ",".join(str(first) if first == last else f"{first}-{last}" for first, last in runs)


def pilotfish_decodes(capture: Path) -> bool:
    """Whether pilotfish has a dissector for what the capture's packets start with.

    Where it has none, as for 802.15.4 or IrDA, it decodes nothing above the
    frame, and a display filter can't match what tshark's does.
    """
    with CaptureFile(capture) as file:
        first = next(iter(file), None)
    return first is not None and REGISTRY.find(LINK_TYPE, first.link_type) is not None


def write_filter_key(capture: Path) -> None:
    """Record which packets tshark says each display filter matches."""
    key = capture.with_name(capture.name + ".filters.json")
    if not (decodes(capture) and pilotfish_decodes(capture)):
        key.unlink(missing_ok=True)
        return

    def matched(expression: str) -> str:
        tshark = ["tshark", "-n", "-r", capture.name, *TSHARK_PREFERENCES]
        chosen = ["-Y", expression, "-T", "fields", "-e", "frame.number"]
        numbers = run_tool([*tshark, *chosen], capture.parent)
        return as_ranges([int(number) for number in numbers.split()])

    filters = display_filters()
    with ThreadPoolExecutor() as pool:
        answers = dict(zip(filters, pool.map(matched, filters), strict=True))
    key.write_text(json.dumps(answers, indent=1) + "\n")


def write_answer_keys(capture: Path) -> None:
    # Run from the capture's folder so capinfos records only the file name,
    # not a path from this machine.
    fields = [arg for field in TSHARK_FIELDS for arg in ("-e", field)]
    tshark = ["tshark", "-n", "-r", capture.name, "-Y", TSHARK_FILTER, "-T"]
    rows = [*tshark, "fields", "-E", "header=y", *fields]
    capture.with_name(capture.name + ".tshark.tsv").write_text(run_tool(rows, capture.parent))
    capinfos = ["capinfos", *CAPINFOS_FLAGS, capture.name]
    capture.with_name(capture.name + ".capinfos.tsv").write_text(run_tool(capinfos, capture.parent))

    key = capture.with_name(capture.name + ".tshark.json.gz")
    if not decodes(capture):
        key.unlink(missing_ok=True)
        return
    decoded = run_tool([*tshark, "json", *TSHARK_PREFERENCES], capture.parent)
    # A fixed timestamp keeps re-recording from changing bytes that didn't.
    key.write_bytes(gzip.compress(decoded.encode(), compresslevel=9, mtime=0))


def main(argv: list[str]) -> None:
    filters_only = "--filters" in argv
    captures = [Path(arg).resolve() for arg in argv if arg != "--filters"] or find_captures()
    for capture in captures:
        if not filters_only:
            write_answer_keys(capture)
        write_filter_key(capture)
        print(f"wrote answer keys for {capture.relative_to(SAMPLES_DIR.parent)}")


if __name__ == "__main__":
    main(sys.argv[1:])
