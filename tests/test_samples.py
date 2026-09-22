"""Compare pilotfish with tshark and capinfos on every sample capture.

The answer keys beside each capture are those tools' own output, recorded by
scripts/update_answer_keys.py, so these tests run without Wireshark installed.
"""

import csv
from pathlib import Path

import pytest

from pilotfish.core.formats import CaptureFile

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURE_SUFFIXES = frozenset({".cap", ".ntar", ".pcap", ".pcapng"})
CAPTURES = sorted(p for p in SAMPLES_DIR.rglob("*") if p.suffix in CAPTURE_SUFFIXES)

# For some link types Wireshark moves a fixed-size pseudo-header out of the
# packet and into metadata, so its frame.len and frame.cap_len leave it out.
# pilotfish reports the lengths stored in the file, as libpcap and tcpdump do.
WIRESHARK_PSEUDO_HEADER_BYTES = {144: 16}  # LINKTYPE_LINUX_IRDA


def parse_time(text: str) -> int | None:
    """Turn tshark's or capinfos's decimal seconds into exact nanoseconds."""
    if text in {"", "n/a"}:
        return None
    sign = -1 if text.startswith("-") else 1
    seconds, _, fraction = text.removeprefix("-").partition(".")
    return sign * (int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0")))


def answer_key(capture: Path, tool: str) -> list[dict[str, str]]:
    path = capture.with_name(f"{capture.name}.{tool}.tsv")
    if not path.exists():
        pytest.fail(f"no {path.name}; run: uv run scripts/update_answer_keys.py {capture}")
    with path.open(newline="") as file:
        return list(csv.DictReader(file, delimiter="\t", quoting=csv.QUOTE_NONE))


def sample_id(capture: Path) -> str:
    return str(capture.relative_to(SAMPLES_DIR))


def test_there_are_samples() -> None:
    assert len(CAPTURES) >= 10


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_packets_match_tshark(capture: Path) -> None:
    expected = [
        (
            parse_time(row["frame.time_epoch"]),
            int(row["frame.len"]),
            int(row["frame.cap_len"]),
            int(row["frame.interface_id"] or 0),  # blank for pcap, which has one interface
        )
        for row in answer_key(capture, "tshark")
    ]
    actual = []
    with CaptureFile(capture) as packets:
        for p in packets:
            hidden = WIRESHARK_PSEUDO_HEADER_BYTES.get(p.link_type, 0)
            lengths = (p.original_length - hidden, p.captured_length - hidden)
            actual.append((p.timestamp_ns, *lengths, p.interface_id))
    assert actual == expected


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_summary_matches_capinfos(capture: Path) -> None:
    [row] = answer_key(capture, "capinfos")
    with CaptureFile(capture) as packets:
        times = [p.timestamp_ns for p in packets]
    stamps = [t for t in times if t is not None]
    # capinfos gives no start or end time when any packet lacks a timestamp.
    span = (min(stamps), max(stamps)) if stamps and len(stamps) == len(times) else (None, None)
    assert len(times) == int(row["Number of packets"])
    assert span == (parse_time(row["Start time"]), parse_time(row["End time"]))
