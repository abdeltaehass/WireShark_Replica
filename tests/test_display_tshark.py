"""Hold the display filters to tshark's answers.

``samples/display-filters.txt`` is a list of filters, and beside every sample
capture is the list of packets ``tshark -Y`` matched for each of them,
recorded by ``scripts/update_answer_keys.py``. A filter here has to match
exactly the packets tshark matched, which checks the whole chain at once: the
parse, the types, the evaluation, and the fields the dissectors produced.
"""

import json
from functools import cache
from pathlib import Path

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
import tshark
from pilotfish.core.display import DisplayFilter, compile_display_filter
from pilotfish.core.dissect import ProtocolTree, Session, dissect
from pilotfish.core.formats import CaptureFile
from pilotfish.core.packet import Packet

FILTERS_FILE = tshark.SAMPLES_DIR / "display-filters.txt"
KEY_SUFFIX = ".filters.json"

KNOWN_DIFFERENCES = {
    # tshark starts a layer for the first bytes of a message that isn't all
    # there yet, and when it has to wait for the rest the layer stays in the
    # tree with nothing in it. So the protocol's name matches a packet that
    # carries only the start of a message. pilotfish adds no layer until
    # there is a message to put in it.
    ("segments.pcap", "tls"),
    ("segments.pcap", "ssh"),
    # A segment that fills a gap delivers the ones waiting behind it too, and
    # pilotfish lists the segments those bytes came from. tshark only lists
    # them when a protocol above asked for more bytes, and here nothing did.
    ("tcp.pcap", "tcp.segment"),
}


def filters() -> list[str]:
    lines = FILTERS_FILE.read_text().splitlines()
    return [line for line in lines if line and not line.startswith("#")]


def recorded() -> list[Path]:
    """Every capture with tshark's answers beside it."""
    return sorted(
        key.with_name(key.name.removesuffix(KEY_SUFFIX))
        for key in tshark.SAMPLES_DIR.rglob(f"*{KEY_SUFFIX}")
    )


def answers(capture: Path) -> dict[str, str]:
    key = capture.with_name(capture.name + KEY_SUFFIX)
    loaded: dict[str, str] = json.loads(key.read_text())
    return loaded


def decoded(capture: Path) -> list[tuple[Packet, ProtocolTree]]:
    session = Session()
    with CaptureFile(capture) as file:
        return [
            (packet, dissect(packet, number, session=session))
            for number, packet in enumerate(file, start=1)
        ]


CAPTURES = recorded()
"""Answers are only recorded for captures whose link type pilotfish decodes.
For the others, such as 802.15.4 and IrDA, it decodes nothing above the frame,
and a filter on a protocol inside can't match what tshark's does."""


@cache
def compiled(text: str) -> DisplayFilter:
    return compile_display_filter(text)


def as_ranges(numbers: list[int]) -> str:
    """Packet numbers as the answer keys write them: ``1-3,7``."""
    runs: list[list[int]] = []
    for number in numbers:
        if runs and number == runs[-1][1] + 1:
            runs[-1][1] = number
        else:
            runs.append([number, number])
    return ",".join(str(first) if first == last else f"{first}-{last}" for first, last in runs)


def sample_id(capture: Path) -> str:
    return str(capture.relative_to(tshark.SAMPLES_DIR))


def test_the_answers_cover_the_list_of_filters() -> None:
    """A filter added to the list has no answers until they are recorded."""
    listed = filters()
    assert len(listed) >= 300
    assert len(set(listed)) == len(listed)
    for capture in CAPTURES:
        assert list(answers(capture)) == listed, (
            f"{capture.name}: run scripts/update_answer_keys.py --filters"
        )


def test_the_samples_give_the_filters_something_to_match() -> None:
    """The comparison is only worth having if the answers aren't all empty.

    Nearly every filter in the list has to match a packet in some capture
    the repository holds, and fail to match one in some other.
    """
    assert len(CAPTURES) >= 15
    matched: set[str] = set()
    for capture in CAPTURES:
        if capture.relative_to(tshark.SAMPLES_DIR).parts[0] == "private":
            continue
        matched.update(text for text, packets in answers(capture).items() if packets)
    listed = filters()
    assert len(matched) >= len(listed) * 0.9


@pytest.mark.parametrize("text", filters())
def test_every_listed_filter_compiles(text: str) -> None:
    compiled(text)


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_every_filter_matches_the_packets_tshark_matched(capture: Path) -> None:
    packets = decoded(capture)
    wrong: dict[str, tuple[str, str]] = {}
    for text, expected in answers(capture).items():
        if (capture.name, text) in KNOWN_DIFFERENCES:
            continue
        display = compiled(text)
        ours = as_ranges(
            [
                number
                for number, (packet, tree) in enumerate(packets, start=1)
                if display.matches(tree, packet.data)
            ]
        )
        walked = as_ranges(
            [
                number
                for number, (packet, tree) in enumerate(packets, start=1)
                if display.walk(tree, packet.data)
            ]
        )
        assert ours == walked, f"{text}: the generated code and the tree walk disagree"
        if ours != expected:
            wrong[text] = (expected, ours)
    assert not wrong, "tshark's packets, then pilotfish's"


def test_the_known_differences_are_still_differences() -> None:
    """Each exception above has to earn its place.

    If pilotfish and tshark come to agree on one of them, it should stop
    being excused.
    """
    by_name = {capture.name: capture for capture in CAPTURES}
    for name, text in sorted(KNOWN_DIFFERENCES):
        packets = decoded(by_name[name])
        ours = as_ranges(
            [
                number
                for number, (packet, tree) in enumerate(packets, start=1)
                if compiled(text).matches(tree, packet.data)
            ]
        )
        assert ours != answers(by_name[name])[text], f"{name}: {text}"
