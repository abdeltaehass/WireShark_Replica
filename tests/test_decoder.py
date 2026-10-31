"""Decoding on demand: any packet, in any order, as decoding in order gives it."""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.decoder import (
    CHECKPOINT_BYTES,
    CHECKPOINT_SPACING,
    MAX_CHECKPOINTS,
    SUMMARIES_KEPT,
    TREES_KEPT,
    Decoder,
    Summary,
)
from pilotfish.core.dissect import Node, ProtocolTree, Session, dissect
from pilotfish.core.formats import CaptureFile, CaptureFileError, PacketIndex
from pilotfish.core.packet import Packet

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURES = sorted(
    capture
    for capture in SAMPLES_DIR.rglob("*")
    if capture.suffix in {".cap", ".ntar", ".pcap", ".pcapng"}
)
# Captures whose packets depend on the ones before: TCP analysis, streams,
# fragments and messages that span segments.
STATEFUL = [
    SAMPLES_DIR / "wireshark-wiki" / "http.cap",
    SAMPLES_DIR / "made" / "tcp.pcap",
    SAMPLES_DIR / "made" / "segments.pcap",
    SAMPLES_DIR / "made" / "fragments.pcap",
    SAMPLES_DIR / "made" / "http-download.pcap",
    SAMPLES_DIR / "made" / "tls.pcap",
    SAMPLES_DIR / "made" / "ssh.pcap",
]


def shape(tree: ProtocolTree) -> tuple[object, ...]:
    """A tree as plain data, to compare by content.

    Fields point at the reassembled bytes they came from, and those compare
    by identity, so they are replaced here by their name and bytes.
    """

    def node(item: Node) -> tuple[object, ...]:
        source = None if item.source is None else (item.source.name, item.source.data)
        children = tuple(node(child) for child in item.children)
        return (
            *(item.name, item.label, item.type, item.offset, item.length, repr(item.value)),
            *(item.summary, item.hex, item.digits, source, children),
        )

    sources = tuple((source.name, source.data) for source in tree.sources)
    layers = tuple(node(layer) for layer in tree.layers)
    return layers, tree.info, tree.protocol, tree.error, sources


def in_order(capture: Path) -> list[ProtocolTree]:
    """Every packet decoded in order, the way the command line does it."""
    session = Session()
    with CaptureFile(capture) as file:
        try:
            return [
                dissect(packet, number, session=session)
                for number, packet in enumerate(file, start=1)
            ]
        except CaptureFileError:
            pytest.skip("the file is damaged; the index tests cover that")


def opens(capture: Path) -> bool:
    try:
        CaptureFile(capture).close()
    except CaptureFileError:
        return False
    return True


@contextmanager
def decoder_for(
    capture: Path,
    *,
    spacing: int = CHECKPOINT_SPACING,
    checkpoints: int = MAX_CHECKPOINTS,
    checkpoint_bytes: int = CHECKPOINT_BYTES,
    summaries: int = SUMMARIES_KEPT,
    trees: int = TREES_KEPT,
) -> Iterator[Decoder]:
    with PacketIndex.open(capture) as index:
        yield Decoder(
            index,
            spacing=spacing,
            checkpoints=checkpoints,
            checkpoint_bytes=checkpoint_bytes,
            summaries=summaries,
            trees=trees,
        )


@pytest.mark.parametrize(
    "capture",
    [capture for capture in CAPTURES if opens(capture)],
    ids=lambda capture: str(capture.relative_to(SAMPLES_DIR)),
)
def test_every_summary_is_the_packet_lists(capture: Path) -> None:
    expected = [Summary.of(tree) for tree in in_order(capture)]
    with decoder_for(capture, spacing=5) as decoder:
        assert decoder.advance(len(decoder)) == len(expected)
        assert [decoder.summary(row) for row in range(len(decoder))] == expected
        # Every checkpoint could be taken, so none had to be skipped.
        assert decoder.checkpoints == tuple(range(0, len(expected), 5))


@pytest.mark.parametrize("capture", STATEFUL, ids=lambda capture: capture.name)
@given(data=st.data())
def test_any_packet_in_any_order_is_as_in_order(capture: Path, data: st.DataObject) -> None:
    expected = in_order(capture)
    rows = st.integers(0, len(expected) - 1)
    # Tiny caches and close checkpoints, so most answers are decoded again.
    with decoder_for(capture, spacing=3, summaries=4, trees=2) as decoder:
        for row in data.draw(st.lists(rows, min_size=1, max_size=30)):
            ahead = row >= decoder.decoded
            summary = decoder.summary(row)
            assert summary is None if ahead else summary == Summary.of(expected[row])
            assert shape(decoder.tree(row)) == shape(expected[row])
            assert decoder.decoded >= row + 1


def test_nothing_is_decoded_until_asked() -> None:
    with decoder_for(SAMPLES_DIR / "wireshark-wiki" / "dns.cap") as decoder:
        assert decoder.decoded == 0
        assert decoder.summary(0) is None
        assert decoder.advance(9) == 10
        assert decoder.summary(9) is not None
        assert decoder.summary(10) is None


def test_advancing_stops_at_the_deadline() -> None:
    with decoder_for(SAMPLES_DIR / "wireshark-wiki" / "dns.cap") as decoder:
        # A deadline already past still decodes one packet, so a front end
        # decoding a slice at a time always gets somewhere.
        assert decoder.advance(len(decoder), deadline=time.monotonic() - 1) == 1
        assert decoder.advance(len(decoder) + 100) == len(decoder)


def test_a_tree_ahead_is_decoded_up_to_it() -> None:
    capture = SAMPLES_DIR / "wireshark-wiki" / "http.cap"
    expected = in_order(capture)
    with decoder_for(capture) as decoder:
        assert shape(decoder.tree(37)) == shape(expected[37])
        assert decoder.decoded == 38


def test_checkpoints_thin_out_to_stay_within_their_limit() -> None:
    capture = SAMPLES_DIR / "wireshark-wiki" / "http.cap"
    expected = in_order(capture)
    with decoder_for(capture, spacing=1, checkpoints=4, summaries=1, trees=1) as decoder:
        decoder.advance(len(decoder))
        assert len(decoder.checkpoints) <= 4
        assert decoder.checkpoints[0] == 0
        for row in reversed(range(len(expected))):
            assert decoder.summary(row) == Summary.of(expected[row])
            assert shape(decoder.tree(row)) == shape(expected[row])


def test_checkpoints_thin_out_to_stay_within_their_bytes() -> None:
    capture = SAMPLES_DIR / "made" / "segments.pcap"
    expected = in_order(capture)
    # Room for the empty session at the start and little else.
    with decoder_for(capture, spacing=1, checkpoint_bytes=2_000, summaries=1, trees=1) as decoder:
        decoder.advance(len(decoder))
        assert 1 <= len(decoder.checkpoints) < len(expected)
        assert decoder.checkpoints[0] == 0
        for row in reversed(range(len(expected))):
            assert shape(decoder.tree(row)) == shape(expected[row])


def test_there_is_no_tree_past_the_end() -> None:
    with decoder_for(SAMPLES_DIR / "wireshark-wiki" / "dns.cap") as decoder:
        with pytest.raises(IndexError, match="there is no packet 39; the file has 38"):
            decoder.tree(38)
        assert decoder.summary(38) is None


def test_every_packet_is_shown_to_the_visitor_once_in_order() -> None:
    capture = SAMPLES_DIR / "wireshark-wiki" / "http.cap"
    expected = in_order(capture)
    seen: list[tuple[int, tuple[object, ...]]] = []
    with decoder_for(capture, spacing=4, summaries=2, trees=1) as decoder:
        decoder.visit = lambda row, tree: seen.append((row, shape(tree)))
        decoder.advance(9)
        decoder.tree(20)  # decodes up to it
        decoder.tree(3)  # decoded again from a checkpoint, which isn't news
        decoder.summary(1)
        decoder.advance(len(decoder))
    assert seen == [(row, shape(tree)) for row, tree in enumerate(expected)]


class Growing:
    """Packets arriving as a live capture's do: more of them every so often."""

    def __init__(self, packets: list[Packet]) -> None:
        self.waiting = packets
        self.arrived: list[Packet] = []

    def arrive(self, count: int) -> None:
        self.arrived += self.waiting[:count]
        del self.waiting[:count]

    def __len__(self) -> int:
        return len(self.arrived)

    def __getitem__(self, row: int) -> Packet:
        return self.arrived[row]


def test_a_capture_that_grows_is_decoded_as_it_grows() -> None:
    capture = SAMPLES_DIR / "made" / "segments.pcap"
    expected = in_order(capture)
    with CaptureFile(capture) as file:
        growing = Growing(list(file))
    decoder = Decoder(growing, spacing=3)
    assert decoder.advance(100) == 0
    while growing.waiting:
        growing.arrive(4)
        assert decoder.advance(100) == len(growing)
    for row in reversed(range(len(expected))):
        assert shape(decoder.tree(row)) == shape(expected[row])
