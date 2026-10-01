"""One direction of a TCP connection, put back in the order it was sent.

Segments arrive late, twice, and overlapping what came before. The flow has to
turn any of that back into the bytes that were written, and to say honestly
when some of them never reached the capture.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pilotfish.core.reassembly import Flow, Piece

DATA = bytes(range(256)) * 20


def segments(data: bytes, size: int, start: int = 1) -> list[tuple[int, bytes]]:
    """``data`` cut into segments: where each belongs, and its bytes."""
    return [(start + at, data[at : at + size]) for at in range(0, len(data), size)]


def listen(flow: Flow) -> list[tuple[bytes, int]]:
    """Everything the flow puts in order, as it does so."""
    heard: list[tuple[bytes, int]] = []
    flow.heard = lambda data, missed: heard.append((data, missed))
    return heard


def said(heard: list[tuple[bytes, int]]) -> bytes:
    return b"".join(data for data, _ in heard)


class TestPuttingSegmentsInOrder:
    def test_segments_that_arrive_in_order(self) -> None:
        flow = Flow()
        for frame, (position, data) in enumerate(segments(DATA, 1460)):
            added = flow.add(position, data, frame)
            assert added.fresh == len(data)
            assert not added.early
        assert bytes(flow.pending) == DATA

    def test_a_segment_ahead_of_a_gap_waits_for_it_to_close(self) -> None:
        flow = Flow()
        first, second, third = segments(DATA[:3000], 1000)
        assert flow.add(*first, frame=1).fresh == 1000
        ahead = flow.add(*third, frame=2)
        assert ahead.early
        assert ahead.fresh == 0
        assert bytes(flow.pending) == DATA[:1000]
        # The missing segment brings the one behind it along.
        assert flow.add(*second, frame=3).fresh == 2000
        assert bytes(flow.pending) == DATA[:3000]
        assert list(flow.pieces) == [Piece(1, 1000), Piece(3, 1000), Piece(2, 1000)]

    def test_a_segment_sent_again_adds_nothing(self) -> None:
        flow = Flow()
        first, second = segments(DATA[:2000], 1000)
        flow.add(*first, frame=1)
        flow.add(*second, frame=2)
        again = flow.add(*first, frame=3)
        assert again.fresh == 0
        assert again.seen == 1000
        assert bytes(flow.pending) == DATA[:2000]

    def test_a_segment_that_overlaps_what_has_arrived_adds_only_the_rest(self) -> None:
        # A sender that repackages what it has already sent: the same bytes
        # again, and new ones after them.
        flow = Flow()
        flow.add(1, DATA[:1000], frame=1)
        added = flow.add(501, DATA[500:1500], frame=2)
        assert (added.seen, added.fresh) == (500, 500)
        assert bytes(flow.pending) == DATA[:1500]

    def test_the_bytes_that_came_first_are_the_ones_kept(self) -> None:
        flow = Flow()
        flow.add(1, b"GET /safe", frame=1)
        flow.add(5, b"/evil HTTP/1.1", frame=2)
        assert bytes(flow.pending) == b"GET /safe HTTP/1.1"

    def test_segments_ahead_of_a_gap_that_overlap_each_other(self) -> None:
        flow = Flow()
        flow.add(1, DATA[:100], frame=1)
        flow.add(301, DATA[300:500], frame=2)
        flow.add(201, DATA[200:400], frame=3)
        flow.add(101, DATA[100:250], frame=4)
        assert bytes(flow.pending) == DATA[:500]

    def test_the_same_early_segment_twice_is_only_kept_once(self) -> None:
        flow = Flow()
        flow.add(1, DATA[:100], frame=1)
        for frame in range(2, 50):
            flow.add(501, DATA[500:600], frame=frame)
        assert flow.early_size == 100

    def test_the_first_segment_seen_is_where_the_stream_starts(self) -> None:
        # A capture that began after the connection did has no way to know
        # what came before, so it starts counting from what it sees.
        flow = Flow()
        flow.add(70_001, b"middle", frame=1)
        assert flow.start == 70_001
        assert bytes(flow.pending) == b"middle"

    @given(
        data=st.binary(min_size=1, max_size=5000),
        size=st.integers(1, 700),
        order=st.randoms(use_true_random=False),
        repeats=st.integers(0, 5),
        start=st.integers(0, 2**32 - 1),
    )
    def test_any_order_with_any_segment_repeated(
        self, data: bytes, size: int, order: object, repeats: int, start: int
    ) -> None:
        # Whatever order the network delivers them in, and however many are
        # sent twice, the stream comes out as it was written, even where the
        # sequence numbers wrap round to zero partway through.
        cut = segments(data, size, start)
        first, rest = cut[0], cut[1:] + cut[:repeats]
        order.shuffle(rest)  # type: ignore[attr-defined]
        flow = Flow()
        heard = listen(flow)
        flow.restart(start)
        for frame, (position, piece) in enumerate([first, *rest]):
            flow.add(flow.position(position % 2**32), piece, frame)
        assert bytes(flow.pending) == data
        assert said(heard) == data
        assert not flow.early

    @given(
        data=st.binary(min_size=1, max_size=3000),
        cuts=st.lists(st.tuples(st.integers(0, 3000), st.integers(1, 400)), max_size=40),
        order=st.randoms(use_true_random=False),
    )
    def test_segments_cut_anywhere_and_overlapping_anyhow(
        self, data: bytes, cuts: list[tuple[int, int]], order: object
    ) -> None:
        # Arbitrary overlapping windows onto the same bytes, then enough
        # plain segments to be sure every byte was sent at least once.
        windows = [(1 + at, data[at : at + length]) for at, length in cuts if at < len(data)]
        arriving = windows + segments(data, 97)
        order.shuffle(arriving)  # type: ignore[attr-defined]
        flow = Flow()
        flow.restart(1)
        for frame, (position, piece) in enumerate(arriving):
            flow.add(position, piece, frame)
        assert bytes(flow.pending) == data


class TestSequenceNumbersThatWrap:
    def test_a_stream_that_runs_past_four_gigabytes(self) -> None:
        flow = Flow()
        flow.restart(2**32 - 4)
        flow.add(flow.position(2**32 - 4), b"abcd", frame=1)
        # The next byte is numbered zero.
        added = flow.add(flow.position(0), b"efgh", frame=2)
        assert added.fresh == 4
        assert bytes(flow.pending) == b"abcdefgh"
        assert flow.next == 2**32 + 4

    def test_a_number_just_behind_is_old_and_not_four_gigabytes_ahead(self) -> None:
        flow = Flow()
        flow.restart(1000)
        flow.add(1000, b"abcd", frame=1)
        assert flow.position(996) == 996
        assert flow.position(2**32 - 1) == -1


class TestTakingMessagesOffTheFront:
    def test_a_message_names_the_packets_it_came_in(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=4)
        flow.add(101, bytes(100), frame=5)
        flow.add(201, bytes(100), frame=7)
        assert flow.take(150) == [Piece(4, 100), Piece(5, 50)]
        assert list(flow.pieces) == [Piece(5, 50), Piece(7, 100)]
        assert flow.start == 151
        assert len(flow.pending) == 150

    def test_waiting_for_a_number_of_bytes(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        ready = [flow.ready]
        flow.wait(50)
        ready.append(flow.ready)
        assert flow.exact
        flow.add(101, bytes(49), frame=2)
        ready.append(flow.ready)
        flow.add(150, bytes(1), frame=3)
        ready.append(flow.ready)
        assert ready == [True, False, False, True]

    def test_waiting_without_knowing_how_long(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        flow.wait()
        assert not flow.ready
        assert not flow.exact
        flow.add(101, b"x", frame=2)
        assert flow.ready

    def test_waiting_for_more_than_was_looked_at(self) -> None:
        # Only the first sixty bytes were shown, and forty more are wanted.
        # That much is here already.
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        flow.wait(40, have=60)
        assert flow.ready

    def test_waiting_for_the_stream_to_close(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        flow.wait(to_end=True)
        flow.add(101, bytes(100), frame=2)
        assert not flow.ready
        flow.close(201)
        assert flow.ended
        assert not flow.open
        assert flow.ready

    def test_a_stream_that_closes_past_a_gap_has_not_ended(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        flow.wait(to_end=True)
        flow.close(301)
        assert not flow.ended
        assert not flow.ready

    def test_taking_a_message_ends_the_wait(self) -> None:
        flow = Flow()
        flow.add(1, bytes(100), frame=1)
        flow.wait(1000)
        flow.take(100)
        assert (flow.wanted, flow.exact, flow.to_end) == (0, False, False)


class TestBytesTheCaptureNeverSaw:
    def test_an_acknowledgement_past_a_gap_gives_up_on_it(self) -> None:
        flow = Flow()
        heard = listen(flow)
        flow.add(1, DATA[:100], frame=1)
        flow.add(301, DATA[300:400], frame=2)
        # The other end has everything up to 401, so the 200 bytes this
        # capture is missing arrived without being recorded.
        assert flow.acknowledge(401) == 200
        assert heard == [(DATA[:100], 0), (DATA[300:400], 200)]
        assert flow.next == 401
        # The message that was waiting on them can't be finished.
        assert bytes(flow.pending) == DATA[300:400]

    def test_an_acknowledgement_proves_nothing_while_nothing_is_waiting(self) -> None:
        # An acknowledgement that runs ahead of the data may only mean the
        # data hasn't been read from the capture yet.
        flow = Flow()
        flow.add(1, DATA[:100], frame=1)
        assert flow.acknowledge(5000) == 0
        assert flow.next == 101
        assert flow.add(101, DATA[100:200], frame=2).fresh == 100

    def test_an_acknowledgement_short_of_the_gap_changes_nothing(self) -> None:
        flow = Flow()
        flow.add(1, DATA[:100], frame=1)
        flow.add(301, DATA[300:400], frame=2)
        assert flow.acknowledge(101) == 0
        assert flow.add(101, DATA[100:300], frame=3).fresh == 300

    def test_an_acknowledgement_part_way_into_a_gap(self) -> None:
        flow = Flow()
        heard = listen(flow)
        flow.add(1, DATA[:100], frame=1)
        flow.add(301, DATA[300:400], frame=2)
        assert flow.acknowledge(201) == 100
        # The rest of the gap can still arrive, and does.
        flow.add(201, DATA[200:300], frame=3)
        assert heard == [(DATA[:100], 0), (DATA[200:300], 100), (DATA[300:400], 0)]

    def test_two_gaps_given_up_on_at_once(self) -> None:
        flow = Flow()
        heard = listen(flow)
        flow.add(1, b"aaaa", frame=1)
        flow.add(11, b"bbbb", frame=2)
        flow.add(21, b"cccc", frame=3)
        assert flow.acknowledge(25) == 12
        assert heard == [(b"aaaa", 0), (b"bbbb", 6), (b"cccc", 6)]

    def test_nothing_is_given_up_beyond_what_was_seen_being_sent(self) -> None:
        flow = Flow()
        flow.add(1, b"aaaa", frame=1)
        flow.add(11, b"bbbb", frame=2)
        flow.acknowledge(1_000_000)
        assert flow.next == 15

    def test_a_late_copy_of_bytes_given_up_on_is_ignored(self) -> None:
        flow = Flow()
        flow.add(1, b"aaaa", frame=1)
        flow.add(11, b"bbbb", frame=2)
        flow.acknowledge(15)
        late = flow.add(5, b"------", frame=3)
        assert late.fresh == 0
        assert late.seen == 6


class TestAFlowThatCannotGrowWithoutEnd:
    def test_a_message_too_long_to_keep_stops_being_waited_for(self) -> None:
        flow = Flow(limit=1000)
        flow.add(1, bytes(400), frame=1)
        flow.wait(to_end=True)
        assert (flow.open, flow.ready) == (True, False)
        flow.add(401, bytes(600), frame=2)
        assert (flow.open, flow.ready) == (False, True)

    def test_a_message_that_asks_for_more_than_the_limit_is_not_waited_for(self) -> None:
        flow = Flow(limit=1000)
        flow.add(1, bytes(100), frame=1)
        flow.wait(5000)
        assert not flow.open
        assert flow.ready

    def test_too_much_waiting_on_a_gap_gives_up_on_the_gap(self) -> None:
        flow = Flow(limit=1000)
        heard = listen(flow)
        flow.add(1, bytes(10), frame=1)
        position = 101
        for frame in range(2, 20):
            flow.add(position, bytes(100), frame)
            position += 100
        assert flow.early_size <= 1000
        assert flow.next == position
        # The ninety bytes before the first of them are counted as lost.
        assert heard[1][1] == 90

    @given(
        st.lists(
            st.tuples(st.integers(0, 50_000), st.binary(max_size=300)), min_size=1, max_size=200
        )
    )
    def test_whatever_arrives_stays_under_the_limit(
        self, arriving: list[tuple[int, bytes]]
    ) -> None:
        flow = Flow(limit=2000)
        for frame, (position, data) in enumerate(arriving):
            flow.add(position, data, frame)
            if not flow.open:
                flow.take(len(flow.pending))
            assert flow.early_size <= 2000
            assert len(flow.pending) < 2000 + 300
            assert sum(piece.length for piece in flow.pieces) == len(flow.pending)


def test_a_segment_the_capture_cut_short_starts_the_stream_over() -> None:
    flow = Flow()
    flow.add(1, b"abcd", frame=1)
    flow.add(101, b"wxyz", frame=2)
    flow.restart()
    assert (flow.next, flow.early, flow.early_size) == (None, [], 0)
    assert not flow.pending
    flow.add(9001, b"fresh", frame=3)
    assert bytes(flow.pending) == b"fresh"


@pytest.mark.parametrize("count", [0, 5, 100, 1000])
def test_taking_more_than_there_is_takes_what_there_is(count: int) -> None:
    flow = Flow()
    flow.add(1, bytes(100), frame=1)
    taken = flow.take(count)
    assert sum(piece.length for piece in taken) == min(count, 100)
    assert len(flow.pending) == 100 - min(count, 100)
