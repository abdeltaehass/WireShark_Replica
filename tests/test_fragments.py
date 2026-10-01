"""Fragments, in every order and state a network can deliver them in.

The reassembler takes whatever it is given, and what it is given is chosen by
whoever sent the packets. So as well as putting a datagram back together, it
has to stay small when the pieces never add up to one.
"""

from hypothesis import given
from hypothesis import strategies as st

from pilotfish.core.reassembly import Fragments
from pilotfish.core.reassembly.fragments import MAX_DATAGRAM, MAX_FRAGMENTS

KEY = ("192.0.2.1", "192.0.2.2", 17, 0x1234)
SECOND = 1_000_000_000


def pieces(data: bytes, size: int) -> list[tuple[int, bytes, bool]]:
    """A datagram cut every ``size`` bytes: where each piece goes, the piece,
    and whether more follow it."""
    return [
        (offset, data[offset : offset + size], offset + size < len(data))
        for offset in range(0, len(data), size)
    ]


def feed(fragments: Fragments, cut: list[tuple[int, bytes, bool]], key: object = KEY) -> bytes:
    """Add every piece, and return the datagram the last of them completed."""
    whole = None
    for frame, (offset, data, more) in enumerate(cut, start=1):
        assert whole is None, "the datagram was complete before its last piece"
        whole = fragments.add(key, offset, data, more=more, frame=frame)
    assert whole is not None
    return whole.data


DATAGRAM = bytes(range(256)) * 12


class TestPuttingADatagramBackTogether:
    def test_in_the_order_it_was_cut(self) -> None:
        assert feed(Fragments(), pieces(DATAGRAM, 1480)) == DATAGRAM

    def test_backwards(self) -> None:
        assert feed(Fragments(), pieces(DATAGRAM, 1480)[::-1]) == DATAGRAM

    def test_the_middle_last(self) -> None:
        first, middle, last = pieces(DATAGRAM, 1480)
        assert feed(Fragments(), [first, last, middle]) == DATAGRAM

    def test_nothing_comes_back_until_the_last_piece(self) -> None:
        fragments = Fragments()
        first, middle, last = pieces(DATAGRAM, 1480)
        assert fragments.add(KEY, *first[:2], more=True, frame=1) is None
        assert fragments.add(KEY, *last[:2], more=False, frame=2) is None
        assert len(fragments) == 1
        whole = fragments.add(KEY, *middle[:2], more=True, frame=3)
        assert whole is not None
        assert whole.frames == (1, 2, 3)

    def test_nothing_is_kept_once_it_is_whole(self) -> None:
        fragments = Fragments()
        feed(fragments, pieces(DATAGRAM, 1480))
        assert len(fragments) == 0
        assert fragments.buffered == 0

    def test_two_datagrams_at_once_stay_apart(self) -> None:
        fragments = Fragments()
        other = ("192.0.2.1", "192.0.2.2", 17, 0x9999)
        ours, theirs = pieces(DATAGRAM, 1480), pieces(DATAGRAM[::-1], 1480)
        for frame, (mine, yours) in enumerate(zip(ours[:-1], theirs[:-1], strict=True)):
            assert fragments.add(KEY, *mine[:2], more=True, frame=frame) is None
            assert fragments.add(other, *yours[:2], more=True, frame=frame) is None
        first = fragments.add(KEY, *ours[-1][:2], more=False, frame=9)
        second = fragments.add(other, *theirs[-1][:2], more=False, frame=9)
        assert first is not None
        assert second is not None
        assert (first.data, second.data) == (DATAGRAM, DATAGRAM[::-1])

    def test_a_datagram_that_ends_with_an_empty_fragment(self) -> None:
        fragments = Fragments()
        assert fragments.add(KEY, 0, b"abcdefgh", more=True, frame=1) is None
        whole = fragments.add(KEY, 8, b"", more=False, frame=2)
        assert whole is not None
        assert whole.data == b"abcdefgh"

    @given(
        data=st.binary(min_size=1, max_size=4000),
        size=st.integers(1, 200).map(lambda words: words * 8),
        order=st.randoms(use_true_random=False),
        repeats=st.integers(0, 3),
    )
    def test_any_order_with_any_piece_repeated(
        self, data: bytes, size: int, order: object, repeats: int
    ) -> None:
        cut = pieces(data, size)
        shuffled = cut + cut[:repeats]
        order.shuffle(shuffled)  # type: ignore[attr-defined]
        fragments = Fragments()
        whole = None
        for frame, (offset, piece, more) in enumerate(shuffled):
            whole = fragments.add(KEY, offset, piece, more=more, frame=frame) or whole
        assert whole is not None
        assert whole.data == data
        assert not whole.conflict


class TestFragmentsThatOverlap:
    def test_the_same_piece_twice_is_noted_and_harmless(self) -> None:
        first, last = pieces(DATAGRAM[:2000], 1480)
        fragments = Fragments()
        fragments.add(KEY, *first[:2], more=True, frame=1)
        fragments.add(KEY, *first[:2], more=True, frame=2)
        whole = fragments.add(KEY, *last[:2], more=False, frame=3)
        assert whole is not None
        assert whole.data == DATAGRAM[:2000]
        assert whole.overlap
        assert not whole.conflict
        assert whole.frames == (1, 2, 3)

    def test_the_bytes_that_came_first_are_the_ones_kept(self) -> None:
        # A fragment sent to rewrite one that has already arrived is how a
        # packet gets to mean one thing to a filter and another to the host
        # behind it. The rewrite is refused, and remembered.
        fragments = Fragments()
        fragments.add(KEY, 0, b"GET /safe", more=True, frame=1)
        whole = fragments.add(KEY, 4, b"/evil HTTP/1.1  ", more=False, frame=2)
        assert whole is not None
        assert whole.data == b"GET /safe HTTP/1.1  "
        assert whole.overlap
        assert whole.conflict

    def test_a_piece_that_fills_a_hole_and_laps_both_sides(self) -> None:
        fragments = Fragments()
        fragments.add(KEY, 0, b"aaaaaaaa", more=True, frame=1)
        fragments.add(KEY, 16, b"cccccccc", more=False, frame=2)
        whole = fragments.add(KEY, 4, b"XXXXbbbbbbbbXXXX", more=True, frame=3)
        assert whole is not None
        assert whole.data == b"aaaaaaaabbbbbbbbcccccccc"
        assert whole.conflict

    def test_two_last_fragments_that_disagree(self) -> None:
        fragments = Fragments()
        fragments.add(KEY, 8, b"12345678", more=False, frame=1)
        # A second "last" piece, claiming the datagram is longer than that.
        fragments.add(KEY, 16, b"abcdefgh", more=False, frame=2)
        whole = fragments.add(KEY, 0, b"ABCDEFGH", more=True, frame=3)
        assert whole is not None
        assert whole.data == b"ABCDEFGH12345678"
        assert whole.conflict

    def test_a_last_fragment_that_ends_before_bytes_already_here(self) -> None:
        fragments = Fragments()
        fragments.add(KEY, 8, b"12345678", more=True, frame=1)
        fragments.add(KEY, 0, b"ABCDEFGH", more=True, frame=2)
        whole = fragments.add(KEY, 8, b"1234", more=False, frame=3)
        assert whole is not None
        assert whole.data == b"ABCDEFGH1234"
        assert whole.conflict


class TestAFloodOfFragments:
    """None of these ever completes, and none of them may cost much."""

    def test_a_datagram_is_forgotten_when_it_has_waited_too_long(self) -> None:
        fragments = Fragments(timeout=30 * SECOND)
        fragments.add(KEY, 0, b"abcdefgh", more=True, frame=1, time=0)
        fragments.add(("other",), 0, b"abcdefgh", more=True, frame=2, time=20 * SECOND)
        assert len(fragments) == 2
        fragments.add(("third",), 0, b"abcdefgh", more=True, frame=3, time=31 * SECOND)
        assert len(fragments) == 2
        # Its last piece arrives too late to complete anything.
        assert fragments.add(KEY, 8, b"ijklmnop", more=False, frame=4, time=32 * SECOND) is None

    def test_a_capture_with_no_times_never_times_anything_out(self) -> None:
        fragments = Fragments(timeout=1)
        fragments.add(KEY, 0, b"abcdefgh", more=True, frame=1)
        whole = fragments.add(KEY, 8, b"ijklmnop", more=False, frame=2)
        assert whole is not None

    def test_first_fragments_that_never_finish_stay_under_the_limit(self) -> None:
        fragments = Fragments(limit=64 * 1024)
        for number in range(5000):
            fragments.add(("flood", number), 0, bytes(1480), more=True, frame=number)
            assert fragments.buffered <= 64 * 1024
        assert len(fragments) == 64 * 1024 // 1480

    def test_the_oldest_go_first(self) -> None:
        fragments = Fragments(limit=3000)
        fragments.add(("old",), 0, bytes(1480), more=True, frame=1)
        fragments.add(("new",), 0, bytes(1480), more=True, frame=2)
        fragments.add(("newest",), 0, bytes(1480), more=True, frame=3)
        assert fragments.add(("old",), 1480, b"end", more=False, frame=4) is None
        assert fragments.add(("newest",), 1480, b"end", more=False, frame=5) is not None

    def test_tiny_fragments_at_the_far_end_are_counted_by_what_they_reserve(self) -> None:
        # Eight bytes at the far end of a datagram reserve room for all of
        # it, so it is the room that is counted, not the eight bytes.
        fragments = Fragments(limit=256 * 1024)
        for number in range(1000):
            fragments.add(("far", number), MAX_DATAGRAM - 15, bytes(8), more=True, frame=number)
        assert fragments.buffered <= 256 * 1024
        assert len(fragments) <= 4

    def test_no_more_datagrams_than_the_most_allowed(self) -> None:
        fragments = Fragments(most=10)
        for number in range(100):
            fragments.add(("many", number), 0, b"abcdefgh", more=True, frame=number)
        assert len(fragments) == 10

    def test_a_fragment_past_the_largest_datagram_is_refused(self) -> None:
        # The "ping of death": pieces that are each legal and add up to more
        # than the sixteen-bit length of a datagram can describe.
        fragments = Fragments()
        assert fragments.add(KEY, 65528, bytes(16), more=False, frame=1) is None
        assert len(fragments) == 0

    def test_a_datagram_in_too_many_pieces_is_given_up_on(self) -> None:
        fragments = Fragments()
        for number in range(MAX_FRAGMENTS + 1):
            fragments.add(KEY, 0, b"abcdefgh", more=True, frame=number)
        assert len(fragments) == 0
        assert fragments.buffered == 0

    @given(
        st.lists(
            st.tuples(
                st.integers(0, 3),
                st.integers(0, 8191).map(lambda units: units * 8),
                st.binary(max_size=64),
                st.booleans(),
            ),
            max_size=200,
        )
    )
    def test_whatever_arrives_the_books_balance(
        self, arriving: list[tuple[int, int, bytes, bool]]
    ) -> None:
        fragments = Fragments(limit=100_000, most=3)
        for frame, (key, offset, data, more) in enumerate(arriving):
            whole = fragments.add(key, offset, data, more=more, frame=frame)
            assert whole is None or len(whole.data) <= MAX_DATAGRAM
            assert 0 <= fragments.buffered <= 100_000 + MAX_DATAGRAM
            assert len(fragments) <= 3
