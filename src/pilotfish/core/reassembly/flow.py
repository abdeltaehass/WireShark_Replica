"""The bytes one end of a TCP connection sent, back in the order it sent them.

TCP numbers every byte, so however the segments arrive — late, twice, or
overlapping what came before — each byte has exactly one place. A flow puts
them there: what is in order joins the end of a buffer, what is ahead of a gap
waits for the gap to close, and what has been seen already is dropped.

The buffer holds only what no message has claimed yet. Whoever reads the flow
takes whole messages off the front as they complete, so what stays behind is
the start of a message whose end hasn't arrived.
"""

from bisect import insort
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

WORD = 1 << 32
HALF = 1 << 31

LIMIT = 16 * 1024 * 1024
"""How many bytes a flow holds for a message that hasn't finished, and as many
again for segments ahead of a gap. Past that the message is handed over as it
stands, or the gap given up on, rather than growing without end."""


@dataclass(frozen=True, slots=True)
class Piece:
    """A run of bytes in the buffer, and the packet they arrived in."""

    frame: int
    length: int


@dataclass(frozen=True, slots=True)
class Added:
    """What became of one segment's bytes."""

    fresh: int = 0
    """How many bytes joined the end of the buffer: the segment's own, and
    any that had been waiting behind a gap it closed."""
    seen: int = 0
    """How many of the segment's leading bytes had been here before."""
    early: bool = False
    """Whether the segment is ahead of a gap, and is being kept until the
    bytes before it turn up."""


class Flow:
    """One direction of a connection, as a stream of bytes."""

    def __init__(self, limit: int = LIMIT) -> None:
        self.next: int | None = None
        """Where the next byte in order belongs. Not known until the first
        segment says where the stream is up to."""
        self.pending = bytearray()
        """Bytes in order that no message has claimed yet."""
        self.pieces: deque[Piece] = deque()
        """Which packets those bytes came in, front to back."""
        self.early: list[tuple[int, int, bytes]] = []
        """Segments ahead of a gap: position, packet and bytes, by position."""
        self.early_size = 0
        self.wanted = 0
        """How long the message at the front has to be before there is any
        point looking at it again."""
        self.exact = False
        """Whether that is where the message ends, rather than a guess."""
        self.to_end = False
        """Whether the message at the front runs until the stream closes."""
        self.end: int | None = None
        """Where the stream stops, once a FIN or a reset has said."""
        self.limit = limit
        self.heard: Callable[[bytes, int], None] | None = None
        """Called with each run of bytes as it falls into order, and how many
        bytes the capture missed just before it. Following a stream is
        listening here."""
        self._missed = 0

    @property
    def start(self) -> int:
        """Where the first byte still in the buffer belongs."""
        return (self.next or 0) - len(self.pending)

    @property
    def ended(self) -> bool:
        """Whether every byte the stream will ever carry has arrived."""
        return self.end is not None and self.next is not None and self.next >= self.end

    @property
    def open(self) -> bool:
        """Whether the message at the front can wait for more bytes.

        It can't once it has outgrown the limit, or when it was waiting for
        the stream to close and the stream has.
        """
        if len(self.pending) >= self.limit or self.wanted > self.limit:
            return False
        return not (self.to_end and self.ended)

    @property
    def ready(self) -> bool:
        """Whether the buffer holds something worth showing to a dissector."""
        if not self.pending:
            return False
        if not self.open:
            return True
        return not self.to_end and len(self.pending) >= self.wanted

    def position(self, sequence: int) -> int:
        """Where a sequence number falls in the stream.

        Sequence numbers are thirty-two bits and wrap, so a long download
        passes the same number more than once. The position nearest to where
        the stream is up to is the one meant.
        """
        if self.next is None:
            return sequence
        return self.next + (sequence - self.next + HALF) % WORD - HALF

    def add(self, position: int, data: bytes, frame: int) -> Added:
        """Put a segment's bytes where they belong in the stream."""
        if self.next is None:
            self.next = position
        end = position + len(data)
        if end <= self.next:
            # All of it has been here before: a retransmission.
            return Added(seen=len(data))
        if position > self.next:
            return self._keep(position, data, frame)
        seen = self.next - position
        before = len(self.pending)
        self._append(data[seen:], frame)
        self._close_gaps()
        return Added(fresh=len(self.pending) - before, seen=seen)

    def acknowledge(self, position: int) -> int:
        """The other end says it has everything before ``position``.

        If the capture is still waiting for some of that, it is waiting for
        bytes that arrived without being captured, and they will not be sent
        again. So the gap is given up on, along with the unfinished message
        in front of it, and the stream carries on from the far side. Returns
        how many bytes were given up on.

        Nothing is given up while no later segment is waiting: an
        acknowledgement on its own is not proof that the capture missed
        anything, only that it hasn't seen it yet.
        """
        if self.next is None or not self.early:
            return 0
        # Nothing can have been received that was never seen being sent.
        last, _, data = self.early[-1]
        position = min(position, last + len(data))
        lost = 0
        while self.early and self.next < position:
            lost += self._skip(min(position, self.early[0][0]))
        return lost

    def take(self, count: int) -> list[Piece]:
        """Remove a finished message from the front of the buffer.

        Returns the packets its bytes arrived in.
        """
        count = min(count, len(self.pending))
        del self.pending[:count]
        taken: list[Piece] = []
        while count and self.pieces:
            piece = self.pieces.popleft()
            if piece.length > count:
                self.pieces.appendleft(Piece(piece.frame, piece.length - count))
                piece = Piece(piece.frame, count)
            taken.append(piece)
            count -= piece.length
        self.wanted, self.exact, self.to_end = 0, False, False
        return taken

    def wait(
        self, count: int | None = None, *, to_end: bool = False, have: int | None = None
    ) -> None:
        """Leave the buffer alone until the message at the front has grown.

        ``count`` is how many more bytes it needs, beyond the ``have`` that
        were looked at: the whole buffer, unless less of it was shown.
        Without a count, anything more at all is worth another look.
        """
        if have is None:
            have = len(self.pending)
        self.to_end = to_end
        self.exact = count is not None
        self.wanted = have + (1 if count is None else max(count, 1))

    def close(self, position: int) -> None:
        """The stream stops at ``position``: a FIN or a reset said so."""
        if self.end is None:
            self.end = position

    def restart(self, position: int | None = None) -> None:
        """Forget where the stream was up to, and everything waiting.

        A SYN starts the numbering again at ``position``. A segment the
        capture cut short leaves no way to place what follows it, so the next
        segment starts over from wherever it is.
        """
        self.next = position
        self.end = None
        self._abandon()
        self.early.clear()
        self.early_size = 0

    def _append(self, data: bytes, frame: int) -> None:
        assert self.next is not None
        self.pending += data
        self.pieces.append(Piece(frame, len(data)))
        self.next += len(data)
        if self.heard is not None:
            self.heard(data, self._missed)
        self._missed = 0

    def _keep(self, position: int, data: bytes, frame: int) -> Added:
        """Hold a segment that is ahead of a gap."""
        if any(at == position and len(held) >= len(data) for at, _, held in self.early):
            # The same segment again, while the gap before it is still open.
            return Added(early=True)
        insort(self.early, (position, frame, data))
        self.early_size += len(data)
        if self.early_size <= self.limit:
            return Added(early=True)
        # Too much is waiting on bytes that show no sign of coming.
        self._skip(self.early[0][0])
        return Added(fresh=len(self.pending))

    def _skip(self, position: int) -> int:
        """Give up on the bytes before ``position``, and return how many."""
        assert self.next is not None
        lost = max(position - self.next, 0)
        if lost:
            self._abandon()
            self.next = position
            self._missed += lost
        self._close_gaps()
        return lost

    def _abandon(self) -> None:
        """Drop the message at the front, which can no longer be finished."""
        self.pending.clear()
        self.pieces.clear()
        self.wanted, self.exact, self.to_end = 0, False, False

    def _close_gaps(self) -> None:
        """Bring in the held segments that the stream has now reached."""
        assert self.next is not None
        while self.early and self.early[0][0] <= self.next:
            position, frame, data = self.early.pop(0)
            self.early_size -= len(data)
            if position + len(data) > self.next:
                self._append(data[self.next - position :], frame)
