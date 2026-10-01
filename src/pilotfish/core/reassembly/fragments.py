"""A fragmented datagram, put back together.

IP cuts a datagram that is too big for a link into fragments, each saying
where in the whole it belongs and whether more follow. They can arrive in any
order, more than once, or never, and whoever sends them chooses what they
claim. So everything kept here has a bound: a datagram still unfinished after
the timeout is forgotten, and the oldest go first once too much is waiting. A
flood of fragments that never complete costs a fixed amount of memory and no
more.

References: RFC 791 for the fields, RFC 815 for the bookkeeping, RFC 8200 for
what IPv6 changed.
"""

from collections.abc import Hashable
from dataclasses import dataclass, field

MAX_DATAGRAM = 65535
"""The longest datagram a sixteen-bit length can describe. A fragment that
reaches past it is the old "ping of death", and is refused."""

MAX_FRAGMENTS = 2048
"""How many pieces one datagram may come in before it stops being believed.
A real one needs a few dozen."""

TIMEOUT_NS = 30_000_000_000
"""How long a datagram may wait for its missing pieces, as Linux allows."""

LIMIT = 4 * 1024 * 1024
"""How many bytes all the unfinished datagrams may hold between them."""

MOST = 1024
"""How many datagrams may be unfinished at once."""


@dataclass(frozen=True, slots=True)
class Reassembled:
    """A datagram whose pieces have all arrived."""

    data: bytes
    frames: tuple[int, ...]
    """The packet each fragment came in, in the order they arrived."""
    overlap: bool = False
    """Whether two fragments covered the same bytes."""
    conflict: bool = False
    """Whether they disagreed about them, which no honest sender's do."""


@dataclass(slots=True)
class _Datagram:
    started: int | None
    data: bytearray = field(default_factory=bytearray)
    have: list[tuple[int, int]] = field(default_factory=list)
    """The runs of bytes that have arrived, in order, none touching the next."""
    length: int | None = None
    """How long the whole is, which only the last fragment says."""
    frames: list[int] = field(default_factory=list)
    overlap: bool = False
    conflict: bool = False

    @property
    def complete(self) -> bool:
        if self.length is None:
            return False
        return self.length == 0 or self.have == [(0, self.length)]


class Fragments:
    """The datagrams of one capture that are still missing pieces."""

    def __init__(self, *, timeout: int = TIMEOUT_NS, limit: int = LIMIT, most: int = MOST) -> None:
        self._timeout = timeout
        self._limit = limit
        self._most = most
        # Oldest first, which is the order a dict keeps.
        self._waiting: dict[Hashable, _Datagram] = {}
        self._buffered = 0

    def __len__(self) -> int:
        """How many datagrams are waiting for the rest of themselves."""
        return len(self._waiting)

    @property
    def buffered(self) -> int:
        """How many bytes they hold between them."""
        return self._buffered

    def add(
        self,
        key: Hashable,
        offset: int,
        data: bytes,
        *,
        more: bool,
        frame: int,
        time: int | None = None,
    ) -> Reassembled | None:
        """Add one fragment, and return the datagram if that completes it.

        ``key`` is whatever tells one datagram's fragments from another's:
        the addresses and the identification field. ``offset`` is where the
        fragment's bytes go, ``more`` whether others follow it, and ``time``
        when it was captured, which is what the timeout is measured against.
        """
        self._expire(time)
        end = offset + len(data)
        if end > MAX_DATAGRAM:
            return None
        datagram = self._waiting.get(key)
        if datagram is None:
            datagram = self._waiting[key] = _Datagram(started=time)
        datagram.frames.append(frame)
        if len(datagram.frames) > MAX_FRAGMENTS:
            self._forget(key)
            return None
        if not more:
            if datagram.length is None:
                datagram.length = end
                if len(datagram.data) > end:
                    # Bytes have already arrived for past where this says the
                    # datagram ends. They can't both be right.
                    datagram.conflict = True
                    datagram.have = [
                        (low, min(high, end)) for low, high in datagram.have if low < end
                    ]
            elif datagram.length != end:
                # Two fragments both claiming to be the last, at different
                # places. The first one said is the one believed.
                datagram.conflict = True
        if datagram.length is not None and end > datagram.length:
            datagram.conflict = True
            data = data[: max(datagram.length - offset, 0)]
            end = offset + len(data)
        grown = end - len(datagram.data)
        if grown > 0:
            datagram.data.extend(bytes(grown))
            self._buffered += grown
        self._place(datagram, offset, data)
        if datagram.complete:
            del self._waiting[key]
            self._buffered -= len(datagram.data)
            assert datagram.length is not None
            return Reassembled(
                bytes(datagram.data[: datagram.length]),
                tuple(datagram.frames),
                datagram.overlap,
                datagram.conflict,
            )
        self._make_room(key)
        return None

    @staticmethod
    def _place(datagram: _Datagram, offset: int, data: bytes) -> None:
        """Write a fragment's bytes where they belong.

        Bytes that have already arrived are left as they were, so a fragment
        sent to overwrite an earlier one changes nothing. That it tried is
        recorded: overlapping fragments that disagree are how a packet is
        made to look harmless to a filter and not to the host behind it.
        """
        if not data:
            return
        end = offset + len(data)
        cursor = offset
        for start, stop in datagram.have:
            if stop <= cursor or start >= end:
                continue
            datagram.overlap = True
            low, high = max(start, offset), min(stop, end)
            if datagram.data[low:high] != data[low - offset : high - offset]:
                datagram.conflict = True
            if start > cursor:
                datagram.data[cursor:start] = data[cursor - offset : start - offset]
            cursor = max(cursor, stop)
        if cursor < end:
            datagram.data[cursor:end] = data[cursor - offset :]
        datagram.have = _joined(datagram.have, offset, end)

    def _expire(self, now: int | None) -> None:
        """Forget the datagrams that have waited too long for their pieces."""
        if now is None:
            return
        while self._waiting:
            key, oldest = next(iter(self._waiting.items()))
            if oldest.started is None or now - oldest.started <= self._timeout:
                return
            self._forget(key)

    def _make_room(self, keep: Hashable) -> None:
        """Forget the oldest datagrams until what is left fits the limits."""
        while len(self._waiting) > 1 and (
            self._buffered > self._limit or len(self._waiting) > self._most
        ):
            key = next(each for each in self._waiting if each != keep)
            self._forget(key)

    def _forget(self, key: Hashable) -> None:
        self._buffered -= len(self._waiting.pop(key).data)


def _joined(runs: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    """The runs with one more added, and any that now touch made into one."""
    joined: list[tuple[int, int]] = []
    for low, high in sorted([*runs, (start, end)]):
        if joined and low <= joined[-1][1]:
            joined[-1] = (joined[-1][0], max(joined[-1][1], high))
        else:
            joined.append((low, high))
    return joined
