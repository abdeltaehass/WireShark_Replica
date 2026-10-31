"""Decoding a capture file's packets on demand, in any order.

A packet can't be decoded on its own. Whether a segment is a retransmission,
which stream it belongs to, and what message it completes all depend on the
packets before it, which the dissectors remember in a :class:`Session`.
Wireshark deals with this by decoding every packet once, in order, as the
file opens, and saving what each dissector worked out for each packet so it
can be decoded again later on its own.

The :class:`Decoder` decodes in order as well, but only as far as it has been
asked to: the furthest row the packet list has shown. As it goes it keeps
two things and lets the trees go:

- each packet's summary, the columns of the packet list, in a cache of
  bounded size;
- every so often, a checkpoint: the session pickled as it stood before a
  packet.

A packet behind that point which is no longer at hand, a summary let go or
the full tree of a packet clicked on, is decoded again from the checkpoint
before it. That gives the very tree the first pass gave, because a packet's
tree depends only on the packet and the session it was decoded with.
"""

import bisect
import pickle
import time
from collections import OrderedDict
from dataclasses import dataclass, replace

from pilotfish.core.columns import addresses, protocol, summary
from pilotfish.core.dissect import REGISTRY, ProtocolTree, Registry, Session, dissect
from pilotfish.core.formats.index import PacketIndex
from pilotfish.core.packet import Packet

CHECKPOINT_SPACING = 1_000
"""Packets between checkpoints to begin with: decoding again from one costs
at most this many packets, about 60 ms."""
MAX_CHECKPOINTS = 256
"""Checkpoints kept at most. Past this, every other one is dropped and the
spacing doubles, so a capture of any length costs a fixed number of them."""
CHECKPOINT_BYTES = 256 * 1024 * 1024
"""Bytes of checkpoints kept at most. A capture of many connections makes a
large session, and past this every other checkpoint goes the same way."""
SUMMARIES_KEPT = 100_000
"""Summaries kept at most, the most recently used."""
TREES_KEPT = 16
"""Full trees kept at most, the most recently asked for."""


@dataclass(frozen=True, slots=True)
class Summary:
    """The packet list's columns that come from decoding the packet."""

    source: str
    destination: str
    protocol: str
    info: str
    malformed: bool

    @classmethod
    def of(cls, tree: ProtocolTree) -> "Summary":
        source, destination = addresses(tree)
        return cls(
            source=source,
            destination=destination,
            protocol=protocol(tree),
            info=summary(tree),
            malformed=tree.error is not None,
        )


class Decoder:
    """The packets of an index, decoded as they are asked for."""

    def __init__(
        self,
        index: PacketIndex,
        *,
        registry: Registry = REGISTRY,
        spacing: int = CHECKPOINT_SPACING,
        checkpoints: int = MAX_CHECKPOINTS,
        checkpoint_bytes: int = CHECKPOINT_BYTES,
        summaries: int = SUMMARIES_KEPT,
        trees: int = TREES_KEPT,
    ) -> None:
        self.index = index
        self._registry = registry
        self._spacing = spacing
        self._max_checkpoints = max(checkpoints, 1)
        self._max_checkpoint_bytes = checkpoint_bytes
        self._checkpoint_bytes = 0
        self._max_summaries = summaries
        self._max_trees = trees
        self._session = Session()
        self._decoded = 0
        self._checkpoints: dict[int, bytes] = {}
        self._checkpoint_rows: list[int] = []
        self._summaries: OrderedDict[int, Summary] = OrderedDict()
        self._trees: OrderedDict[int, ProtocolTree] = OrderedDict()

    def __len__(self) -> int:
        return len(self.index)

    @property
    def decoded(self) -> int:
        """How many packets, from the first, have been decoded in order."""
        return self._decoded

    @property
    def checkpoints(self) -> tuple[int, ...]:
        """The rows a checkpoint was taken before."""
        return tuple(self._checkpoint_rows)

    def packet(self, row: int) -> Packet:
        """The packet in this row, as the file holds it."""
        return self.index[row]

    def summary(self, row: int) -> Summary | None:
        """The columns for this row, or ``None`` if decoding hasn't got there.

        This never decodes ahead, since the packets before the row would have
        to come first: that is :meth:`advance`'s job. A row behind that point
        whose summary was let go is decoded again, along with the rest of its
        stretch between checkpoints, which is what a screenful needs next.
        """
        cached = self._summaries.get(row)
        if cached is not None:
            self._summaries.move_to_end(row)
            return cached
        if not 0 <= row < self._decoded:
            return None
        start, stop = self._stretch(row)
        return self._replay(start, stop, row)[0]

    def advance(self, until: int, deadline: float | None = None) -> int:
        """Decode in order up to and including row ``until``.

        Stops early once ``deadline``, a :func:`time.monotonic` time, has
        passed, so a front end can decode a little at a time between
        repaints. Returns how many packets are decoded now.
        """
        last = min(until, len(self) - 1)
        while self._decoded <= last:
            self._step()
            if deadline is not None and time.monotonic() >= deadline:
                break
        return self._decoded

    def tree(self, row: int) -> ProtocolTree:
        """The full protocol tree of one packet, as decoding in order gives it."""
        if not 0 <= row < len(self):
            raise IndexError(f"there is no packet {row + 1}; the file has {len(self)}")
        cached = self._trees.get(row)
        if cached is not None:
            self._trees.move_to_end(row)
            return cached
        if row >= self._decoded:
            self.advance(row - 1)
            tree = self._step()
        else:
            start, _ = self._stretch(row)
            tree = self._replay(start, row + 1, row)[1]
        self._keep_tree(row, tree)
        return tree

    def _step(self) -> ProtocolTree:
        """Decode the next packet in order with the session."""
        row = self._decoded
        # Always at a multiple of the spacing, so that thinning them out
        # leaves them evenly spaced.
        if row % self._spacing == 0:
            self._checkpoint(row)
        tree = self._decode(row, self._session)
        self._keep_summary(row, Summary.of(tree))
        self._decoded += 1
        return tree

    def _decode(self, row: int, session: Session) -> ProtocolTree:
        # A copy of the bytes rather than a view into the file, so that
        # nothing a dissector keeps in the session stops it being pickled.
        packet = self.index[row]
        packet = replace(packet, data=bytes(packet.data))
        return dissect(packet, row + 1, self._registry, session)

    def _checkpoint(self, row: int) -> None:
        try:
            saved = pickle.dumps(self._session, protocol=pickle.HIGHEST_PROTOCOL)
        except (pickle.PicklingError, TypeError, AttributeError):
            # Something in the session can't be saved. Decoding again then
            # starts from an earlier checkpoint, which is slower but the same.
            return
        self._checkpoints[row] = saved
        self._checkpoint_rows.append(row)
        self._checkpoint_bytes += len(saved)
        while len(self._checkpoint_rows) > 1 and (
            len(self._checkpoint_rows) > self._max_checkpoints
            or self._checkpoint_bytes > self._max_checkpoint_bytes
        ):
            self._thin()

    def _thin(self) -> None:
        """Drop every other checkpoint and take them half as often from now on.

        The first one, before any packet, always stays, so there is always
        somewhere to decode again from.
        """
        self._spacing *= 2
        kept = [row for row in self._checkpoint_rows if row % self._spacing == 0]
        for dropped in set(self._checkpoint_rows) - set(kept):
            self._checkpoint_bytes -= len(self._checkpoints.pop(dropped))
        self._checkpoint_rows = kept

    def _stretch(self, row: int) -> tuple[int, int]:
        """The checkpoint before ``row``, and where the next one or the decoded part ends."""
        found = bisect.bisect_right(self._checkpoint_rows, row)
        start = self._checkpoint_rows[found - 1]
        stop = self._checkpoint_rows[found] if found < len(self._checkpoint_rows) else self._decoded
        return start, stop

    def _replay(self, start: int, stop: int, row: int) -> tuple[Summary, ProtocolTree]:
        """Decode rows ``start`` to ``stop`` again from the checkpoint at
        ``start``, keeping their summaries, and return ``row``'s."""
        session: Session = pickle.loads(self._checkpoints[start])
        found: tuple[Summary, ProtocolTree] | None = None
        for again in range(start, stop):
            tree = self._decode(again, session)
            decoded = Summary.of(tree)
            self._keep_summary(again, decoded)
            if again == row:
                found = decoded, tree
        if found is None:
            raise IndexError(f"row {row} isn't between rows {start} and {stop}")
        return found

    def _keep_summary(self, row: int, decoded: Summary) -> None:
        self._summaries[row] = decoded
        self._summaries.move_to_end(row)
        while len(self._summaries) > self._max_summaries:
            self._summaries.popitem(last=False)

    def _keep_tree(self, row: int, tree: ProtocolTree) -> None:
        self._trees[row] = tree
        while len(self._trees) > self._max_trees:
            self._trees.popitem(last=False)
