"""Merging several captures into one, in the order their packets were captured.

Each capture file is already in time order, so merging them is the merge
step of a merge sort: :func:`heapq.merge` holds the next packet of each file
and hands out whichever is earliest. Nothing is read ahead, so files of any
size merge in the memory a packet from each takes.
"""

import heapq
from collections.abc import Iterable, Iterator

from pilotfish.core.packet import Packet


def by_time(packet: Packet) -> int:
    """Where a packet goes in time order. One with no time goes first."""
    return packet.timestamp_ns or 0


def merge(captures: Iterable[Iterable[Packet]]) -> Iterator[Packet]:
    """Every packet of every capture, earliest first.

    Packets captured at the same moment keep the order of the captures they
    came from, and their order within each.
    """
    return heapq.merge(*captures, key=by_time)
