"""Putting back together what the network took apart.

A message bigger than one packet travels in pieces, at two layers. IP cuts a
datagram into fragments when a link can't carry it whole, and TCP cuts a
stream of bytes into segments as a matter of course. Either way the pieces
can arrive late, twice or not at all, and only the whole is worth decoding.

Nothing here knows about dissectors: these are the bookkeeping, and the
protocols in :mod:`pilotfish.core.protocols` decide what to feed them.
"""

from pilotfish.core.reassembly.flow import Added, Flow, Piece
from pilotfish.core.reassembly.fragments import Fragments, Reassembled

__all__ = ["Added", "Flow", "Fragments", "Piece", "Reassembled"]
