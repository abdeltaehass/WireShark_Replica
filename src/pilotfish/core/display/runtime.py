"""What a filter needs while it runs, whichever way it is run.

The tree walker and the generated code both call these, so the two can only
differ in how they get from one operation to the next, which is the thing
being compared when they are timed against each other.
"""

from collections.abc import Iterable

from pilotfish.core.dissect import Node, ProtocolTree

type Found = dict[str, list[Node]]
"""The nodes of one packet's tree, by field name, for the names a filter reads."""

type Ranges = tuple[tuple[int, int | None], ...]


def gather(tree: ProtocolTree, names: frozenset[str]) -> Found:
    """Find every node a filter could ask about, in one pass over the tree.

    A filter can name the same field several times, and walking the tree once
    per mention would cost far more than evaluating the filter does. Every
    name has an entry, empty for a field the packet doesn't have.
    """
    found: Found = {name: [] for name in names}
    nodes = list(tree.layers)
    # The list grows as it is read, each node adding its children to the end,
    # so the loop reaches the whole tree without recursing into it.
    for node in nodes:
        wanted = found.get(node.name)
        if wanted is not None:
            wanted.append(node)
        if node.children:
            nodes.extend(node.children)
    return found


def layer(node: Node, data: bytes | memoryview) -> bytes:
    """A protocol's bytes: from the first of its header to the end of the
    packet, or of the reassembled message it was decoded from."""
    whole = data if node.source is None else node.source.data
    return bytes(whole[node.offset :])


def mac(address: str) -> bytes:
    """The six bytes of an Ethernet address written ``00:1a:2b:3c:4d:5e``."""
    return bytes.fromhex(address.replace(":", ""))


def cut(value: bytes, ranges: Ranges) -> tuple[bytes, ...]:
    """What a slice takes out of ``value``: one run of bytes, or nothing.

    A slice that reaches outside the value gives nothing rather than fewer
    bytes, so ``eth.src[10:2]`` matches no packet instead of raising for
    every one of them.
    """
    pieces = []
    for offset, length in ranges:
        start = offset + len(value) if offset < 0 else offset
        end = len(value) if length is None else start + length
        if start < 0 or end > len(value) or start >= end:
            return ()
        pieces.append(value[start:end])
    return (b"".join(pieces),)


def every(results: Iterable[bool]) -> bool:
    """Whether all of ``results`` are true, and there are any.

    The second half is where this parts from :func:`all`: ``ip.addr != x``
    is false of a packet with no addresses at all.
    """
    passed = False
    for result in results:
        if not result:
            return False
        passed = True
    return passed
