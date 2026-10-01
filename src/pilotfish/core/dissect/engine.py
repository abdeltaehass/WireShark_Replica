"""Turning a captured packet into its protocol tree."""

from pilotfish.core.dissect.buffer import Buffer
from pilotfish.core.dissect.dissector import (
    LINK_TYPE,
    REGISTRY,
    Context,
    Dissector,
    Handoff,
    Registry,
    Stream,
)
from pilotfish.core.dissect.errors import DeclinedError, MalformedError, NeedMoreError
from pilotfish.core.dissect.fields import Field, FieldType
from pilotfish.core.dissect.reader import Reader
from pilotfish.core.dissect.session import Session
from pilotfish.core.dissect.tree import ProtocolTree
from pilotfish.core.packet import Packet

MAX_LAYERS = 32
"""How deep decoding goes before giving up, in case protocols route in a circle."""


class Frame(Dissector):
    """What the capture itself says about a packet, rather than the packet.

    This is the root of every tree, as it is in Wireshark, and hands the
    bytes to whichever dissector decodes the capture's link type.
    """

    name = "frame"
    title = "Frame"
    fields = (
        Field("frame.number", FieldType.UINT, "Frame number"),
        Field("frame.len", FieldType.UINT, "Frame length"),
        Field("frame.cap_len", FieldType.UINT, "Capture length"),
        Field("frame.time_epoch", FieldType.TIME, "Epoch arrival time"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        packet = context.packet
        # These come from the capture rather than from bytes in the packet,
        # so they have no bytes of their own.
        reader.add("frame.number", context.number)
        reader.add("frame.len", packet.original_length)
        reader.add("frame.cap_len", packet.captured_length)
        if packet.timestamp_ns is not None:
            reader.add("frame.time_epoch", packet.timestamp_ns)
        reader.summarize(
            f"Frame {context.number}: {packet.original_length} bytes on wire, "
            f"{packet.captured_length} bytes captured"
        )
        reader.set_length(packet.captured_length)
        return Handoff(LINK_TYPE, packet.link_type, reader.payload())


class Data(Dissector):
    """Bytes no dissector claimed."""

    name = "data"
    title = "Data"
    fields = (
        Field("data.data", FieldType.BYTES, "Data"),
        Field("data.len", FieldType.UINT, "Length"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        count = reader.remaining
        reader.bytes("data.data", count)
        reader.add("data.len", count)
        reader.summarize(f"Data ({count} bytes)")
        return None


DATA_TABLE = "data"
"""The table :func:`as_data` routes through, so a dissector that knows it
can't decode what's left can still hand it over as data."""

REGISTRY.add(Frame)
REGISTRY.add(Data, DATA_TABLE, (0,))


def as_data(payload: Buffer) -> Handoff:
    """Hand the rest over as data, undecoded."""
    return Handoff(DATA_TABLE, 0, payload)


def dissect(
    packet: Packet,
    number: int = 1,
    registry: Registry = REGISTRY,
    session: Session | None = None,
) -> ProtocolTree:
    """Decode one packet, layer by layer, into a tree of fields.

    A packet that doesn't hold what its headers claim doesn't raise: decoding
    stops where the bytes ran out, the tree keeps every field read up to
    there, and ``tree.error`` says what happened.

    Pass the same ``session`` for every packet of a capture, in the order
    they were captured, and the dissectors that follow connections can see
    what came before. That is also what puts a message split across packets
    back together: it is decoded in the packet that completes it.
    """
    tree = ProtocolTree()
    context = Context(packet=packet, number=number, session=session or Session())
    registry.add(Data, DATA_TABLE, (0,))
    dissector: Dissector | None = registry.add(Frame)
    payload = Buffer(packet.data)
    stream: Stream | None = None
    # A segment can hold several messages. The ones behind the message being
    # decoded wait here until the layers inside it are done.
    later: list[tuple[Dissector, Buffer, Stream]] = []
    while dissector is not None:
        reader = Reader(dissector.protocol, payload, registry.fields)
        quoted = context.in_error
        offered = payload.remaining
        context.can_wait = stream is not None and stream.open
        try:
            handoff = dissector.dissect(reader, context)
        except DeclinedError:
            # Not this protocol after all, so it never was a layer, and the
            # bytes stay data.
            dissector = registry.add(Data)
            continue
        except NeedMoreError as more:
            if stream is None or not context.can_wait:
                # There is nowhere for more to come from, so what is here is
                # all there will ever be.
                dissector = registry.add(Data)
                continue
            again = stream.held(more)
            if again is not None and (again.remaining > offered or not stream.open):
                # Either more of the message had already arrived than the
                # dissector was shown, or the stream can't keep it and the
                # dissector has to make do with what there is.
                payload = again
                continue
            if not later:
                break
            dissector, payload, stream = later.pop()
            context.keep()
            continue
        except MalformedError as error:
            # A packet quoted inside an error message is only its first bytes,
            # so running out of them is the format working as intended, not a
            # packet that doesn't hold what it claims.
            if not quoted:
                tree.error = f"{dissector.name}: {error}"
            _add_layer(tree, reader, payload, dissector, quoted)
            if stream is not None:
                # Kept, the same bytes would come back with every segment
                # that follows and spoil each of them in turn.
                stream.taken(offered)
            break
        _add_layer(tree, reader, payload, dissector, quoted)
        if stream is not None:
            # A dissector that read nothing can't be offered the same bytes
            # again, so they count as read.
            rest = stream.taken(offered - payload.remaining or offered)
            if rest is not None:
                later.append((dissector, rest, stream))
        if handoff is not None and handoff.payload.remaining:
            if len(tree.layers) >= MAX_LAYERS:
                tree.error = f"stopped after {MAX_LAYERS} layers"
                break
            dissector = handoff.dissector or _route(handoff, registry, context)
            dissector = dissector or registry.add(Data)
            payload, stream = handoff.payload, handoff.stream
            continue
        # Nothing is left inside this message, so on to the next one. What
        # doesn't fit under the limit stays in its stream for the next packet.
        if not later or len(tree.layers) >= MAX_LAYERS:
            break
        dissector, payload, stream = later.pop()
        context.keep()
    tree.info = context.info or _summary(tree)
    return tree


def _add_layer(
    tree: ProtocolTree, reader: Reader, payload: Buffer, dissector: Dissector, quoted: bool
) -> None:
    """Add a finished layer, and the reassembled bytes it was read from."""
    tree.layers.append(reader.node())
    if payload.source is not None and payload.source not in tree.sources:
        tree.sources.append(payload.source)
    _name_protocol(tree, dissector, quoted)


def _route(handoff: Handoff, registry: Registry, context: Context) -> Dissector | None:
    """The dissector for a handoff: by value, else by asking the heuristics.

    A transport protocol hands over both of its ports, lower one first, which
    is the order Wireshark tries them in, so a well-known port wins over the
    ephemeral one at the other end.
    """
    for key in (handoff.key, *handoff.also):
        found = registry.find(handoff.table, key)
        if found is not None:
            return found
    if not handoff.heuristics:
        return None
    return registry.guess(handoff.heuristics, handoff.payload, context)


def _name_protocol(tree: ProtocolTree, dissector: Dissector, quoted: bool) -> None:
    """Name the packet after this layer, unless it is inside an error message."""
    if not quoted and dissector.name not in {Frame.name, Data.name}:
        tree.protocol = dissector.name


def _summary(tree: ProtocolTree) -> str:
    """What the packet list shows when no dissector had anything better to say."""
    if not tree.layers:
        return ""
    innermost = tree.layers[-1]
    return innermost.summary or innermost.label
