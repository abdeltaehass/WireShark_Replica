"""Turning a captured packet into its protocol tree."""

from pilotfish.core.dissect.buffer import Buffer
from pilotfish.core.dissect.dissector import (
    LINK_TYPE,
    REGISTRY,
    Context,
    Dissector,
    Handoff,
    Registry,
)
from pilotfish.core.dissect.errors import MalformedError
from pilotfish.core.dissect.fields import Field, FieldType
from pilotfish.core.dissect.reader import Reader
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


def dissect(packet: Packet, number: int = 1, registry: Registry = REGISTRY) -> ProtocolTree:
    """Decode one packet, layer by layer, into a tree of fields.

    A packet that doesn't hold what its headers claim doesn't raise: decoding
    stops where the bytes ran out, the tree keeps every field read up to
    there, and ``tree.error`` says what happened.
    """
    tree = ProtocolTree()
    context = Context(packet=packet, number=number)
    registry.add(Data, DATA_TABLE, (0,))
    dissector: Dissector | None = registry.add(Frame)
    payload = Buffer(packet.data)
    while dissector is not None:
        reader = Reader(dissector.protocol, payload, registry.fields)
        quoted = context.in_error
        try:
            handoff = dissector.dissect(reader, context)
        except MalformedError as error:
            tree.error = f"{dissector.name}: {error}"
            tree.layers.append(reader.node())
            _name_protocol(tree, dissector, quoted)
            break
        tree.layers.append(reader.node())
        _name_protocol(tree, dissector, quoted)
        if handoff is None or handoff.payload.remaining == 0:
            break
        if len(tree.layers) >= MAX_LAYERS:
            tree.error = f"stopped after {MAX_LAYERS} layers"
            break
        dissector = registry.find(handoff.table, handoff.key) or registry.add(Data)
        payload = handoff.payload
    tree.info = context.info or _summary(tree)
    return tree


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
