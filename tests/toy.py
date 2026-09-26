"""A made-up protocol, for testing the framework without a real one.

It uses every kind of field the reader can read, hands off to a second
protocol by value, and has a length field that can lie, which is how the
tests reach the malformed path.
"""

import struct
from ipaddress import IPv4Address

from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    Reader,
    Registry,
    register,
)

TOY_LINK_TYPE = 147
"""LINKTYPE_USER0, which the tcpdump registry leaves for private use."""

NEXT = "toy.next"
"""The table the toy header's last field routes through."""

BODY = 7
"""The ``toy.next`` value the toy body protocol is registered for."""

LOOP = 9
"""A ``toy.next`` value routing back to a protocol that never finishes."""

HEADER_SIZE = 20

REGISTRY = Registry()
"""A registry of its own, so the toys stay out of the real one."""

URGENT = 0x01
LAST = 0x02


@register(LINK_TYPE, TOY_LINK_TYPE, registry=REGISTRY)
class Toy(Dissector):
    """The toy header: a version, flags, a length, addresses and a label."""

    name = "toy"
    title = "Toy Protocol"
    fields = (
        Field("toy.version", FieldType.UINT, "Version"),
        Field("toy.flags", FieldType.UINT, "Flags"),
        Field("toy.flags.urgent", FieldType.BOOL, "Urgent"),
        Field("toy.flags.last", FieldType.BOOL, "Last"),
        Field("toy.length", FieldType.UINT, "Payload length"),
        Field("toy.source", FieldType.IPV4, "Source address"),
        Field("toy.hardware", FieldType.ETHERNET, "Hardware address"),
        Field("toy.next", FieldType.UINT, "Next protocol"),
        Field("toy.label", FieldType.STRING, "Label"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        version = reader.uint8("toy.version")
        flags = reader.uint8("toy.flags")
        with reader.inside():
            reader.add("toy.flags.urgent", bool(flags & URGENT))
            reader.add("toy.flags.last", bool(flags & LAST))
        length = reader.uint16("toy.length")
        reader.ipv4("toy.source")
        reader.mac("toy.hardware")
        next_protocol = reader.uint16("toy.next")
        label = reader.string("toy.label", 4)
        reader.summarize(f"Toy Protocol {version}, label {label}")
        context.info = f"Toy {label}"
        return Handoff(NEXT, next_protocol, reader.payload(length))


@register(NEXT, BODY, registry=REGISTRY)
class ToyBody(Dissector):
    """Whatever the toy header was carrying."""

    name = "toybody"
    title = "Toy Body"
    fields = (Field("toybody.body", FieldType.BYTES, "Body"),)

    def dissect(self, reader: Reader, context: Context) -> None:
        body = reader.bytes("toybody.body", reader.remaining)
        reader.summarize(f"Toy Body ({len(body)} bytes)")
        context.info = f"{context.info}, {len(body)} bytes"
        return None


@register(NEXT, LOOP, registry=REGISTRY)
class ToyLoop(Dissector):
    """Hands what's left back to itself, to prove the engine gives up."""

    name = "toyloop"
    title = "Toy Loop"

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        return Handoff(NEXT, LOOP, reader.payload())


def toy_packet(
    *,
    version: int = 1,
    flags: int = URGENT,
    length: int | None = None,
    source: str = "192.0.2.1",
    hardware: str = "02:00:00:00:00:01",
    next_protocol: int = BODY,
    label: str = "toy1",
    payload: bytes = b"body",
) -> bytes:
    """A toy packet, whose length field can be made to lie."""
    header = struct.pack(
        ">BBH4s6sH4s",
        version,
        flags,
        len(payload) if length is None else length,
        IPv4Address(source).packed,
        bytes.fromhex(hardware.replace(":", "")),
        next_protocol,
        label.encode(),
    )
    return header + payload
