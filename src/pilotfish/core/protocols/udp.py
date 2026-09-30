"""UDP: two ports, a length, and a checksum over a pseudo header.

Reference: RFC 768, and RFC 8200 for what IPv6 changed about the checksum.
"""

from pilotfish.core.dissect import (
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    MalformedError,
    Reader,
    register,
)
from pilotfish.core.protocols.checksum import (
    ChecksumStatus,
    offloaded,
    pseudo_header,
    verify,
)
from pilotfish.core.protocols.conversations import Conversations, Counter
from pilotfish.core.protocols.ip import IP_PROTO, PROTO_UDP

UDP_PORT = "udp.port"
"""The table keyed by port, for what a datagram carries."""

HEURISTICS = "udp"
"""Dissectors to ask about a payload no port claimed."""

HEADER_SIZE = 8


@register(IP_PROTO, PROTO_UDP)
class Udp(Dissector):
    name = "udp"
    title = "User Datagram Protocol"
    fields = (
        Field("udp.srcport", FieldType.UINT, "Source Port"),
        Field("udp.dstport", FieldType.UINT, "Destination Port"),
        Field("udp.length", FieldType.UINT, "Length"),
        Field("udp.checksum", FieldType.UINT, "Checksum", hex=True),
        Field("udp.checksum.status", FieldType.UINT, "Checksum status"),
        Field("udp.stream", FieldType.UINT, "Stream index"),
        Field("udp.payload", FieldType.BYTES, "Payload"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        datagram = reader.buffer.peek(reader.remaining)
        source_port = reader.uint16("udp.srcport")
        destination_port = reader.uint16("udp.dstport")
        context.source_port, context.destination_port = source_port, destination_port
        length = reader.uint16("udp.length")
        checksum = reader.uint16("udp.checksum")
        with reader.inside():
            reader.add(
                "udp.checksum.status", int(self._status(context, datagram, length, checksum))
            )
        if length < HEADER_SIZE:
            raise MalformedError(f"a length of {length} is shorter than UDP's header")

        conversations = context.session.store(self.name, lambda: Conversations(Counter))
        conversation, _ = conversations.find(
            (context.source or "", source_port), (context.destination or "", destination_port)
        )
        conversation.state.packets += 1
        reader.add("udp.stream", conversation.index)

        reader.summarize(
            f"User Datagram Protocol, Src Port: {source_port}, Dst Port: {destination_port}"
        )
        context.describe(f"{source_port} → {destination_port} Len={length - HEADER_SIZE}")
        payload = reader.payload(length - HEADER_SIZE)
        if not payload.remaining:
            return None
        reader.add(
            "udp.payload",
            payload.peek(payload.remaining),
            offset=payload.offset,
            length=payload.remaining,
        )
        return Handoff(
            UDP_PORT,
            min(source_port, destination_port),
            payload,
            also=(max(source_port, destination_port),),
            heuristics=HEURISTICS,
        )

    @staticmethod
    def _status(context: Context, datagram: bytes, length: int, checksum: int) -> ChecksumStatus:
        """Whether the checksum adds up, over the pseudo header as well.

        Over IPv4 a datagram may leave the checksum out altogether, which it
        says by sending zero. Over IPv6 it has to be there.
        """
        if checksum == 0:
            return ChecksumStatus.NOT_PRESENT
        if context.truncated or length > len(datagram):
            # A datagram quoted inside an ICMP error is usually cut off after
            # its header, and then the checksum has nothing to add up over.
            return ChecksumStatus.UNVERIFIED
        if context.source is None or context.destination is None:
            return ChecksumStatus.UNVERIFIED
        pseudo = pseudo_header(context.source, context.destination, PROTO_UDP, len(datagram))
        status = verify(pseudo, datagram)
        if status is ChecksumStatus.BAD and offloaded(pseudo, checksum):
            return ChecksumStatus.GOOD
        return status
