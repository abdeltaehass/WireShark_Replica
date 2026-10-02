"""Ethernet II, and the 802.1Q VLAN tag that can sit inside it.

macOS hands wireless traffic over as Ethernet as well: the Wi-Fi card strips
the 802.11 header, so a capture on en0 decodes the same way as a wired one.

References: IEEE 802.3 for the frame, IEEE 802.1Q for the tag.
"""

from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    Reader,
    register,
)

ETHERTYPE = "ethertype"
"""The table that says what an Ethernet frame is carrying."""

LINKTYPE_ETHERNET = 1

MAX_802_3_LENGTH = 1500
"""A type field no larger than this is an 802.3 length instead."""

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_VLAN_STACKED = (0x88A8, 0x9100)
"""Outer tags of a frame carrying more than one VLAN tag."""


@register(LINK_TYPE, LINKTYPE_ETHERNET)
class Ethernet(Dissector):
    """Two addresses and a type, in fourteen bytes."""

    name = "eth"
    title = "Ethernet II"
    fields = (
        Field("eth.dst", FieldType.ETHERNET, "Destination"),
        Field("eth.src", FieldType.ETHERNET, "Source"),
        Field("eth.addr", FieldType.ETHERNET, "Address", either=("eth.src", "eth.dst")),
        Field("eth.type", FieldType.UINT, "Type", hex=True),
        Field("eth.len", FieldType.UINT, "Length"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        destination = reader.mac("eth.dst")
        source = reader.mac("eth.src")
        reader.summarize(f"Ethernet II, Src: {source}, Dst: {destination}")
        offset = reader.buffer.offset
        value = reader.buffer.uint(2, name="eth.type")
        if value > MAX_802_3_LENGTH:
            reader.add("eth.type", value, offset=offset, length=2)
            return Handoff(ETHERTYPE, value, reader.payload())
        # An 802.3 frame: the field is how long the payload is, and an LLC
        # header follows, which pilotfish doesn't decode. No EtherType is
        # registered this low, so the payload shows as data.
        reader.add("eth.len", value, offset=offset, length=2)
        return Handoff(ETHERTYPE, value, reader.payload(value))


@register(ETHERTYPE, ETHERTYPE_VLAN, *ETHERTYPE_VLAN_STACKED)
class Vlan(Dissector):
    """A four-byte tag: which VLAN the frame belongs to, and its priority."""

    name = "vlan"
    title = "802.1Q Virtual LAN"
    fields = (
        Field("vlan.priority", FieldType.UINT, "Priority"),
        Field("vlan.dei", FieldType.BOOL, "DEI"),
        Field("vlan.id", FieldType.UINT, "ID"),
        Field("vlan.etype", FieldType.UINT, "Type", hex=True),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        offset = reader.buffer.offset
        control = reader.buffer.uint(2, name="vlan.id")
        priority = control >> 13
        drop_eligible = bool(control & 0x1000)
        identifier = control & 0x0FFF
        reader.add("vlan.priority", priority, offset=offset, length=2)
        reader.add("vlan.dei", drop_eligible, offset=offset, length=2)
        reader.add("vlan.id", identifier, offset=offset, length=2)
        ethertype = reader.uint16("vlan.etype")
        reader.summarize(
            f"802.1Q Virtual LAN, PRI: {priority}, DEI: {int(drop_eligible)}, ID: {identifier}"
        )
        return Handoff(ETHERTYPE, ethertype, reader.payload())
