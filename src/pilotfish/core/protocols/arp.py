"""The Address Resolution Protocol: which MAC address holds an IP address.

Reference: RFC 826.
"""

from pilotfish.core.dissect import (
    Context,
    Dissector,
    Field,
    FieldType,
    Reader,
    register,
)
from pilotfish.core.protocols.ethernet import ETHERTYPE, ETHERTYPE_ARP, ETHERTYPE_IPV4

HARDWARE_ETHERNET = 1
ETHERNET_ADDRESS_SIZE = 6
IPV4_ADDRESS_SIZE = 4

REQUEST = 1
REPLY = 2
REVERSE_REQUEST = 3
REVERSE_REPLY = 4

_OPCODES = {
    REQUEST: "request",
    REPLY: "reply",
    REVERSE_REQUEST: "reverse request",
    REVERSE_REPLY: "reverse reply",
}


@register(ETHERTYPE, ETHERTYPE_ARP)
class Arp(Dissector):
    name = "arp"
    title = "Address Resolution Protocol"
    fields = (
        Field("arp.hw.type", FieldType.UINT, "Hardware type"),
        Field("arp.proto.type", FieldType.UINT, "Protocol type", hex=True),
        Field("arp.hw.size", FieldType.UINT, "Hardware size"),
        Field("arp.proto.size", FieldType.UINT, "Protocol size"),
        Field("arp.opcode", FieldType.UINT, "Opcode"),
        Field("arp.src.hw_mac", FieldType.ETHERNET, "Sender MAC address"),
        Field("arp.src.proto_ipv4", FieldType.IPV4, "Sender IP address"),
        Field("arp.dst.hw_mac", FieldType.ETHERNET, "Target MAC address"),
        Field("arp.dst.proto_ipv4", FieldType.IPV4, "Target IP address"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        hardware = reader.uint16("arp.hw.type")
        protocol = reader.uint16("arp.proto.type")
        hardware_size = reader.uint8("arp.hw.size")
        protocol_size = reader.uint8("arp.proto.size")
        opcode = reader.uint16("arp.opcode")
        reader.summarize(
            f"Address Resolution Protocol ({_OPCODES.get(opcode, 'opcode ' + str(opcode))})"
        )
        if (hardware, protocol, hardware_size, protocol_size) != (
            HARDWARE_ETHERNET,
            ETHERTYPE_IPV4,
            ETHERNET_ADDRESS_SIZE,
            IPV4_ADDRESS_SIZE,
        ):
            # Addresses of another kind have no fields of their own here.
            return None
        sender_mac = reader.mac("arp.src.hw_mac")
        sender_ip = reader.ipv4("arp.src.proto_ipv4")
        reader.mac("arp.dst.hw_mac")
        target_ip = reader.ipv4("arp.dst.proto_ipv4")
        if opcode == REQUEST:
            context.describe(f"Who has {target_ip}? Tell {sender_ip}")
        elif opcode == REPLY:
            context.describe(f"{sender_ip} is at {sender_mac}")
        else:
            context.describe(f"ARP {_OPCODES.get(opcode, opcode)}")
        # Anything after the addresses is padding the frame out to its
        # minimum size, which belongs to Ethernet rather than to ARP.
        return None
