"""DHCP: how a machine that knows nothing asks for an address.

The header is BOOTP's, from 1985, and everything that makes it DHCP is in
the options after the four magic bytes at the end of it. The exchange is four
messages: the client asks the whole network (Discover), a server offers an
address (Offer), the client asks for that one (Request), and the server
confirms it (ACK).

References: RFC 2131 for the protocol, RFC 2132 for the options.
"""

from pilotfish.core.dissect import (
    Context,
    Dissector,
    Field,
    FieldType,
    MalformedError,
    Reader,
    register,
)
from pilotfish.core.protocols.udp import UDP_PORT

SERVER_PORT = 67
CLIENT_PORT = 68

HEADER_SIZE = 236
"""The fixed part, before the magic cookie and the options."""
COOKIE = b"\x63\x82\x53\x63"
"""What says the options that follow are DHCP's rather than BOOTP's."""

BROADCAST = 0x8000

PAD = 0
END = 255

ETHERNET = 1
"""The hardware type a client identifier gives when it names an address."""

MESSAGES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "ACK",
    6: "NAK",
    7: "Release",
    8: "Inform",
    9: "Force Renew",
    10: "Lease query",
    11: "Lease unassigned",
    12: "Lease unknown",
    13: "Lease active",
}

# The options worth reading out, by the field their value goes in and how it
# is read. Anything else keeps its type, length and bytes and nothing more.
ADDRESSES = {
    1: "dhcp.option.subnet_mask",
    3: "dhcp.option.router",
    6: "dhcp.option.domain_name_server",
    28: "dhcp.option.broadcast_address",
    50: "dhcp.option.requested_ip_address",
    54: "dhcp.option.dhcp_server_id",
}
TIMES = {
    51: "dhcp.option.ip_address_lease_time",
    58: "dhcp.option.renewal_time_value",
    59: "dhcp.option.rebinding_time_value",
}
TEXTS = {
    12: "dhcp.option.hostname",
    15: "dhcp.option.domain_name",
    60: "dhcp.option.vendor_class_id",
    66: "dhcp.option.tftp_server_name",
}


@register(UDP_PORT, SERVER_PORT, CLIENT_PORT)
class Dhcp(Dissector):
    name = "dhcp"
    title = "Dynamic Host Configuration Protocol"
    fields = (
        Field("dhcp.type", FieldType.UINT, "Message type"),
        Field("dhcp.hw.type", FieldType.UINT, "Hardware type", hex=True),
        Field("dhcp.hw.len", FieldType.UINT, "Hardware address length"),
        Field("dhcp.hops", FieldType.UINT, "Hops"),
        Field("dhcp.id", FieldType.UINT, "Transaction ID", hex=True),
        Field("dhcp.secs", FieldType.UINT, "Seconds elapsed"),
        Field("dhcp.flags", FieldType.UINT, "Bootp flags", hex=True),
        Field("dhcp.flags.bc", FieldType.BOOL, "Broadcast flag"),
        Field("dhcp.flags.reserved", FieldType.UINT, "Reserved flags", hex=True),
        Field("dhcp.ip.client", FieldType.IPV4, "Client IP address"),
        Field("dhcp.ip.your", FieldType.IPV4, "Your (client) IP address"),
        Field("dhcp.ip.server", FieldType.IPV4, "Next server IP address"),
        Field("dhcp.ip.relay", FieldType.IPV4, "Relay agent IP address"),
        Field("dhcp.hw.mac_addr", FieldType.ETHERNET, "Client MAC address"),
        Field("dhcp.hw.addr_padding", FieldType.BYTES, "Client hardware address padding"),
        Field("dhcp.server", FieldType.STRING, "Server host name"),
        Field("dhcp.file", FieldType.STRING, "Boot file name"),
        Field("dhcp.cookie", FieldType.IPV4, "Magic cookie"),
        Field("dhcp.option.type", FieldType.UINT, "Option"),
        Field("dhcp.option.length", FieldType.UINT, "Length"),
        Field("dhcp.option.value", FieldType.BYTES, "Value"),
        Field("dhcp.option.end", FieldType.UINT, "Option End"),
        Field("dhcp.option.padding", FieldType.BYTES, "Padding"),
        Field("dhcp.option.dhcp", FieldType.UINT, "DHCP"),
        Field("dhcp.option.subnet_mask", FieldType.IPV4, "Subnet Mask"),
        Field("dhcp.option.router", FieldType.IPV4, "Router"),
        Field("dhcp.option.domain_name_server", FieldType.IPV4, "Domain Name Server"),
        Field("dhcp.option.broadcast_address", FieldType.IPV4, "Broadcast Address"),
        Field("dhcp.option.requested_ip_address", FieldType.IPV4, "Requested IP Address"),
        Field("dhcp.option.dhcp_server_id", FieldType.IPV4, "DHCP Server Identifier"),
        Field("dhcp.option.ip_address_lease_time", FieldType.UINT, "IP Address Lease Time"),
        Field("dhcp.option.renewal_time_value", FieldType.UINT, "Renewal Time Value"),
        Field("dhcp.option.rebinding_time_value", FieldType.UINT, "Rebinding Time Value"),
        Field("dhcp.option.request_list_item", FieldType.UINT, "Parameter Request List Item"),
        Field("dhcp.option.hostname", FieldType.STRING, "Host Name"),
        Field("dhcp.option.domain_name", FieldType.STRING, "Domain Name"),
        Field("dhcp.option.vendor_class_id", FieldType.STRING, "Vendor class identifier"),
        Field("dhcp.option.tftp_server_name", FieldType.STRING, "TFTP Server Name"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        reader.uint8("dhcp.type")
        reader.uint8("dhcp.hw.type")
        length = reader.uint8("dhcp.hw.len")
        reader.uint8("dhcp.hops")
        identifier = reader.uint32("dhcp.id")
        reader.uint16("dhcp.secs")
        offset = reader.buffer.offset
        flags = reader.uint16("dhcp.flags")
        with reader.inside():
            reader.add("dhcp.flags.bc", bool(flags & BROADCAST), offset=offset, length=2)
            reader.add("dhcp.flags.reserved", flags & ~BROADCAST, offset=offset, length=2)
        for name in ("dhcp.ip.client", "dhcp.ip.your", "dhcp.ip.server", "dhcp.ip.relay"):
            reader.ipv4(name)
        self._hardware(reader, length)
        self._text(reader, "dhcp.server", 64)
        self._text(reader, "dhcp.file", 128)

        kind = 0
        if reader.remaining >= len(COOKIE):
            cookie = reader.buffer.peek(len(COOKIE))
            if cookie == COOKIE:
                reader.ipv4("dhcp.cookie")
                kind = self._options(reader)
        said = MESSAGES.get(kind, f"Unknown ({kind})")
        reader.summarize(f"{self.title} ({said})")
        context.describe(f"DHCP {said:<8} - Transaction ID {identifier:#x}")
        return None

    @staticmethod
    def _text(reader: Reader, name: str, size: int) -> None:
        """A name in a field of fixed size, which is filled out with zeroes."""
        offset = reader.buffer.offset
        raw = reader.buffer.read(size, name)
        reader.add(
            name,
            bytes(raw).split(b"\x00")[0].decode("ascii", "replace"),
            offset=offset,
            length=size,
        )

    @staticmethod
    def _hardware(reader: Reader, length: int) -> None:
        """The client's address, in a field with room for sixteen bytes of it."""
        if length == 6:
            reader.mac("dhcp.hw.mac_addr")
            reader.bytes("dhcp.hw.addr_padding", 10)
            return
        reader.bytes("dhcp.hw.addr_padding", 16)

    def _options(self, reader: Reader) -> int:
        """Everything after the cookie, and the message type it says this is."""
        kind = 0
        while reader.remaining:
            offset = reader.buffer.offset
            option = reader.buffer.uint(1, name="dhcp.option.type")
            # Padding and the end of the list are options with no length and
            # no value. Wireshark gives both of them a type of zero, whatever
            # the byte said, and hangs what they are underneath.
            if option == PAD:
                run = 1
                while run < reader.remaining and reader.buffer.peek(run + 1)[run] == PAD:
                    run += 1
                reader.add("dhcp.option.type", 0, offset=offset, length=1)
                with reader.inside():
                    reader.bytes("dhcp.option.padding", run)
                continue
            if option == END:
                reader.add("dhcp.option.type", 0, offset=offset, length=1)
                with reader.inside():
                    reader.add("dhcp.option.end", option, offset=offset, length=1)
                self._padding(reader)
                return kind
            reader.add("dhcp.option.type", option, offset=offset, length=1)
            length = reader.uint8("dhcp.option.length")
            if length > reader.remaining:
                raise MalformedError(
                    f"option {option} claims {length} bytes, but {reader.remaining} are left"
                )
            with reader.inside():
                value = reader.buffer.peek(length)
                reader.add("dhcp.option.value", value, offset=reader.buffer.offset, length=length)
                kind = self._option(reader, option, length) or kind
            reader.skip(max(offset + 2 + length - reader.buffer.offset, 0), "dhcp.option")
        return kind

    @staticmethod
    def _padding(reader: Reader) -> None:
        """The zeroes a message is filled out to its length with."""
        if reader.remaining:
            reader.bytes("dhcp.option.padding", reader.remaining)

    @staticmethod
    def _option(reader: Reader, option: int, length: int) -> int:
        """One option's value, for the options worth reading out."""
        if option == 53 and length == 1:
            return reader.uint8("dhcp.option.dhcp")
        if option in ADDRESSES and length % 4 == 0:
            for _ in range(length // 4):
                reader.ipv4(ADDRESSES[option])
        elif option in TIMES and length == 4:
            reader.uint32(TIMES[option])
        elif option in TEXTS:
            reader.string(TEXTS[option], length)
        elif option == 55:
            for _ in range(length):
                reader.uint8("dhcp.option.request_list_item")
        elif option == 61 and length == 7 and reader.buffer.peek(1)[0] == ETHERNET:
            # A client that names itself by its hardware address, which is
            # what the fields of the header above are called.
            reader.uint8("dhcp.hw.type")
            reader.mac("dhcp.hw.mac_addr")
        return 0
