"""Build the small captures under samples/made/.

The sample captures from the Wireshark wiki carry no VLAN tags, no ICMP over
Ethernet, no ICMPv6 and no IPv6 extension headers, so these are built here
instead, a few packets each. Every layout follows its RFC, and tshark is the
check that they were built right: it decodes them in the answer keys the
dissector tests compare against.

    uv run scripts/make_test_captures.py

Then record the answer keys:

    uv run scripts/update_answer_keys.py samples/made/*.pcap
"""

import struct
import sys
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples" / "made"

LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6_HOPOPTS = 0
PROTO_IPV6_ROUTING = 43
PROTO_IPV6_FRAGMENT = 44
PROTO_IPV6_ICMP = 58
PROTO_IPV6_NONXT = 59
PROTO_IPV6_DSTOPTS = 60

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def checksum(data: bytes) -> int:
    """The internet checksum of RFC 1071, as every header here carries."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


def ethernet(
    payload: bytes, ethertype: int, *, source: str = CLIENT_MAC, destination: str = SERVER_MAC
) -> bytes:
    return mac(destination) + mac(source) + struct.pack(">H", ethertype) + payload


def vlan(
    payload: bytes, ethertype: int, *, priority: int = 0, dei: bool = False, identifier: int = 1
) -> bytes:
    tci = priority << 13 | int(dei) << 12 | identifier
    return struct.pack(">HH", tci, ethertype) + payload


def ipv4(
    payload: bytes,
    protocol: int,
    *,
    source: str = "192.0.2.1",
    destination: str = "192.0.2.2",
    identifier: int = 0x1234,
    flags: int = 0b010,  # don't fragment
    fragment_offset: int = 0,
    ttl: int = 64,
    options: bytes = b"",
    break_checksum: bool = False,
) -> bytes:
    assert len(options) % 4 == 0
    header_length = 20 + len(options)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x40 | header_length // 4,
        0,  # no differentiated services
        header_length + len(payload),
        identifier,
        flags << 13 | fragment_offset,
        ttl,
        protocol,
        0,  # the checksum goes in once the rest is known
        IPv4Address(source).packed,
        IPv4Address(destination).packed,
    )
    whole = header + options
    value = checksum(whole) ^ (0xFFFF if break_checksum else 0)
    return whole[:10] + struct.pack(">H", value) + whole[12:] + payload


def ipv6(
    payload: bytes,
    next_header: int,
    *,
    source: str = "2001:db8::1",
    destination: str = "2001:db8::2",
    traffic_class: int = 0,
    flow_label: int = 0,
    hop_limit: int = 64,
) -> bytes:
    first = 6 << 28 | traffic_class << 20 | flow_label
    return (
        struct.pack(">IHBB", first, len(payload), next_header, hop_limit)
        + IPv6Address(source).packed
        + IPv6Address(destination).packed
        + payload
    )


def hop_by_hop(payload_next: int) -> bytes:
    # One PadN option filling the rest of the eight bytes.
    options = struct.pack(">BB", 1, 4) + bytes(4)
    return struct.pack(">BB", payload_next, 0) + options


def destination_options(payload_next: int) -> bytes:
    options = struct.pack(">BB", 1, 4) + bytes(4)
    return struct.pack(">BB", payload_next, 0) + options


def routing_header(payload_next: int, *, segments: list[str]) -> bytes:
    addresses = b"".join(IPv6Address(each).packed for each in segments)
    return struct.pack(">BBBBI", payload_next, len(addresses) // 8, 0, len(segments), 0) + addresses


def fragment_header(
    payload_next: int, *, offset: int = 0, more: bool = True, identifier: int = 0xF00D
) -> bytes:
    return struct.pack(">BBHI", payload_next, 0, offset << 3 | int(more), identifier)


def udp(payload: bytes, *, source_port: int = 50000, destination_port: int = 53) -> bytes:
    return struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def icmp(kind: int, code: int, rest: bytes, *, break_checksum: bool = False) -> bytes:
    message = struct.pack(">BBH", kind, code, 0) + rest
    value = checksum(message) ^ (0xFFFF if break_checksum else 0)
    return message[:2] + struct.pack(">H", value) + message[4:]


def icmp_echo(
    kind: int = 8, *, identifier: int = 0x00DE, sequence: int = 1, payload: bytes = b"pilotfish"
) -> bytes:
    return icmp(kind, 0, struct.pack(">HH", identifier, sequence) + payload)


def icmp_error(kind: int, code: int, quoted: bytes) -> bytes:
    return icmp(kind, code, bytes(4) + quoted)


def icmpv6(
    kind: int,
    code: int,
    rest: bytes,
    *,
    source: str = "2001:db8::1",
    destination: str = "2001:db8::2",
    break_checksum: bool = False,
) -> bytes:
    message = struct.pack(">BBH", kind, code, 0) + rest
    pseudo = (
        IPv6Address(source).packed
        + IPv6Address(destination).packed
        + struct.pack(">IBBBB", len(message), 0, 0, 0, PROTO_IPV6_ICMP)
    )
    value = checksum(pseudo + message) ^ (0xFFFF if break_checksum else 0)
    return message[:2] + struct.pack(">H", value) + message[4:]


def link_layer_option(kind: int, address: str) -> bytes:
    """A source (1) or target (2) link-layer address option."""
    return struct.pack(">BB", kind, 1) + mac(address)


def write_pcap(path: Path, link_type: int, packets: list[bytes]) -> None:
    """A pcap file with microsecond timestamps, one second apart."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type))
    for number, packet in enumerate(packets):
        out += struct.pack("<IIII", 1_700_000_000 + number, 0, len(packet), len(packet))
        out += packet
    path.write_bytes(out)
    print(f"wrote {path.relative_to(SAMPLES_DIR.parent.parent)} ({len(packets)} packets)")


def vlan_capture() -> list[bytes]:
    echo = ipv4(icmp_echo(), PROTO_ICMP)
    arp_request = struct.pack(
        ">HHBBH6s4s6s4s",
        1,  # Ethernet
        ETHERTYPE_IPV4,
        6,
        4,
        1,  # request
        mac(CLIENT_MAC),
        IPv4Address("192.0.2.1").packed,
        mac("00:00:00:00:00:00"),
        IPv4Address("192.0.2.2").packed,
    )
    return [
        ethernet(vlan(echo, ETHERTYPE_IPV4, priority=3, identifier=100), ETHERTYPE_VLAN),
        ethernet(
            vlan(arp_request, ETHERTYPE_ARP, priority=0, dei=True, identifier=4095), ETHERTYPE_VLAN
        ),
    ]


def icmp_capture() -> list[bytes]:
    quoted = ipv4(udp(b"query"), PROTO_UDP, source="192.0.2.2", destination="192.0.2.1")
    record_route = struct.pack(">BBB", 7, 11, 4) + IPv4Address("192.0.2.9").packed + bytes(5)
    return [
        ethernet(ipv4(icmp_echo(8), PROTO_ICMP), ETHERTYPE_IPV4),
        ethernet(
            ipv4(icmp_echo(0), PROTO_ICMP, source="192.0.2.2", destination="192.0.2.1"),
            ETHERTYPE_IPV4,
        ),
        # Port unreachable, quoting the datagram that caused it.
        ethernet(ipv4(icmp_error(3, 3, quoted[:28]), PROTO_ICMP), ETHERTYPE_IPV4),
        # Time exceeded, as a traceroute hop answers.
        ethernet(ipv4(icmp_error(11, 0, quoted[:28]), PROTO_ICMP, ttl=1), ETHERTYPE_IPV4),
        # A header checksum that doesn't add up.
        ethernet(ipv4(icmp_echo(8, sequence=2), PROTO_ICMP, break_checksum=True), ETHERTYPE_IPV4),
        # A message checksum that doesn't add up.
        ethernet(
            ipv4(icmp(8, 0, struct.pack(">HH", 0xDE, 3) + b"bad", break_checksum=True), PROTO_ICMP),
            ETHERTYPE_IPV4,
        ),
        # Options in the header, and a fragment in the middle of a datagram.
        ethernet(ipv4(icmp_echo(8, sequence=4), PROTO_ICMP, options=record_route), ETHERTYPE_IPV4),
        ethernet(
            ipv4(b"\x00" * 16, PROTO_ICMP, flags=0b001, fragment_offset=185, identifier=0xBEEF),
            ETHERTYPE_IPV4,
        ),
    ]


def icmpv6_capture() -> list[bytes]:
    target = "2001:db8::2"
    quoted = ipv6(udp(b"query"), PROTO_UDP, source="2001:db8::2", destination="2001:db8::1")
    packets = [
        ipv6(icmpv6(128, 0, struct.pack(">HH", 0x007F, 1) + b"pilotfish"), PROTO_IPV6_ICMP),
        ipv6(
            icmpv6(
                129,
                0,
                struct.pack(">HH", 0x007F, 1) + b"pilotfish",
                source="2001:db8::2",
                destination="2001:db8::1",
            ),
            PROTO_IPV6_ICMP,
            source="2001:db8::2",
            destination="2001:db8::1",
        ),
        # Neighbour solicitation, with the sender's link-layer address.
        ipv6(
            icmpv6(
                135, 0, bytes(4) + IPv6Address(target).packed + link_layer_option(1, CLIENT_MAC)
            ),
            PROTO_IPV6_ICMP,
        ),
        # Neighbour advertisement: router, solicited and override flags set.
        ipv6(
            icmpv6(
                136,
                0,
                struct.pack(">I", 0b111 << 29)
                + IPv6Address(target).packed
                + link_layer_option(2, SERVER_MAC),
                source="2001:db8::2",
                destination="2001:db8::1",
            ),
            PROTO_IPV6_ICMP,
            source="2001:db8::2",
            destination="2001:db8::1",
        ),
        # Router advertisement with an MTU option.
        ipv6(
            icmpv6(
                134,
                0,
                struct.pack(">BBHII", 64, 0x08, 1800, 0, 0) + struct.pack(">BBHI", 5, 1, 0, 1500),
                source="fe80::1",
                destination="ff02::1",
            ),
            PROTO_IPV6_ICMP,
            source="fe80::1",
            destination="ff02::1",
            hop_limit=255,
        ),
        # An error message, quoting the packet that caused it.
        ipv6(
            icmpv6(1, 4, bytes(4) + quoted, source="2001:db8::2", destination="2001:db8::1"),
            PROTO_IPV6_ICMP,
            source="2001:db8::2",
            destination="2001:db8::1",
        ),
        # A checksum that doesn't add up.
        ipv6(
            icmpv6(128, 0, struct.pack(">HH", 0x007F, 9) + b"bad", break_checksum=True),
            PROTO_IPV6_ICMP,
        ),
    ]
    return [ethernet(packet, ETHERTYPE_IPV6) for packet in packets]


def extensions_capture() -> list[bytes]:
    echo = icmpv6(128, 0, struct.pack(">HH", 0x00AA, 1) + b"ext")
    packets = [
        # Hop-by-hop options, then the message.
        ipv6(hop_by_hop(PROTO_IPV6_ICMP) + echo, PROTO_IPV6_HOPOPTS),
        # Hop-by-hop, then destination options, then the message.
        ipv6(
            hop_by_hop(PROTO_IPV6_DSTOPTS) + destination_options(PROTO_IPV6_ICMP) + echo,
            PROTO_IPV6_HOPOPTS,
        ),
        # A routing header with one segment left to visit. It repeats the
        # destination, because the checksum of what follows is taken over the
        # last address in the routing header rather than the one in the
        # fixed header.
        ipv6(routing_header(PROTO_IPV6_ICMP, segments=["2001:db8::2"]) + echo, PROTO_IPV6_ROUTING),
        # The first fragment of a larger datagram.
        ipv6(fragment_header(PROTO_IPV6_ICMP, offset=0, more=True) + echo, PROTO_IPV6_FRAGMENT),
        # Nothing after the header at all.
        ipv6(b"", PROTO_IPV6_NONXT),
    ]
    return [ethernet(packet, ETHERTYPE_IPV6) for packet in packets]


def loopback_capture() -> list[bytes]:
    # macOS writes the address family in its own byte order, little-endian.
    inet = struct.pack("<I", 2)
    inet6 = struct.pack("<I", 30)
    return [
        inet + ipv4(icmp_echo(8), PROTO_ICMP, source="127.0.0.1", destination="127.0.0.1"),
        inet6
        + ipv6(
            icmpv6(128, 0, struct.pack(">HH", 0x0001, 1) + b"lo", source="::1", destination="::1"),
            PROTO_IPV6_ICMP,
            source="::1",
            destination="::1",
        ),
    ]


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    write_pcap(SAMPLES_DIR / "vlan.pcap", LINKTYPE_ETHERNET, vlan_capture())
    write_pcap(SAMPLES_DIR / "icmp.pcap", LINKTYPE_ETHERNET, icmp_capture())
    write_pcap(SAMPLES_DIR / "icmpv6.pcap", LINKTYPE_ETHERNET, icmpv6_capture())
    write_pcap(SAMPLES_DIR / "ipv6-extensions.pcap", LINKTYPE_ETHERNET, extensions_capture())
    write_pcap(SAMPLES_DIR / "loopback.pcap", LINKTYPE_NULL, loopback_capture())


if __name__ == "__main__":
    main()
    sys.exit(0)
