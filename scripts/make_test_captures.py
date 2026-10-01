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

import gzip
import hashlib
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


def udp(
    payload: bytes,
    *,
    source_port: int = 50000,
    destination_port: int = 53,
    between: tuple[str, str] | None = None,
) -> bytes:
    """A UDP datagram, checksummed when it is told the addresses it goes
    ``between``. Over IPv4 a checksum of zero means there isn't one."""
    datagram = struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    if between is None:
        return datagram
    pseudo = (
        IPv4Address(between[0]).packed
        + IPv4Address(between[1]).packed
        + struct.pack(">BBH", 0, PROTO_UDP, len(datagram))
    )
    return datagram[:6] + struct.pack(">H", checksum(pseudo + datagram)) + datagram[8:]


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


def write_pcap(
    path: Path, link_type: int, packets: list[bytes], times: list[float] | None = None
) -> None:
    """A pcap file, one packet a second unless ``times`` says otherwise."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type))
    for number, packet in enumerate(packets):
        when = float(number) if times is None else times[number]
        seconds, microseconds = divmod(round(when * 1_000_000), 1_000_000)
        out += struct.pack("<IIII", 1_700_000_000 + seconds, microseconds, len(packet), len(packet))
        out += packet
    path.write_bytes(out)
    print(f"wrote {path.relative_to(SAMPLES_DIR.parent.parent)} ({len(packets)} packets)")


CLIENT_PORT = 50000
SERVER_PORT = 80
CLIENT_ISN = 1000
SERVER_ISN = 5000

FIN = 0x01
SYN = 0x02
ACK = 0x10
PUSH = 0x08


def tcp(
    sequence: int,
    acknowledgement: int,
    flags: int,
    *,
    payload: bytes = b"",
    window: int = 8000,
    options: bytes = b"",
    from_client: bool = True,
    client_port: int = CLIENT_PORT,
    server_port: int = SERVER_PORT,
) -> bytes:
    """One TCP segment, checksummed over the IPv4 pseudo header."""
    assert len(options) % 4 == 0
    header = struct.pack(
        ">HHIIBBHHH",
        client_port if from_client else server_port,
        server_port if from_client else client_port,
        sequence,
        acknowledgement,
        (5 + len(options) // 4) << 4,
        flags,
        window,
        0,
        0,
    )
    source, destination = ("192.0.2.1", "192.0.2.2") if from_client else ("192.0.2.2", "192.0.2.1")
    segment = header + options + payload
    pseudo = (
        IPv4Address(source).packed
        + IPv4Address(destination).packed
        + struct.pack(">BBH", 0, PROTO_TCP, len(segment))
    )
    value = checksum(pseudo + segment)
    segment = segment[:16] + struct.pack(">H", value) + segment[18:]
    return ethernet(
        ipv4(segment, PROTO_TCP, source=source, destination=destination),
        ETHERTYPE_IPV4,
        source=CLIENT_MAC if from_client else SERVER_MAC,
        destination=SERVER_MAC if from_client else CLIENT_MAC,
    )


def tcp_capture() -> tuple[list[bytes], list[float]]:
    """A connection carrying every judgement the analysis can make.

    The times matter as much as the sequence numbers: re-ordering is only
    re-ordering if it arrives soon after the segment it follows, and a
    retransmission is only fast if it comes hard on the heels of duplicate
    acknowledgements.
    """
    # Twelve bytes of options: a maximum segment size, a window scale of zero
    # so the windows below mean what they say, and selective acknowledgement.
    handshake = (
        struct.pack(">BBH", 2, 4, 1460)
        + struct.pack(">BBB", 3, 3, 0)
        + bytes([1])
        + struct.pack(">BB", 4, 2)
        + bytes(2)
    )
    client = CLIENT_ISN
    server = SERVER_ISN
    packets = [
        # The handshake, which fixes where the sequence numbers start.
        tcp(client, 0, SYN, options=handshake),
        tcp(server, client + 1, SYN | ACK, options=handshake, from_client=False),
        tcp(client + 1, server + 1, ACK),
        # A hundred bytes, then a gap, then the pieces that fill it.
        tcp(client + 1, server + 1, PUSH | ACK, payload=b"a" * 100),
        tcp(client + 301, server + 1, PUSH | ACK, payload=b"d" * 100),
        tcp(client + 101, server + 1, PUSH | ACK, payload=b"b" * 100),
        tcp(client + 201, server + 1, PUSH | ACK, payload=b"c" * 100),
        tcp(server + 1, client + 401, ACK, from_client=False),
        tcp(client + 401, server + 1, PUSH | ACK, payload=b"e" * 100),
        # Two acknowledgements that say nothing new, then the sender giving up
        # on the segment they keep asking for.
        tcp(server + 1, client + 401, ACK, from_client=False),
        tcp(server + 1, client + 401, ACK, from_client=False),
        tcp(client + 401, server + 1, PUSH | ACK, payload=b"e" * 100),
        # Data the other end acknowledged long ago.
        tcp(client + 1, server + 1, PUSH | ACK, payload=b"a" * 100),
        # The window shuts, is probed, and opens again.
        tcp(server + 1, client + 501, ACK, window=0, from_client=False),
        tcp(client + 501, server + 1, PUSH | ACK, payload=b"f"),
        tcp(server + 1, client + 501, ACK, window=0, from_client=False),
        tcp(server + 1, client + 501, ACK, from_client=False),
        # The byte the probe carried, now that there is room for it.
        tcp(client + 501, server + 1, PUSH | ACK, payload=b"f"),
        tcp(server + 1, client + 502, ACK, from_client=False),
        # Filling the window right to its edge.
        tcp(client + 502, server + 1, PUSH | ACK, payload=b"g" * 8000),
        tcp(server + 1, client + 8502, ACK, from_client=False),
        # A keep-alive starts one byte before what comes next, and is answered.
        tcp(client + 8501, server + 1, ACK, payload=b"g"),
        tcp(server + 1, client + 8502, ACK, from_client=False),
        # Closing down.
        tcp(client + 8502, server + 1, FIN | ACK),
        tcp(server + 1, client + 8503, FIN | ACK, from_client=False),
        tcp(client + 8503, server + 2, ACK),
        # A second connection, for the two judgements the first one can't
        # make: a segment that arrives late enough to be re-ordering rather
        # than a resend, which takes the other end having acknowledged
        # something in between, and an acknowledgement of data that was never
        # captured.
        *second_connection(),
    ]
    times = [
        0.000,
        0.010,
        0.020,  # handshake, a 10 ms round trip
        0.030,
        0.040,
        0.041,
        0.045,  # data, a gap, and the pieces filling it
        0.050,
        0.060,
        0.150,
        0.160,
        0.165,  # duplicate acknowledgements, then a fast resend
        0.300,  # a resend of data already acknowledged
        0.400,
        0.500,
        0.510,
        0.600,  # window shut, probed, opened
        0.700,
        0.710,  # the byte the probe carried
        0.800,
        0.810,  # filling the window
        0.900,
        0.910,  # a keep-alive and its answer
        1.000,
        1.010,
        1.020,  # closing down
        2.000,
        2.010,
        2.020,  # the second connection's handshake
        2.030,
        2.040,
        2.045,  # data, a gap, and the other end saying where it got to
        2.050,  # the piece filling the gap, soon enough to be re-ordering
        2.060,
        2.070,  # acknowledgements of data that isn't in the capture
    ]
    assert len(times) == len(packets)
    return packets, times


SECOND_CLIENT_PORT = 50001
SECOND_CLIENT_ISN = 2000
SECOND_SERVER_ISN = 6000


def second_connection() -> list[bytes]:
    """A short connection whose gap is filled while the other end is talking.

    Wireshark calls a late segment re-ordering rather than a resend when it
    comes within the handshake's round trip of the other end's last
    acknowledgement, so the acknowledgement in the middle is what makes the
    difference here.
    """
    client = SECOND_CLIENT_ISN
    server = SECOND_SERVER_ISN

    def segment(sequence: int, acknowledgement: int, flags: int, **rest: object) -> bytes:
        return tcp(
            sequence,
            acknowledgement,
            flags,
            client_port=SECOND_CLIENT_PORT,
            **rest,  # type: ignore[arg-type]
        )

    return [
        segment(client, 0, SYN),
        segment(server, client + 1, SYN | ACK, from_client=False),
        segment(client + 1, server + 1, ACK),
        segment(client + 1, server + 1, PUSH | ACK, payload=b"a" * 100),
        segment(client + 201, server + 1, PUSH | ACK, payload=b"c" * 100),
        segment(server + 1, client + 101, ACK, from_client=False),
        segment(client + 101, server + 1, PUSH | ACK, payload=b"b" * 100),
        # Two acknowledgements that reach past anything the capture holds:
        # the client's own segments only ever got as far as 301.
        segment(server + 1, client + 401, ACK, from_client=False),
        segment(server + 1, client + 501, ACK, from_client=False),
    ]


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


MDNS_PORT = 5353
MDNS_GROUP = "224.0.0.251"
MDNS_MAC = "01:00:5e:00:00:fb"
"""The Ethernet address the multicast group maps to."""

CACHE_FLUSH = 0x8000
UNICAST_RESPONSE = 0x8000

CLASS_IN = 1
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33


def labels(name: str) -> bytes:
    """A domain name as DNS writes it: each label with its length in front."""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"


def pointer(offset: int) -> bytes:
    """A name that isn't written out again, but points into the message."""
    return struct.pack(">H", 0xC000 | offset)


def record(name: bytes, kind: int, data: bytes, *, ttl: int = 4500, flush: bool = False) -> bytes:
    record_class = 1 | (CACHE_FLUSH if flush else 0)
    return name + struct.pack(">HHIH", kind, record_class, ttl, len(data)) + data


def mdns_capture() -> list[bytes]:
    """What a Mac announcing itself over Bonjour looks like.

    The response repeats names by pointing at the ones already in the message,
    which is the part of DNS worth testing: a pointer can aim at any byte of
    the message, including a name written inside another record's data. The
    message is built a piece at a time so that every pointer is the offset
    the piece it names actually landed at.
    """
    service = "_airplay._tcp.local"
    # Two questions: one asking for an answer to the whole group, one asking
    # for it straight back, which is the "QU" bit in what used to be the class.
    query = struct.pack(">HHHHHH", 0, 0, 2, 0, 0, 0)
    query += labels(service) + struct.pack(">HH", TYPE_PTR, CLASS_IN)
    query += labels("_companion-link._tcp.local")
    query += struct.pack(">HH", TYPE_PTR, CLASS_IN | UNICAST_RESPONSE)

    message = bytearray(struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 3))
    service_at = len(message)
    # Where the "local" label sits inside the service name, which is what the
    # host name below points at to end itself.
    local_at = service_at + len(labels("_airplay._tcp")) - 1
    instance = b"\x0bLiving Room" + pointer(service_at)
    message += labels(service) + struct.pack(">HHIH", TYPE_PTR, CLASS_IN, 4500, len(instance))
    instance_at = len(message)
    message += instance

    host = b"\x0bliving-room" + pointer(local_at)
    where = struct.pack(">HHH", 0, 0, 7000) + host
    message += pointer(instance_at)
    message += struct.pack(">HHIH", TYPE_SRV, CLASS_IN | CACHE_FLUSH, 120, len(where))
    host_at = len(message) + 6
    message += where

    # A TXT record is one or more strings, each with its length in front.
    text = b"".join(bytes([len(each)]) + each for each in (b"model=J1", b"srcvers=665.5"))
    message += pointer(instance_at)
    message += struct.pack(">HHIH", TYPE_TXT, CLASS_IN | CACHE_FLUSH, 4500, len(text)) + text

    address = IPv4Address("192.0.2.10").packed
    message += pointer(host_at)
    message += struct.pack(">HHIH", TYPE_A, CLASS_IN | CACHE_FLUSH, 120, len(address)) + address

    return [
        ethernet(
            ipv4(
                udp(bytes(payload), source_port=MDNS_PORT, destination_port=MDNS_PORT),
                PROTO_UDP,
                source=source,
                destination=MDNS_GROUP,
            ),
            ETHERTYPE_IPV4,
            source=source_mac,
            destination=MDNS_MAC,
        )
        for payload, source, source_mac in (
            (query, "192.0.2.1", CLIENT_MAC),
            (message, "192.0.2.10", SERVER_MAC),
        )
    ]


SSH_PORT = 22
SSH_CLIENT_PORT = 50002
SSH_CLIENT_ISN = 3000
SSH_SERVER_ISN = 7000


def ssh_packet(payload: bytes, *, padding: int = 8) -> bytes:
    """One SSH binary packet, which is its length, its padding, and the rest.

    Everything after the key exchange is encrypted, so only the packets here
    are readable; a real capture of a session is mostly opaque.
    """
    padded = bytes(padding)
    length = 1 + len(payload) + len(padded)
    return struct.pack(">IB", length, len(padded)) + payload + padded


def name_list(*names: str) -> bytes:
    text = ",".join(names).encode()
    return struct.pack(">I", len(text)) + text


def kexinit(*, from_client: bool) -> bytes:
    """The message each end opens with: everything it is willing to use."""
    kex = name_list("curve25519-sha256", "diffie-hellman-group14-sha256")
    keys = (
        name_list("ssh-ed25519", "rsa-sha2-512")
        if not from_client
        else name_list("ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519")
    )
    ciphers = name_list("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com")
    macs = name_list("hmac-sha2-256-etm@openssh.com", "hmac-sha2-256")
    compression = name_list("none", "zlib@openssh.com")
    languages = name_list()
    body = bytes(range(16))  # the cookie, which is random in a real session
    body += kex + keys + ciphers + ciphers + macs + macs + compression + compression
    body += languages + languages
    body += bytes([0]) + struct.pack(">I", 0)
    return ssh_packet(bytes([20]) + body)


def ssh_capture() -> list[bytes]:
    """A session up to the point where it turns to noise.

    The two ends greet each other in plain text, say what they can do, agree
    a key, and everything after that is encrypted.
    """
    client, server = SSH_CLIENT_ISN, SSH_SERVER_ISN

    def segment(sequence: int, acknowledgement: int, payload: bytes, *, from_client: bool) -> bytes:
        return tcp(
            sequence,
            acknowledgement,
            PUSH | ACK,
            payload=payload,
            from_client=from_client,
            client_port=SSH_CLIENT_PORT,
            server_port=SSH_PORT,
        )

    greetings = (b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n")
    client_kex, server_kex = kexinit(from_client=True), kexinit(from_client=False)
    new_keys = ssh_packet(bytes([21]))
    # Once both ends have switched keys there is nothing left to read.
    encrypted = struct.pack(">I", 44) + bytes(range(44))
    sent = [greetings[0], client_kex, new_keys, encrypted]
    answered = [greetings[1], server_kex, new_keys]
    packets = []
    client_seq, server_seq = client + 1, server + 1
    for number in range(max(len(sent), len(answered))):
        payload = sent[number]
        packets.append(segment(client_seq, server_seq, payload, from_client=True))
        client_seq += len(payload)
        if number >= len(answered):
            continue
        payload = answered[number]
        packets.append(segment(server_seq, client_seq, payload, from_client=False))
        server_seq += len(payload)
    return packets


TLS_PORT = 443
TLS_CLIENT_PORT = 50003
TLS_CLIENT_ISN = 4000
TLS_SERVER_ISN = 8000


def tls_record(kind: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack(">BHH", kind, version, len(body)) + body


def tls_handshake(kind: int, body: bytes) -> bytes:
    return struct.pack(">B", kind) + len(body).to_bytes(3, "big") + body


def tls_extension(kind: int, body: bytes) -> bytes:
    return struct.pack(">HH", kind, len(body)) + body


def tls_client_hello() -> bytes:
    """The record a client opens with: what it will accept, and who it wants.

    The lists here are a real macOS client's, including one of the reserved
    values a client throws in to keep servers honest.
    """
    name = b"example.com"
    server_name = tls_extension(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    alpn = tls_extension(16, struct.pack(">H", 12) + b"\x02h2\x08http/1.1")
    versions = tls_extension(43, bytes([8]) + struct.pack(">HHHH", 0x0304, 0x0303, 0x0302, 0x0301))
    groups = tls_extension(10, struct.pack(">HHHH", 6, 0x0A0A, 0x001D, 0x0017))
    formats = tls_extension(11, bytes([1, 0]))
    signatures = tls_extension(13, struct.pack(">HHHH", 6, 0x0403, 0x0804, 0x0401))
    share = bytes(range(32))
    key_share = tls_extension(51, struct.pack(">HHH", 36, 0x001D, len(share)) + share)
    suites = (0x1301, 0x1302, 0x1303, 0xC02B)

    hello = struct.pack(">H", 0x0303) + bytes(range(32)) + bytes([32]) + bytes(range(32))
    hello += struct.pack(">H", len(suites) * 2)
    hello += b"".join(struct.pack(">H", each) for each in suites)
    hello += bytes([1, 0])
    extensions = server_name + alpn + versions + groups + formats + signatures + key_share
    hello += struct.pack(">H", len(extensions)) + extensions
    return tls_record(22, tls_handshake(1, hello), version=0x0301)


def tls_capture() -> list[bytes]:
    """A handshake up to the point where it turns to noise.

    A client says which versions and ciphers it will accept and, in the clear,
    which server it is asking for; the server picks; and everything after that
    is encrypted.
    """
    client_hello = tls_client_hello()
    share = bytes(range(32))
    answered = struct.pack(">H", 0x0303) + bytes(range(32, 64)) + bytes([32]) + bytes(range(32))
    answered += struct.pack(">HB", 0x1301, 0)
    chosen = tls_extension(43, struct.pack(">H", 0x0304)) + tls_extension(
        51, struct.pack(">HH", 0x001D, len(share)) + share
    )
    answered += struct.pack(">H", len(chosen)) + chosen
    server_hello = tls_record(22, tls_handshake(2, answered))
    server_hello += tls_record(20, bytes([1]))
    server_hello += tls_record(23, bytes(range(64)))

    def segment(
        sequence: int,
        acknowledgement: int,
        flags: int,
        payload: bytes = b"",
        from_client: bool = True,
    ) -> bytes:
        return tcp(
            sequence,
            acknowledgement,
            flags,
            payload=payload,
            from_client=from_client,
            client_port=TLS_CLIENT_PORT,
            server_port=TLS_PORT,
        )

    client, server = TLS_CLIENT_ISN, TLS_SERVER_ISN
    return [
        segment(client, 0, SYN),
        segment(server, client + 1, SYN | ACK, from_client=False),
        segment(client + 1, server + 1, ACK),
        segment(client + 1, server + 1, PUSH | ACK, client_hello),
        segment(
            server + 1, client + 1 + len(client_hello), PUSH | ACK, server_hello, from_client=False
        ),
        segment(client + 1 + len(client_hello), server + 1 + len(server_hello), ACK),
    ]


FRAGMENT_SIZE = 1480
"""What fits in a 1500-byte Ethernet frame after an IPv4 header, and a
multiple of eight, as every fragment but the last has to be."""


def ipv4_fragments(
    datagram: bytes,
    protocol: int,
    *,
    identifier: int,
    source: str = "192.0.2.1",
    destination: str = "192.0.2.2",
    size: int = FRAGMENT_SIZE,
) -> list[bytes]:
    """One IPv4 datagram as the fragments a router would cut it into."""
    from_client = source == "192.0.2.1"
    return [
        ethernet(
            ipv4(
                datagram[offset : offset + size],
                protocol,
                source=source,
                destination=destination,
                identifier=identifier,
                flags=0b001 if offset + size < len(datagram) else 0,
                fragment_offset=offset // 8,
            ),
            ETHERTYPE_IPV4,
            source=CLIENT_MAC if from_client else SERVER_MAC,
            destination=SERVER_MAC if from_client else CLIENT_MAC,
        )
        for offset in range(0, len(datagram), size)
    ]


def ipv6_fragments(
    datagram: bytes,
    next_header: int,
    *,
    identifier: int,
    source: str = "2001:db8::1",
    destination: str = "2001:db8::2",
    size: int = 1232,
) -> list[bytes]:
    """The same for IPv6, where each piece carries a fragment header."""
    return [
        ethernet(
            ipv6(
                fragment_header(
                    next_header,
                    offset=offset // 8,
                    more=offset + size < len(datagram),
                    identifier=identifier,
                )
                + datagram[offset : offset + size],
                PROTO_IPV6_FRAGMENT,
                source=source,
                destination=destination,
            ),
            ETHERTYPE_IPV6,
        )
        for offset in range(0, len(datagram), size)
    ]


def fragments_capture() -> list[bytes]:
    """Datagrams too big for one frame, arriving the ways fragments do.

    In order, backwards, with a piece sent twice, and with a piece that
    never comes. Each whole datagram carries a checksum over all of it, so
    decoding it at all proves the pieces were put back where they belong.
    """
    filler = bytes(range(256)) * 12
    request = icmp_echo(8, identifier=0x0F0F, sequence=1, payload=filler[:3000])
    reply = icmp_echo(0, identifier=0x0F0F, sequence=1, payload=filler[:3000])
    ends = ("192.0.2.1", "192.0.2.2")
    datagram = udp(filler[:2000], source_port=50020, destination_port=50021, between=ends)
    twice = ipv4_fragments(datagram, PROTO_UDP, identifier=0x0303)
    lost = ipv4_fragments(udp(filler[:2500]), PROTO_UDP, identifier=0x0404)

    echo = icmpv6(128, 0, struct.pack(">HH", 0x0F0F, 1) + filler[:2000])
    answer = icmpv6(
        129,
        0,
        struct.pack(">HH", 0x0F0F, 1) + filler[:2000],
        source="2001:db8::2",
        destination="2001:db8::1",
    )
    return [
        # In the order they were cut.
        *ipv4_fragments(request, PROTO_ICMP, identifier=0x0101),
        # Last piece first, as a path that re-orders packets delivers them.
        *reversed(
            ipv4_fragments(
                reply, PROTO_ICMP, identifier=0x0202, source="192.0.2.2", destination="192.0.2.1"
            )
        ),
        # The first piece arrives twice before the second arrives at all.
        twice[0],
        twice[0],
        twice[1],
        # A first piece whose second never turns up, so it stays a fragment.
        lost[0],
        # The same two ways round again, over IPv6.
        *ipv6_fragments(echo, PROTO_IPV6_ICMP, identifier=0xF00D0001),
        *reversed(
            ipv6_fragments(
                answer,
                PROTO_IPV6_ICMP,
                identifier=0xF00D0002,
                source="2001:db8::2",
                destination="2001:db8::1",
            )
        ),
    ]


MSS = 1460
"""The most a segment carries over Ethernet: 1500 less two 20-byte headers."""


class Connection:
    """Both ends of one TCP connection, keeping count of what each has sent.

    Building a segment doesn't put it in the capture. The caller does that,
    which is how a segment gets to arrive late, twice, or not at all.
    """

    def __init__(self, client_port: int, server_port: int, client_isn: int, server_isn: int):
        self.client_port = client_port
        self.server_port = server_port
        self.next = {True: client_isn, False: server_isn}

    def segment(self, flags: int, payload: bytes = b"", *, from_client: bool) -> bytes:
        """The next segment from one end, acknowledging all the other has sent."""
        acknowledgement = self.next[not from_client] if flags & ACK else 0
        frame = tcp(
            self.next[from_client],
            acknowledgement,
            flags,
            payload=payload,
            from_client=from_client,
            client_port=self.client_port,
            server_port=self.server_port,
        )
        self.next[from_client] += len(payload) + (1 if flags & (SYN | FIN) else 0)
        return frame

    def handshake(self) -> list[bytes]:
        return [
            self.segment(SYN, from_client=True),
            self.segment(SYN | ACK, from_client=False),
            self.segment(ACK, from_client=True),
        ]

    def send(self, data: bytes, *, from_client: bool, size: int = MSS) -> list[bytes]:
        """``data`` cut into segments, the last of them pushed."""
        pieces = [data[at : at + size] for at in range(0, len(data), size)]
        return [
            self.segment(
                ACK | (PUSH if number == len(pieces) - 1 else 0), piece, from_client=from_client
            )
            for number, piece in enumerate(pieces)
        ]

    def acknowledge(self, *, from_client: bool) -> bytes:
        return self.segment(ACK, from_client=from_client)

    def close(self, *, first: bool) -> list[bytes]:
        """Each end says it has finished, ``first`` going first."""
        return [
            self.segment(FIN | ACK, from_client=first),
            self.segment(FIN | ACK, from_client=not first),
            self.segment(ACK, from_client=first),
        ]


DOWNLOAD_SIZE = 20000


def download_file() -> bytes:
    """The file the download capture carries: 20,000 bytes that look random
    and are the same every time, so the test that rebuilds the file from the
    capture knows what it should get."""
    blocks = (hashlib.sha256(number.to_bytes(4, "big")).digest() for number in range(625))
    return b"".join(blocks)


def chunked(body: bytes, size: int) -> bytes:
    """A body as HTTP sends it in chunks: each with its length in front, in
    hexadecimal, and a chunk of no length to finish."""
    pieces = [body[at : at + size] for at in range(0, len(body), size)]
    return b"".join(b"%x\r\n%s\r\n" % (len(piece), piece) for piece in pieces) + b"0\r\n\r\n"


def http_download_capture() -> list[bytes]:
    """A file fetched over HTTP, and the three ways a body says where it ends.

    The download is the point: a response far bigger than one segment, whose
    segments don't all arrive in order. Following the server's side of the
    stream has to give back the file exactly.

    After it, on the same connection, comes a body sent compressed and in
    chunks, and on a second connection a body with no length at all, which
    ends when the server hangs up.
    """
    file = download_file()
    assert len(file) == DOWNLOAD_SIZE
    first = Connection(50010, SERVER_PORT, 10_000, 50_000)
    packets = first.handshake()
    request = b"GET /pilotfish.bin HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    packets += first.send(request, from_client=True)
    packets.append(first.acknowledge(from_client=False))
    head = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: pilotfish\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\n"
        b"\r\n" % len(file)
    )
    segments = first.send(head + file, from_client=False)
    # The fourth segment overtakes the third, as happens when the two take
    # different paths. Until the third arrives there is a hole in the file.
    segments[2], segments[3] = segments[3], segments[2]
    packets += segments
    packets.append(first.acknowledge(from_client=True))
    # The server never heard that its last segment arrived, and sends it again.
    packets.append(segments[-1])
    packets.append(first.acknowledge(from_client=True))

    notes = b"".join(b"Line %03d of the notes.\n" % number for number in range(1, 121))
    packets += first.send(
        b"GET /notes.txt HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n",
        from_client=True,
    )
    packed = gzip.compress(notes, mtime=0)
    answer = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: pilotfish\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    ) + chunked(packed, 100)
    # Cut where no chunk ends, so a size and its chunk land in different
    # segments.
    packets += first.send(answer, from_client=False, size=173)
    packets.append(first.acknowledge(from_client=True))
    packets += first.close(first=True)

    second = Connection(50011, SERVER_PORT, 20_000, 60_000)
    packets += second.handshake()
    packets += second.send(b"GET /old.txt HTTP/1.0\r\nHost: example.com\r\n\r\n", from_client=True)
    old = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"".join(
        b"An older server sends line %02d and says nothing of how many follow.\n" % number
        for number in range(1, 41)
    )
    packets += second.send(old, from_client=False)
    packets.append(second.acknowledge(from_client=True))
    # Hanging up is the only thing that says the body is over.
    packets += second.close(first=False)
    return packets


def segments_capture() -> list[bytes]:
    """Messages that TCP cut wherever a segment happened to end.

    A TLS server's records, cut inside a record, inside a record's header,
    and between records, and then an SSH key exchange message that takes two
    segments to arrive. Each message has to be decoded once, whole, in the
    packet that brings the last of it.
    """
    share = bytes(range(32))
    chosen = tls_extension(43, struct.pack(">H", 0x0304)) + tls_extension(
        51, struct.pack(">HH", 0x001D, len(share)) + share
    )
    hello = struct.pack(">H", 0x0303) + bytes(range(32, 64)) + bytes([32]) + bytes(range(32))
    hello += struct.pack(">HB", 0x1301, 0) + struct.pack(">H", len(chosen)) + chosen
    records = [
        tls_record(22, tls_handshake(2, hello)),
        tls_record(20, bytes([1])),
        tls_record(23, bytes(range(256)) * 5),
        tls_record(23, bytes(range(255, -1, -1)) * 12),
        tls_record(23, bytes(range(64))),
        tls_record(23, bytes(range(200))),
    ]
    flight = b"".join(records)
    third = len(records[0]) + len(records[1])
    fourth = third + len(records[2])
    cuts = [
        100,  # inside the ServerHello
        third + 3,  # three bytes into a record's header
        fourth,  # exactly where one record ends and the next begins
        fourth + MSS,
        fourth + 2 * MSS,
        len(flight) - 150,  # the end of one record, a whole one, the start of another
        len(flight),
    ]
    tls = Connection(50012, TLS_PORT, 30_000, 70_000)
    packets = tls.handshake()
    packets += tls.send(tls_client_hello(), from_client=True)
    at = 0
    for cut in cuts:
        packets += tls.send(flight[at:cut], from_client=False)
        at = cut
    packets.append(tls.acknowledge(from_client=True))

    ssh = Connection(50013, SSH_PORT, 40_000, 80_000)
    packets += ssh.handshake()
    packets += ssh.send(b"SSH-2.0-OpenSSH_9.6\r\n", from_client=True)
    packets += ssh.send(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n", from_client=False)
    # A real client offers enough algorithms that the list outgrows a segment.
    packets += ssh.send(kexinit(from_client=True), from_client=True, size=200)
    packets += ssh.send(kexinit(from_client=False), from_client=False)
    packets.append(ssh.acknowledge(from_client=True))
    return packets


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    write_pcap(SAMPLES_DIR / "vlan.pcap", LINKTYPE_ETHERNET, vlan_capture())
    write_pcap(SAMPLES_DIR / "icmp.pcap", LINKTYPE_ETHERNET, icmp_capture())
    write_pcap(SAMPLES_DIR / "icmpv6.pcap", LINKTYPE_ETHERNET, icmpv6_capture())
    write_pcap(SAMPLES_DIR / "ipv6-extensions.pcap", LINKTYPE_ETHERNET, extensions_capture())
    write_pcap(SAMPLES_DIR / "loopback.pcap", LINKTYPE_NULL, loopback_capture())
    segments, times = tcp_capture()
    write_pcap(SAMPLES_DIR / "tcp.pcap", LINKTYPE_ETHERNET, segments, times)
    write_pcap(SAMPLES_DIR / "mdns.pcap", LINKTYPE_ETHERNET, mdns_capture())
    write_pcap(SAMPLES_DIR / "ssh.pcap", LINKTYPE_ETHERNET, ssh_capture())
    write_pcap(SAMPLES_DIR / "tls.pcap", LINKTYPE_ETHERNET, tls_capture())
    write_pcap(SAMPLES_DIR / "fragments.pcap", LINKTYPE_ETHERNET, fragments_capture())
    for name, packets in (
        ("http-download.pcap", http_download_capture()),
        ("segments.pcap", segments_capture()),
    ):
        # A millisecond apart, as packets on a local network are, which is
        # what makes a segment that arrives late count as re-ordered rather
        # than as sent again.
        times = [number / 1000 for number in range(len(packets))]
        write_pcap(SAMPLES_DIR / name, LINKTYPE_ETHERNET, packets, times)
    digest = hashlib.sha256(download_file()).hexdigest()
    print(f"http-download.pcap carries a file whose SHA-256 is {digest}")


if __name__ == "__main__":
    main()
    sys.exit(0)
