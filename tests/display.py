"""A small capture for the display filter tests, one packet of each kind.

==  ==========================================================================
 1  TCP SYN, 192.0.2.1:50000 to 192.0.2.2:80
 2  TCP SYN, ACK back
 3  TCP ACK
 4  HTTP ``GET /index.html`` for www.example.com
 5  HTTP ``200 OK`` carrying ``hello``
 6  DNS query for www.example.com, 192.0.2.1:50001 to 192.0.2.53:53
 7  DNS response with two addresses, 192.0.2.80 and 192.0.2.81
 8  ICMP echo request, 192.0.2.1 to 198.51.100.7
 9  ARP request broadcast for 192.0.2.2
10  ICMPv6 echo request, 2001:db8::1 to 2001:db8::2
11  UDP 10.1.2.3:5000 to 192.168.1.9:6000 carrying five bytes nothing decodes
==  ==========================================================================

They arrive a millisecond apart, the first at 0.001 seconds.
"""

import struct
from functools import cache
from ipaddress import IPv4Address

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from packets import CLIENT_MAC, ethernet, icmp_echo, icmpv6, ipv4, ipv6, mac, udp
from pilotfish.core.display import DisplayFilter
from pilotfish.core.dissect import ProtocolTree, Session, dissect
from pilotfish.core.packet import Packet
from streams import Talk, captured

BROADCAST = "ff:ff:ff:ff:ff:ff"
RESOLVER = "192.0.2.53"

REQUEST = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: pilotfish/1.0\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"


def _name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _dns(*, response: bool) -> bytes:
    question = _name("www.example.com") + struct.pack(">HH", 1, 1)
    if not response:
        return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    answers = b"".join(
        # A pointer back to the name in the question, then an address.
        struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + IPv4Address(address).packed
        for address in ("192.0.2.80", "192.0.2.81")
    )
    return struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0) + question + answers


def _arp_request() -> bytes:
    body = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
    body += mac(CLIENT_MAC) + IPv4Address("192.0.2.1").packed
    body += bytes(6) + IPv4Address("192.0.2.2").packed
    return ethernet(body, 0x0806, destination=BROADCAST)


def frames() -> list[bytes]:
    talk = Talk()
    query = udp(50001, 53, _dns(response=False), source="192.0.2.1", destination=RESOLVER)
    answer = udp(53, 50001, _dns(response=True), source=RESOLVER, destination="192.0.2.1")
    echo6 = icmpv6(128, 0, b"\x00\x01\x00\x01pilotfish")
    return [
        *talk.handshake(),
        *talk.send(REQUEST, from_client=True),
        *talk.send(RESPONSE, from_client=False),
        ethernet(ipv4(query, destination=RESOLVER)),
        ethernet(ipv4(answer, source=RESOLVER, destination="192.0.2.1")),
        ethernet(ipv4(icmp_echo(), 1, destination="198.51.100.7")),
        _arp_request(),
        ethernet(ipv6(echo6, 58), 0x86DD),
        ethernet(
            ipv4(
                udp(5000, 6000, b"\x00\x01\x02\x03\xff"),
                source="10.1.2.3",
                destination="192.168.1.9",
            )
        ),
    ]


@cache
def decoded() -> tuple[tuple[Packet, ProtocolTree], ...]:
    """Every packet of the capture with its tree, decoded as one capture."""
    session = Session()
    packets = captured(frames())
    return tuple(
        (packet, dissect(packet, number, session=session))
        for number, packet in enumerate(packets, start=1)
    )


def matched(compiled: DisplayFilter) -> list[int]:
    """The numbers of the packets a filter passes, by its generated function."""
    return [
        number
        for number, (packet, tree) in enumerate(decoded(), start=1)
        if compiled.matches(tree, packet.data)
    ]


def walked(compiled: DisplayFilter) -> list[int]:
    """The same, by walking the filter's tree instead."""
    return [
        number
        for number, (packet, tree) in enumerate(decoded(), start=1)
        if compiled.walk(tree, packet.data)
    ]
