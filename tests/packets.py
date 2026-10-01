"""Compiled filters and the packets to try them on, shared by the filter tests."""

import struct
from ipaddress import IPv4Address, IPv6Address, ip_address

from pilotfish.core.filters import Instruction, Program


def program(*fields: tuple[int, int, int, int]) -> Program:
    return Program(tuple(Instruction(*each) for each in fields))


# `udp port 53` as libpcap compiles it for Ethernet with a snapshot length of
# 262144. Recorded here so the tests that read it run anywhere, not only where
# libpcap can compile.
DNS_OVER_ETHERNET = program(
    (0x28, 0, 0, 12),  # ldh [12]: the EtherType
    (0x15, 0, 6, 34525),  # jeq #0x86dd: IPv6?
    (0x30, 0, 0, 20),  # ldb [20]: the IPv6 next header
    (0x15, 0, 15, 17),  # jeq #0x11: UDP?
    (0x28, 0, 0, 54),  # ldh [54]: the source port
    (0x15, 12, 0, 53),
    (0x28, 0, 0, 56),  # ldh [56]: the destination port
    (0x15, 10, 11, 53),
    (0x15, 0, 10, 2048),  # jeq #0x800: IPv4?
    (0x30, 0, 0, 23),  # ldb [23]: the IPv4 protocol
    (0x15, 0, 8, 17),  # jeq #0x11: UDP?
    (0x28, 0, 0, 20),  # ldh [20]: flags and fragment offset
    (0x45, 6, 0, 8191),  # jset #0x1fff: a later fragment has no ports to read
    (0xB1, 0, 0, 14),  # ldxb 4*([14]&0xf): the IPv4 header's length
    (0x48, 0, 0, 14),  # ldh [x + 14]: the source port, past that header
    (0x15, 2, 0, 53),
    (0x48, 0, 0, 16),  # ldh [x + 16]: the destination port
    (0x15, 0, 1, 53),
    (0x06, 0, 0, 262144),  # ret #262144: keep the packet
    (0x06, 0, 0, 0),  # ret #0: drop it
)

DNS_OVER_ETHERNET_IMAGE = [
    "(000) ldh      [12]",
    "(001) jeq      #0x86dd          jt 2\tjf 8",
    "(002) ldb      [20]",
    "(003) jeq      #0x11            jt 4\tjf 19",
    "(004) ldh      [54]",
    "(005) jeq      #0x35            jt 18\tjf 6",
    "(006) ldh      [56]",
    "(007) jeq      #0x35            jt 18\tjf 19",
    "(008) jeq      #0x800           jt 9\tjf 19",
    "(009) ldb      [23]",
    "(010) jeq      #0x11            jt 11\tjf 19",
    "(011) ldh      [20]",
    "(012) jset     #0x1fff          jt 19\tjf 13",
    "(013) ldxb     4*([14]&0xf)",
    "(014) ldh      [x + 14]",
    "(015) jeq      #0x35            jt 18\tjf 16",
    "(016) ldh      [x + 16]",
    "(017) jeq      #0x35            jt 18\tjf 19",
    "(018) ret      #262144",
    "(019) ret      #0",
]

ACCEPTED = 262144
"""What DNS_OVER_ETHERNET returns for a packet it keeps."""


CLIENT_MAC = "02:00:00:00:00:02"
SERVER_MAC = "02:00:00:00:00:01"


def mac(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


def ethernet(
    payload: bytes,
    ethertype: int = 0x0800,
    *,
    source: str = CLIENT_MAC,
    destination: str = SERVER_MAC,
) -> bytes:
    return mac(destination) + mac(source) + ethertype.to_bytes(2, "big") + payload


def checksum(data: bytes) -> int:
    """The internet checksum, worked out here rather than taken from pilotfish,
    so that a test packet and the dissector checking it agree by accident."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(
    payload: bytes,
    protocol: int = 17,
    fragment_offset: int = 0,
    options: bytes = b"",
    *,
    flags: int = 0b010,
    source: str = "192.0.2.1",
    destination: str = "192.0.2.2",
    identifier: int = 1,
    break_checksum: bool = False,
) -> bytes:
    """An IPv4 header, with ``options`` after the fixed part."""
    assert len(options) % 4 == 0
    words = 5 + len(options) // 4
    header = bytes([0x40 | words, 0]) + (20 + len(options) + len(payload)).to_bytes(2, "big")
    header += identifier.to_bytes(2, "big") + (flags << 13 | fragment_offset).to_bytes(2, "big")
    header += bytes([64, protocol]) + b"\x00\x00"
    header += IPv4Address(source).packed + IPv4Address(destination).packed
    whole = header + options
    value = checksum(whole) ^ (0xFFFF if break_checksum else 0)
    return whole[:10] + value.to_bytes(2, "big") + whole[12:] + payload


def icmp(kind: int, code: int, rest: bytes, *, break_checksum: bool = False) -> bytes:
    message = bytes([kind, code]) + b"\x00\x00" + rest
    value = checksum(message) ^ (0xFFFF if break_checksum else 0)
    return message[:2] + value.to_bytes(2, "big") + message[4:]


def icmp_echo(
    kind: int = 8,
    *,
    identifier: int = 0x00DE,
    sequence: int = 1,
    payload: bytes = b"pilotfish",
    break_checksum: bool = False,
) -> bytes:
    rest = identifier.to_bytes(2, "big") + sequence.to_bytes(2, "big") + payload
    return icmp(kind, 0, rest, break_checksum=break_checksum)


def pseudo_header(source: str, destination: str, protocol: int, length: int) -> bytes:
    """The bytes a transport checksum covers besides its own, which differ
    between IPv4 and IPv6."""
    first, second = ip_address(source), ip_address(destination)
    if isinstance(first, IPv4Address):
        return first.packed + second.packed + bytes([0, protocol]) + length.to_bytes(2, "big")
    return first.packed + second.packed + length.to_bytes(4, "big") + bytes([0, 0, 0, protocol])


def icmpv6(
    kind: int,
    code: int,
    rest: bytes,
    *,
    source: str = "2001:db8::1",
    destination: str = "2001:db8::2",
) -> bytes:
    """An ICMPv6 message, checksummed over the IPv6 pseudo header as well."""
    message = bytes([kind, code]) + b"\x00\x00" + rest
    pseudo = pseudo_header(source, destination, 58, len(message))
    return message[:2] + checksum(pseudo + message).to_bytes(2, "big") + message[4:]


def ipv6(
    payload: bytes,
    next_header: int = 17,
    *,
    source: str = "2001:db8::1",
    destination: str = "2001:db8::2",
) -> bytes:
    """An IPv6 header, with the addresses the icmpv6 helper checksums over."""
    header = b"\x60\x00\x00\x00" + len(payload).to_bytes(2, "big") + bytes([next_header, 64])
    return header + IPv6Address(source).packed + IPv6Address(destination).packed + payload


def udp(
    source_port: int,
    destination_port: int,
    payload: bytes = b"hello",
    *,
    source: str | None = None,
    destination: str | None = None,
    break_checksum: bool = False,
) -> bytes:
    """A UDP datagram, with no checksum unless it is given the addresses to
    take one over. Over IPv4 a zero means there isn't one."""
    header = source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big")
    datagram = header + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
    if source is None or destination is None:
        return datagram
    pseudo = pseudo_header(source, destination, 17, len(datagram))
    value = checksum(pseudo + datagram) ^ (0xFFFF if break_checksum else 0)
    return datagram[:6] + value.to_bytes(2, "big") + datagram[8:]


def tcp(
    source_port: int = 50000,
    destination_port: int = 80,
    payload: bytes = b"",
    *,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x010,
    window: int = 8192,
    options: bytes = b"",
    urgent: int = 0,
    source: str = "192.0.2.1",
    destination: str = "192.0.2.2",
    break_checksum: bool = False,
) -> bytes:
    """A TCP segment, checksummed over the pseudo header of its addresses.

    ``options`` goes after the fixed header and sets the header length, so it
    has to be a whole number of words, padded as a real sender pads it.
    """
    assert len(options) % 4 == 0
    words = 5 + len(options) // 4
    header = struct.pack(
        ">HHIIBBHHH",
        source_port,
        destination_port,
        seq,
        ack,
        words << 4 | flags >> 8,
        flags & 0xFF,
        window,
        0,
        urgent,
    )
    segment = header + options + payload
    pseudo = pseudo_header(source, destination, 6, len(segment))
    value = checksum(pseudo + segment) ^ (0xFFFF if break_checksum else 0)
    return segment[:16] + value.to_bytes(2, "big") + segment[18:]
