"""Compiled filters and the packets to try them on, shared by the filter tests."""

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


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    destination = b"\x02\x00\x00\x00\x00\x01"
    source = b"\x02\x00\x00\x00\x00\x02"
    return destination + source + ethertype.to_bytes(2, "big") + payload


def ipv4(payload: bytes, protocol: int = 17, fragment_offset: int = 0, options: int = 0) -> bytes:
    """An IPv4 header, with room for ``options`` bytes after the fixed part."""
    words = 5 + options // 4
    header = bytes([0x40 | words, 0]) + (20 + options + len(payload)).to_bytes(2, "big")
    header += b"\x00\x01" + fragment_offset.to_bytes(2, "big")
    header += bytes([64, protocol]) + b"\x00\x00"
    header += bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2])
    return header + bytes(options) + payload


def ipv6(payload: bytes, next_header: int = 17) -> bytes:
    header = b"\x60\x00\x00\x00" + len(payload).to_bytes(2, "big") + bytes([next_header, 64])
    return header + bytes(16) + bytes(16) + payload


def udp(source_port: int, destination_port: int, payload: bytes = b"hello") -> bytes:
    header = source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big")
    return header + (8 + len(payload)).to_bytes(2, "big") + b"\x00\x00" + payload
