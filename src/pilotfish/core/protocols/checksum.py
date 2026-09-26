"""The internet checksum, and what Wireshark calls a checksum's status.

Every header in this stage that carries a checksum uses the same one: the
one's complement of the one's complement sum of the 16-bit words. Checking it
is the same sum over the bytes with the checksum still in place, which comes
out as zero when nothing was damaged.

Reference: RFC 1071.
"""

import struct
from collections.abc import Buffer
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address


class ChecksumStatus(IntEnum):
    """The numbers Wireshark's ``*.checksum.status`` fields report."""

    BAD = 0
    GOOD = 1
    UNVERIFIED = 2
    """The checksum wasn't checked, because not enough of the packet was captured."""
    NOT_PRESENT = 3


def internet_checksum(*parts: Buffer) -> int:
    """The checksum of these bytes, taken as one run."""
    data = b"".join(bytes(part) for part in parts)
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def verify(*parts: Buffer) -> ChecksumStatus:
    """Whether bytes that still hold their checksum add up."""
    return ChecksumStatus.GOOD if internet_checksum(*parts) == 0 else ChecksumStatus.BAD


def pseudo_header(
    source: IPv4Address | IPv6Address,
    destination: IPv4Address | IPv6Address,
    protocol: int,
    length: int,
) -> bytes:
    """The addresses and length a transport checksum is taken over as well.

    It isn't sent anywhere: both ends build it from the IP header, so a packet
    delivered to the wrong address or the wrong protocol fails the check.
    """
    if isinstance(source, IPv6Address):
        return source.packed + destination.packed + struct.pack(">IBBBB", length, 0, 0, 0, protocol)
    return source.packed + destination.packed + struct.pack(">BBH", 0, protocol, length)
