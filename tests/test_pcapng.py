import re
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from builders import (
    ByteOrder,
    block,
    enhanced_packet,
    interface_description,
    option,
    options,
    packet_block,
    section_header,
    simple_packet,
)
from pilotfish.core.formats import CaptureFileError, PcapngReader
from pilotfish.core.packet import Packet

ORDERS: tuple[ByteOrder, ...] = ("<", ">")


def read(data: bytes) -> list[Packet]:
    return list(PcapngReader(memoryview(data)))


def expected_ns(ticks: int, tsresol: int | None, tsoffset: int = 0) -> int:
    """Convert ticks to nanoseconds the long way, as a check on the reader."""
    resolution = 6 if tsresol is None else tsresol
    exponent = resolution & 0x7F
    ns: int  # int ** int is typed Any, since a negative exponent gives a float
    if resolution & 0x80:
        ns = ticks * 10**9 // 2**exponent
    elif exponent <= 9:
        ns = ticks * 10 ** (9 - exponent)
    else:
        ns = ticks // 10 ** (exponent - 9)
    return ns + tsoffset * 10**9


@pytest.mark.parametrize("order", ORDERS)
def test_reads_a_basic_file(order: ByteOrder) -> None:
    data = section_header(order) + interface_description(order, link_type=1, snaplen=65535)
    data += enhanced_packet(order, 0, 1_340_954_905_298_858, b"\xff" * 6, original_length=60)
    assert read(data) == [
        Packet(
            timestamp_ns=1_340_954_905_298_858_000,
            original_length=60,
            link_type=1,
            data=b"\xff" * 6,
        )
    ]


@pytest.mark.parametrize(
    ("tsresol", "ticks", "ns"),
    [
        (None, 1_000_000_123_456, 1_000_000_123_456_000),  # default: microseconds
        (9, 1_000_000_000_123_456_789, 1_000_000_000_123_456_789),
        (0, 5, 5_000_000_000),  # whole seconds
        (0x80 | 20, 3 * 2**20 + 2**19, 3_500_000_000),  # 2**-20 seconds
        (10, 12_345, 1_234),  # tenths of a nanosecond, rounded down
    ],
)
def test_timestamp_resolution(tsresol: int | None, ticks: int, ns: int) -> None:
    data = section_header() + interface_description(tsresol=tsresol)
    data += enhanced_packet("<", 0, ticks, b"")
    assert read(data)[0].timestamp_ns == ns


@pytest.mark.parametrize("tsoffset", [100, -100])
def test_timestamp_offset(tsoffset: int) -> None:
    data = section_header() + interface_description(tsoffset=tsoffset)
    data += enhanced_packet("<", 0, 1_000_000, b"")
    assert read(data)[0].timestamp_ns == (1 + tsoffset) * 10**9


def test_packets_take_link_type_from_their_interface() -> None:
    data = section_header()
    data += interface_description(link_type=1, name="en0")
    data += interface_description(link_type=0, name="lo0")
    data += enhanced_packet("<", 1, 0, b"lo") + enhanced_packet("<", 0, 0, b"en")
    assert [(p.interface_id, p.link_type, bytes(p.data)) for p in read(data)] == [
        (1, 0, b"lo"),
        (0, 1, b"en"),
    ]


def test_skips_blocks_it_does_not_recognize() -> None:
    unknown = [
        block("<", 4, b"\0" * 4),  # Name Resolution Block
        block("<", 5, b"\0" * 12),  # Interface Statistics Block
        block("<", 0x00000BAD, b"\0\0\x7e\xd9custom data"),  # Custom Block
        block("<", 0x12345678, b""),
    ]
    data = section_header() + interface_description()
    data += b"".join(unknown[:2]) + enhanced_packet("<", 0, 0, b"a")
    data += b"".join(unknown[2:]) + enhanced_packet("<", 0, 0, b"b")
    assert [bytes(p.data) for p in read(data)] == [b"a", b"b"]


def test_strips_padding_and_ignores_packet_options() -> None:
    comment = options("<", option("<", 1, b"a comment"))
    data = section_header() + interface_description()
    data += enhanced_packet("<", 0, 0, b"12345", opts=comment)
    assert bytes(read(data)[0].data) == b"12345"


def test_each_section_sets_its_own_byte_order_and_interfaces() -> None:
    data = section_header("<") + interface_description("<", link_type=1)
    data += enhanced_packet("<", 0, 1_000_000, b"le")
    data += section_header(">") + interface_description(">", link_type=101, tsresol=9)
    data += enhanced_packet(">", 0, 2_000_000_000, b"be")
    assert [(p.link_type, p.timestamp_ns, bytes(p.data)) for p in read(data)] == [
        (1, 1_000_000_000, b"le"),
        (101, 2_000_000_000, b"be"),
    ]


def test_new_section_forgets_earlier_interfaces() -> None:
    data = section_header() + interface_description() + interface_description()
    data += section_header() + interface_description() + enhanced_packet("<", 1, 0, b"")
    with pytest.raises(CaptureFileError, match="refers to interface 1, but its section"):
        read(data)


@pytest.mark.parametrize(
    ("snaplen", "payload", "original_length", "captured"),
    [
        (0, b"123456", None, b"123456"),  # no snap length: everything
        (4, b"123456", None, b"1234"),  # cut to the snap length
        (0, b"12345", None, b"12345"),  # padding isn't data
        (2, b"123", 1500, b"12"),  # longer on the wire, cut to the snap length
    ],
)
def test_simple_packet_block(
    snaplen: int, payload: bytes, original_length: int | None, captured: bytes
) -> None:
    data = section_header() + interface_description(snaplen=snaplen, link_type=113)
    data += simple_packet("<", payload, original_length)
    [packet] = read(data)
    assert packet.timestamp_ns is None
    assert packet.link_type == 113
    assert bytes(packet.data) == captured
    assert packet.original_length == (len(payload) if original_length is None else original_length)


def test_simple_packet_longer_than_its_block_is_an_error() -> None:
    # Without a snap length the packet should be all 1500 bytes, which the block
    # can't hold. tshark reports these files as corrupt too.
    data = section_header() + interface_description() + simple_packet("<", b"123", 1500)
    with pytest.raises(CaptureFileError, match="claims 1500 bytes, more than its block holds"):
        read(data)


def test_reads_obsolete_packet_block() -> None:
    data = section_header() + interface_description(tsresol=9)
    data += packet_block("<", 0, 42, b"old", original_length=64)
    assert read(data) == [Packet(42, 64, 1, b"old")]


def _with_length(data: bytes, offset: int, length: int) -> bytes:
    return data[: offset + 4] + struct.pack("<I", length) + data[offset + 8 :]


_SHB = section_header()
_IDB = interface_description()
_EPB = enhanced_packet("<", 0, 0, b"abcd")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xa1\xb2\xc3\xd4" + _SHB[4:], "not a pcapng file"),
        (_SHB[:8] + b"\0\0\0\0" + _SHB[12:], "bad byte-order magic"),
        (section_header(version=(2, 0)), "unsupported pcapng version 2.0"),
        (_SHB + _with_length(_IDB, 0, 30), "length 30, which isn't a multiple of 4"),
        (_SHB + block("<", 6, b"\0" * 4), "has length 16; this type needs 32"),
        (_SHB + _IDB[:-4] + b"\x10\0\0\0", "starts with length 20 but ends with 16"),
        (_SHB + _IDB + _EPB[:-8], "is cut short: 28 of 36 bytes"),
        (_SHB + _IDB + b"\x06\0\0\0", "block at offset 48 is cut short"),
        (_SHB + _EPB, "refers to interface 0, but its section describes 0 interfaces"),
        (
            _SHB + _IDB + _EPB[:20] + struct.pack("<I", 9) + _EPB[24:],
            "claims 9 bytes, more than its block holds",
        ),
        (
            _SHB + block("<", 1, b"\x01\0\0\0\0\0\0\0" + option("<", 2, b"en0")[:4]),
            "runs past the end of its block",
        ),
    ],
)
def test_rejects_malformed_files(data: bytes, message: str) -> None:
    with pytest.raises(CaptureFileError, match=re.escape(message)):
        read(data)


interfaces = st.lists(
    st.tuples(
        st.integers(0, 0xFFFF),  # link type
        st.sampled_from([None, 0, 3, 6, 9, 12, 0x80 | 10, 0x80 | 30]),  # if_tsresol
        st.integers(-(2**40), 2**40),  # if_tsoffset
    ),
    min_size=1,
    max_size=3,
)


@st.composite
def sections(draw: st.DrawFn) -> tuple[bytes, list[Packet]]:
    order = draw(st.sampled_from(ORDERS))
    section_interfaces = draw(interfaces)
    data = section_header(order)
    for link_type, tsresol, tsoffset in section_interfaces:
        data += interface_description(
            order, link_type=link_type, tsresol=tsresol, tsoffset=tsoffset
        )
    expected = []
    for _ in range(draw(st.integers(0, 6))):
        interface_id = draw(st.integers(0, len(section_interfaces) - 1))
        link_type, tsresol, tsoffset = section_interfaces[interface_id]
        ticks = draw(st.integers(0, 2**64 - 1))
        payload = draw(st.binary(max_size=40))
        original_length = len(payload) + draw(st.integers(0, 1000))
        if draw(st.booleans()):
            data += block(order, 0x40000BAD, draw(st.binary(max_size=16)))
        make_block = draw(st.sampled_from([enhanced_packet, packet_block]))
        interface_field = interface_id if make_block is enhanced_packet else interface_id & 0xFFFF
        data += make_block(order, interface_field, ticks, payload, original_length)
        timestamp = expected_ns(ticks, tsresol, tsoffset)
        expected.append(Packet(timestamp, original_length, link_type, payload, interface_id))
    return data, expected


@given(st.lists(sections(), min_size=1, max_size=3))
def test_round_trip(file_sections: list[tuple[bytes, list[Packet]]]) -> None:
    data = b"".join(section for section, _ in file_sections)
    assert read(data) == [packet for _, packets in file_sections for packet in packets]
