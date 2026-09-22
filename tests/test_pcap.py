import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from builders import ByteOrder, pcap_header, pcap_record
from pilotfish.core.formats import CaptureFileError, PcapReader, reader_for
from pilotfish.core.packet import Packet

ORDERS: tuple[ByteOrder, ...] = ("<", ">")


def read(data: bytes) -> list[Packet]:
    return list(PcapReader(memoryview(data)))


@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize(
    ("nanosecond", "fraction", "expected_ns"),
    [(False, 311_224, 1_084_443_427_311_224_000), (True, 311_224_567, 1_084_443_427_311_224_567)],
)
def test_reads_both_magics_in_both_byte_orders(
    order: ByteOrder, nanosecond: bool, fraction: int, expected_ns: int
) -> None:
    data = pcap_header(order, nanosecond=nanosecond, snaplen=96, link_type=101)
    data += pcap_record(order, 1_084_443_427, fraction, b"\x45\x00", original_length=60)
    reader = PcapReader(memoryview(data))

    assert reader.header.byte_order == order
    assert reader.header.nanosecond is nanosecond
    assert reader.header.snaplen == 96
    assert list(reader) == [
        Packet(timestamp_ns=expected_ns, original_length=60, link_type=101, data=b"\x45\x00")
    ]


def test_link_type_ignores_fcs_bits() -> None:
    # Bit 26 flags an FCS and bits 28-31 give its length; the link type is the low 16 bits.
    data = pcap_header(link_type=0x0400_0000 | (4 << 28) | 1) + pcap_record("<", 0, 0, b"x")
    assert read(data)[0].link_type == 1


def test_reads_a_file_with_no_packets() -> None:
    assert read(pcap_header()) == []


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (pcap_header()[:20], "pcap header needs 24 bytes"),
        (pcap_header(version=(1, 0)), "unsupported pcap version 1.0"),
        (b"\x34\xcd\xb2\xa1" + pcap_header()[4:], "modified (Kuznetzov) pcap"),
        (pcap_header() + b"\0" * 10, "record header at offset 24 is cut short: 10 of 16"),
        (pcap_header() + pcap_record("<", 0, 0, b"abcd")[:-1], "cut short: 3 of 4 bytes"),
    ],
)
def test_rejects_malformed_files(data: bytes, message: str) -> None:
    with pytest.raises(CaptureFileError, match=re.escape(message)):
        read(data)


packets = st.lists(
    st.tuples(
        st.integers(0, 2**32 - 1),  # seconds
        st.integers(0, 999_999_999),  # fraction, reduced below for microsecond files
        st.binary(max_size=64),
        st.integers(0, 2**32 - 1),  # extra bytes on the wire beyond those captured
    ),
    max_size=20,
)


@given(
    order=st.sampled_from(ORDERS),
    nanosecond=st.booleans(),
    link_type=st.integers(0, 0xFFFF),
    packets=packets,
)
def test_round_trip(
    order: ByteOrder,
    nanosecond: bool,
    link_type: int,
    packets: list[tuple[int, int, bytes, int]],
) -> None:
    ticks_per_second = 1_000_000_000 if nanosecond else 1_000_000
    data = pcap_header(order, nanosecond=nanosecond, link_type=link_type)
    expected = []
    for seconds, fraction, payload, extra in packets:
        fraction %= ticks_per_second
        original_length = min(len(payload) + extra, 2**32 - 1)
        data += pcap_record(order, seconds, fraction, payload, original_length)
        ns = seconds * 1_000_000_000 + fraction * (1_000_000_000 // ticks_per_second)
        expected.append(Packet(ns, original_length, link_type, payload))
    assert read(data) == expected


@given(packets=packets, cut=st.integers(min_value=0))
def test_truncated_file_yields_whole_packets_then_raises(
    packets: list[tuple[int, int, bytes, int]], cut: int
) -> None:
    records = [pcap_record("<", s, f % 1_000_000, p) for s, f, p, _ in packets]
    data = pcap_header() + b"".join(records)
    cut %= len(data) + 1
    complete = []
    try:
        for packet in reader_for(data[:cut]):
            complete.append(bytes(packet.data))
    except CaptureFileError:
        pass
    # Whatever was read must be exactly the leading packets, never a partial one.
    assert complete == [p for _, _, p, _ in packets][: len(complete)]
