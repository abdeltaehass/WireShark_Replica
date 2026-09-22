import contextlib
import gzip
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from builders import (
    block,
    enhanced_packet,
    interface_description,
    pcap_header,
    pcap_record,
    section_header,
    simple_packet,
)
from pilotfish.core.formats import CaptureFile, CaptureFileError, FileFormat, reader_for

PCAP = pcap_header() + pcap_record("<", 1, 2, b"first") + pcap_record("<", 3, 4, b"second")
PCAP_BIG_ENDIAN_NS = pcap_header(">", nanosecond=True) + pcap_record(">", 1, 2, b"x" * 20)
PCAPNG = (
    section_header()
    + interface_description(link_type=1, snaplen=8, tsresol=9, tsoffset=5, name="en0")
    + enhanced_packet("<", 0, 10, b"packet")
    + block("<", 0x00000BAD, b"\0\0\x7e\xd9custom")
    + simple_packet("<", b"simple", 40)
    + section_header(">")
    + interface_description(">", link_type=0, tsresol=0x80 | 16)
    + enhanced_packet(">", 0, 2**40, b"big-endian")
)


@pytest.mark.parametrize(
    ("data", "file_format"), [(PCAP, FileFormat.PCAP), (PCAPNG, FileFormat.PCAPNG)]
)
def test_opens_by_magic_number(tmp_path: Path, data: bytes, file_format: FileFormat) -> None:
    path = tmp_path / "capture.bin"
    path.write_bytes(data)
    with CaptureFile(path) as capture:
        assert capture.format is file_format
        assert len(list(capture)) in {2, 3}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "file is empty"),
        (b"\xd4\xc3", "too short to be a capture file"),
        (gzip.compress(PCAP), "gzip-compressed; decompress it first"),
        (b"GMBU\0\0\0\0", "not a pcap or pcapng file"),
    ],
)
def test_explains_files_it_cannot_read(tmp_path: Path, data: bytes, message: str) -> None:
    path = tmp_path / "capture.bin"
    path.write_bytes(data)
    with pytest.raises(CaptureFileError, match=message):
        CaptureFile(path)


def test_packet_data_outlives_the_file(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(PCAP)
    with CaptureFile(path) as capture:
        packets = list(capture)
    capture.close()  # closing twice is harmless
    assert [bytes(p.data) for p in packets] == [b"first", b"second"]


valid_files = st.sampled_from([PCAP, PCAP_BIG_ENDIAN_NS, PCAPNG])
edits = st.lists(st.tuples(st.integers(min_value=0), st.integers(0, 255)), max_size=6)


@settings(max_examples=500)
@given(data=valid_files, edits=edits, cut=st.integers(min_value=0))
def test_corrupt_files_raise_only_capture_file_error(
    data: bytes, edits: list[tuple[int, int]], cut: int
) -> None:
    """Flipping bytes or cutting the file must never crash the reader."""
    corrupt = bytearray(data)
    for position, value in edits:
        corrupt[position % len(corrupt)] = value
    del corrupt[len(corrupt) - cut % len(corrupt) :]
    try:
        for packet in reader_for(bytes(corrupt)):
            assert packet.captured_length == len(bytes(packet.data))
    except CaptureFileError:
        pass


@given(
    magic=st.sampled_from([b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"]),
    rest=st.binary(max_size=200),
)
def test_random_bytes_after_a_magic_raise_only_capture_file_error(
    magic: bytes, rest: bytes
) -> None:
    with contextlib.suppress(CaptureFileError):
        list(reader_for(magic + rest))
