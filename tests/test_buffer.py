import pytest
from hypothesis import given
from hypothesis import strategies as st

from pilotfish.core.dissect import Buffer, MalformedError


def test_reads_move_the_cursor() -> None:
    buffer = Buffer(bytes(range(8)))
    assert buffer.uint(1) == 0x00
    assert buffer.uint(2) == 0x0102
    assert buffer.uint(4) == 0x03040506
    assert buffer.offset == 7
    assert buffer.remaining == 1
    assert not buffer.at_end
    assert bytes(buffer.read(1)) == b"\x07"
    assert buffer.at_end


def test_little_endian() -> None:
    assert Buffer(b"\x02\x00\x00\x00").uint(4, little=True) == 2


def test_reading_past_the_end_is_malformed() -> None:
    buffer = Buffer(b"\x01\x02")
    with pytest.raises(MalformedError, match=r"^needed 4 bytes at offset 0, but the packet has 2$"):
        buffer.read(4)
    # The failed read left the cursor alone.
    assert buffer.remaining == 2


def test_a_named_read_says_which_field_ran_out() -> None:
    buffer = Buffer(b"\x01\x02")
    buffer.skip(1)
    with pytest.raises(MalformedError, match=r"^ip.src needs 4 bytes at offset 1"):
        buffer.uint(4, name="ip.src")


def test_a_negative_count_is_malformed() -> None:
    # A header whose lengths don't add up can work out to a negative length.
    with pytest.raises(MalformedError, match=r"^ip.len needs -1 bytes, which is not a length$"):
        Buffer(b"\x01").read(-1, "ip.len")


def test_offsets_are_where_the_bytes_are_in_the_packet() -> None:
    packet = Buffer(bytes(range(20)))
    packet.skip(14)
    payload = packet.rest()
    assert payload.offset == 14
    assert payload.remaining == 6
    assert payload.uint(1) == 14
    assert payload.offset == 15
    assert packet.at_end


def test_take_hands_over_part_of_the_packet() -> None:
    packet = Buffer(bytes(range(10)))
    header = packet.take(4)
    assert header.remaining == 4
    assert packet.offset == 4
    with pytest.raises(MalformedError):
        header.read(5)


def test_repr_says_where_it_is() -> None:
    assert repr(Buffer(b"abc", start=10)) == "Buffer(offset=10, remaining=3)"


@given(data=st.binary(max_size=64), reads=st.lists(st.integers(-2, 20), max_size=20))
def test_reads_only_ever_raise_malformed(data: bytes, reads: list[int]) -> None:
    buffer = Buffer(data)
    for count in reads:
        try:
            chunk = buffer.read(count)
        except MalformedError:
            continue
        assert len(chunk) == count
    assert buffer.offset + buffer.remaining == len(data)
