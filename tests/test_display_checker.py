"""The type checker: what a filter turns into once its words are resolved.

The messages for filters it refuses are in ``test_display_filters.py``. These
are about what it accepts: that the typed tree says what the filter meant.
"""

import re
from ipaddress import IPv4Address, IPv6Address

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
import toy
from pilotfish.core.display import DisplayFilterError, compile_display_filter, typed
from pilotfish.core.display.typed import Constant, FieldValues, Kind
from pilotfish.core.dissect import REGISTRY, Field, FieldRegistry, FieldType

PORTS = ("tcp.srcport", "tcp.dstport")


def checked(text: str, fields: FieldRegistry | None = None) -> typed.Test:
    test = compile_display_filter(text, fields).typed
    assert test is not None
    return test


def test_a_field_becomes_the_names_to_look_under_and_its_kind() -> None:
    assert checked("ip.ttl == 64") == typed.Compare(
        "==", FieldValues(("ip.ttl",), Kind.NUMBER), Constant(64, Kind.NUMBER), every=False
    )


def test_a_field_that_stands_for_two_looks_under_both() -> None:
    test = checked("tcp.port == 80")
    assert isinstance(test, typed.Compare)
    assert test.left == FieldValues(PORTS, Kind.NUMBER)
    assert compile_display_filter("tcp.port == 80").names == frozenset(PORTS)


@pytest.mark.parametrize(
    ("name", "stands_for"),
    [
        ("eth.addr", ("eth.src", "eth.dst")),
        ("ip.addr", ("ip.src", "ip.dst")),
        ("ipv6.addr", ("ipv6.src", "ipv6.dst")),
        ("tcp.port", ("tcp.srcport", "tcp.dstport")),
        ("udp.port", ("udp.srcport", "udp.dstport")),
    ],
)
def test_the_fields_that_stand_for_two(name: str, stands_for: tuple[str, str]) -> None:
    field = REGISTRY.fields[name]
    assert field.either == stands_for
    assert REGISTRY.fields.found_as(name) == stands_for
    # Both of them are fields of the same type as the name for either.
    assert {REGISTRY.fields[each].type for each in stands_for} == {field.type}


def test_an_ordinary_field_is_found_under_its_own_name() -> None:
    assert REGISTRY.fields.found_as("ip.src") == ("ip.src",)
    with pytest.raises(KeyError):
        REGISTRY.fields.found_as("ip.nothing")


def test_every_name_a_filter_reads_is_collected() -> None:
    compiled = compile_display_filter('ip.addr == 10.0.0.1 and (dns or http.host contains "x")')
    assert compiled.names == {"ip.src", "ip.dst", "dns", "http.host"}


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("frame.number == 0x10", 16),
        ("frame.number == 010", 8),
        ("frame.number == 0b10", 2),
        ("frame.number == +7", 7),
        ("frame.number == 'A'", 65),
        ("tcp.window_size_scalefactor == -1", -1),
        ("tcp.flags.syn == TRUE", True),
        ("tcp.flags.syn == 0", False),
        ("tcp.flags.syn == 5", True),
        ("http.host == example", "example"),
        ('http.host == "ex\\x61mple"', "example"),
        ("eth.src == 00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("eth.src == 001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("ip.src == 192.0.2.1", IPv4Address("192.0.2.1")),
        ("ip.src == 192.0.2.1/32", IPv4Address("192.0.2.1")),
        ("ipv6.src == 2001:DB8::1", IPv6Address("2001:db8::1")),
        ("ipv6.src == ::ffff:192.0.2.1", IPv6Address("::ffff:c000:201")),
        ("udp.payload == 00:1a:2b", b"\x00\x1a\x2b"),
        ("udp.payload == 001a2b", b"\x00\x1a\x2b"),
        ("udp.payload == 0x1a", b"\x1a"),
        ("udp.payload == 26", b"\x1a"),
        ("udp.payload == 1a:", b"\x1a"),
        ('udp.payload == "\\x00a"', b"\x00a"),
        ("udp.payload == 'a'", b"a"),
        ("frame.time_epoch == 1.5", 1_500_000_000),
        ("frame.time_epoch == -0.000000001", -1),
        ("frame.time_epoch == 1700000000", 1_700_000_000_000_000_000),
        ('frame.time_epoch == "2023-11-14 22:13:20"', 1_700_000_000_000_000_000),
        ('frame.time_epoch == "2023-11-14T22:13:20.5Z"', 1_700_000_000_500_000_000),
        ('frame.time_epoch == "2023-11-14 22:13:20 UTC"', 1_700_000_000_000_000_000),
        ('frame.time_epoch == "2023-11-14 17:13:20-05:00"', 1_700_000_000_000_000_000),
        ('frame.time_epoch == "2023-11-15 03:43:20+0530"', 1_700_000_000_000_000_000),
        ('frame.time_epoch == " 2023-11-14 22:13:20 "', 1_700_000_000_000_000_000),
        ('frame.time_epoch == "2024-02-29 23:59:59.5 UTC"', 1_709_251_199_500_000_000),
    ],
)
def test_a_literal_is_read_as_the_kind_of_its_field(text: str, value: object) -> None:
    test = checked(text)
    assert isinstance(test, typed.Compare)
    assert isinstance(test.right, Constant)
    assert test.right.value == value
    assert type(test.right.value) is type(value)
    assert test.right.kind is test.left.kind


def test_a_protocol_is_its_bytes() -> None:
    test = checked('tcp contains "GET"')
    assert test == typed.Compare(
        "contains", typed.LayerBytes(("tcp",)), Constant(b"GET", Kind.BYTES), every=False
    )


def test_a_subnet_is_the_range_of_addresses_in_it() -> None:
    inside = ((IPv4Address("192.168.0.0"), IPv4Address("192.168.255.255")),)
    addresses = FieldValues(("ip.src", "ip.dst"), Kind.IPV4)
    assert checked("ip.addr == 192.168.0.0/16") == typed.InSet(
        addresses, frozenset(), inside, negated=False, every=False
    )
    # Neither address is in it, which is what != means everywhere else too.
    assert checked("ip.addr != 192.168.0.0/16") == typed.InSet(
        addresses, frozenset(), inside, negated=True, every=True
    )


def test_the_host_bits_of_a_subnet_are_dropped() -> None:
    assert checked("ip.src == 192.168.77.5/16") == checked("ip.src == 192.168.0.0/16")
    assert checked("ipv6.src == fe80::1/10") == checked("ipv6.src == fe80::/10")


@pytest.mark.parametrize(
    ("text", "operator", "address"),
    [
        # Past a subnet is past its last address, and before it is before its first.
        ("ip.src > 10.0.0.0/8", ">", "10.255.255.255"),
        ("ip.src >= 10.0.0.0/8", ">=", "10.0.0.0"),
        ("ip.src < 10.0.0.0/8", "<", "10.0.0.0"),
        ("ip.src <= 10.0.0.0/8", "<=", "10.255.255.255"),
        # The same, read from the other side.
        ("10.0.0.0/8 < ip.src", ">", "10.255.255.255"),
        ("10.0.0.0/8 >= ip.src", "<=", "10.255.255.255"),
    ],
)
def test_an_address_is_ordered_against_the_ends_of_a_subnet(
    text: str, operator: str, address: str
) -> None:
    assert checked(text) == typed.Compare(
        operator,
        FieldValues(("ip.src",), Kind.IPV4),
        Constant(IPv4Address(address), Kind.IPV4),
        every=False,
    )


def test_a_literal_on_the_left_turns_the_comparison_round() -> None:
    assert checked("1024 <= tcp.srcport") == checked("tcp.srcport >= 1024")
    assert checked("80 == tcp.srcport") == checked("tcp.srcport == 80")
    assert checked("80 != tcp.srcport") == checked("tcp.srcport != 80")


def test_a_set_keeps_values_and_ranges_apart() -> None:
    test = checked("tcp.srcport in {80, 443, 8000..8080, 22}")
    assert test == typed.InSet(
        FieldValues(("tcp.srcport",), Kind.NUMBER),
        frozenset({80, 443, 22}),
        ((8000, 8080),),
        negated=False,
        every=False,
    )


def test_a_subnet_in_a_set_is_a_range() -> None:
    test = checked("ip.src in {10.0.0.0/8, 192.0.2.1, 192.0.2.5 .. 192.0.2.9}")
    assert isinstance(test, typed.InSet)
    assert test.values == {IPv4Address("192.0.2.1")}
    assert test.ranges == (
        (IPv4Address("10.0.0.0"), IPv4Address("10.255.255.255")),
        (IPv4Address("192.0.2.5"), IPv4Address("192.0.2.9")),
    )


def test_not_in_asks_it_of_every_value() -> None:
    test = checked("tcp.port not in {80}")
    assert isinstance(test, typed.InSet)
    assert (test.negated, test.every) == (True, True)


@pytest.mark.parametrize(
    ("text", "every"),
    [
        ("tcp.port == 80", False),
        ("tcp.port === 80", True),
        ("tcp.port != 80", True),
        ("tcp.port !== 80", False),
        ("tcp.port > 80", False),
        ("all tcp.port > 80", True),
        ("any tcp.port != 80", False),
    ],
)
def test_which_comparisons_ask_about_every_value(text: str, every: bool) -> None:
    test = checked(text)
    assert isinstance(test, typed.Compare)
    assert test.every is every


def test_a_slice_of_an_address_is_taken_from_its_bytes() -> None:
    test = checked("eth.src[0:3] == 00:1a:2b")
    assert test == typed.Compare(
        "==",
        typed.Sliced(typed.AsBytes(FieldValues(("eth.src",), Kind.ETHERNET)), ((0, 3),)),
        Constant(b"\x00\x1a\x2b", Kind.BYTES),
        every=False,
    )


def test_bytes_are_sliced_as_they_are() -> None:
    test = checked("udp.payload[-2:] == 00:00")
    assert isinstance(test, typed.Compare)
    assert test.left == typed.Sliced(FieldValues(("udp.payload",), Kind.BYTES), ((-2, None),))


def test_an_ethernet_address_meets_bytes_as_bytes() -> None:
    test = checked("eth.dst == frame[0:6]")
    assert isinstance(test, typed.Compare)
    assert test.left == typed.AsBytes(FieldValues(("eth.dst",), Kind.ETHERNET))
    assert test.left.kind is test.right.kind is Kind.BYTES
    # Two addresses are compared as they are.
    both = checked("eth.src == eth.dst")
    assert isinstance(both, typed.Compare)
    assert both.left.kind is both.right.kind is Kind.ETHERNET


def test_matches_compiles_its_pattern_once_and_ignores_case() -> None:
    test = checked('http.host matches "^www"')
    assert isinstance(test, typed.Matches)
    assert test.pattern.pattern == "^www"
    assert test.pattern.flags & re.IGNORECASE
    # Over bytes the pattern is bytes, so it can hold any byte at all.
    over_bytes = checked('tcp.payload matches "\\xff+"')
    assert isinstance(over_bytes, typed.Matches)
    assert over_bytes.pattern.pattern == b"\xff+"


def test_a_field_alone_asks_whether_it_is_there() -> None:
    assert checked("dns") == typed.Exists(("dns",))
    assert checked("tcp.port") == typed.Exists(PORTS)
    # A flag too: this is every TCP packet, not only the ones with it set.
    assert checked("tcp.flags.syn") == typed.Exists(("tcp.flags.syn",))


def test_a_mask_alone_asks_whether_any_bit_is_left() -> None:
    assert checked("tcp.flags & 0x02") == typed.NonZero(
        typed.BitAnd(FieldValues(("tcp.flags",), Kind.NUMBER), Constant(2, Kind.NUMBER))
    )


def test_a_slice_alone_asks_whether_it_fits() -> None:
    assert checked("udp.payload[8:4]") == typed.Present(
        typed.Sliced(FieldValues(("udp.payload",), Kind.BYTES), ((8, 4),))
    )


def test_the_functions() -> None:
    host = FieldValues(("http.host",), Kind.TEXT)
    assert checked("len(http.host) > 5") == typed.Compare(
        ">", typed.Length(host), Constant(5, Kind.NUMBER), every=False
    )
    assert checked('upper(http.host) == "X"') == typed.Compare(
        "==", typed.Cased(host, upper=True), Constant("X", Kind.TEXT), every=False
    )
    assert checked("count(ip.addr) == 2") == typed.Compare(
        "==", typed.Count(("ip.src", "ip.dst")), Constant(2, Kind.NUMBER), every=False
    )


def test_the_checker_only_knows_the_fields_it_is_given() -> None:
    """A filter is checked against a registry, not against a fixed list."""
    fields = toy.REGISTRY.fields
    test = checked("toy.source == 10.0.0.0/8 and toy.label contains fish", fields)
    assert isinstance(test, typed.And)
    assert compile_display_filter("toy.hardware[0:3] == 02:00:00", fields).names == {"toy.hardware"}
    with pytest.raises(DisplayFilterError, match=re.escape('no field is named "tcp.port"')):
        compile_display_filter("tcp.port == 80", fields)
    with pytest.raises(DisplayFilterError, match=re.escape("toy.version is a number")):
        compile_display_filter("toy.version == one", fields)


def test_every_type_of_field_has_a_kind() -> None:
    assert set(typed.KIND_OF) == set(FieldType)
    fields = FieldRegistry()
    fields.add(*(Field(f"t.{each.value}", each, each.value) for each in FieldType))
    for each in FieldType:
        assert compile_display_filter(f"t.{each.value}", fields).typed == typed.Exists(
            (f"t.{each.value}",)
        )


def test_a_signed_field_can_be_negative_and_an_unsigned_one_cannot() -> None:
    assert isinstance(checked("tcp.window_size_scalefactor < -1"), typed.Compare)
    with pytest.raises(DisplayFilterError, match=re.escape("tcp.srcport is never negative")):
        compile_display_filter("tcp.srcport > -1")
