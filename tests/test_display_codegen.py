"""The generated code: what it looks like, and that it never disagrees with
the tree walk it replaces.

A filter is run two ways. Walking the typed tree is the one that is easy to
check by reading, and the function compiled from the same tree is the one
that is used. The property test here generates filters at random and holds
the two to the same answer for every packet.
"""

import re
from ipaddress import IPv4Address

import pytest
from hypothesis import given
from hypothesis import strategies as st

import display
from pilotfish.core.display import DisplayFilter, DisplayFilterError, compile_display_filter
from pilotfish.core.display.parser import MAX_DEPTH
from pilotfish.core.display.runtime import cut, every, gather, layer, mac
from pilotfish.core.dissect import Node, ProtocolTree, Source
from pilotfish.core.dissect.fields import FieldType


def source(text: str) -> str:
    return compile_display_filter(text).source


@pytest.mark.parametrize(
    ("text", "python"),
    [
        ("dns", "lambda found, data: found['dns'] != []"),
        (
            "tcp.port",
            "lambda found, data: found['tcp.srcport'] != [] or found['tcp.dstport'] != []",
        ),
        (
            "ip.ttl == 64",
            "lambda found, data: any((n0.value == 64 for n0 in found['ip.ttl']))",
        ),
        (
            "tcp.port != 80",
            "lambda found, data: _every((n0.value != 80 for n0 in "
            "found['tcp.srcport'] + found['tcp.dstport']))",
        ),
        (
            "not dns and udp",
            "lambda found, data: not found['dns'] != [] and found['udp'] != []",
        ),
        (
            "tcp or udp or arp",
            "lambda found, data: found['tcp'] != [] or found['udp'] != [] or found['arp'] != []",
        ),
        (
            "tcp xor udp",
            "lambda found, data: (found['tcp'] != []) != (found['udp'] != [])",
        ),
        (
            'http.host contains "example"',
            "lambda found, data: any(('example' in n0.value for n0 in found['http.host']))",
        ),
        (
            'frame contains "GET"',
            "lambda found, data: any((b'GET' in _layer(n0, data) for n0 in found['frame']))",
        ),
        (
            "eth.src[0:3] == 00:1a:2b",
            "lambda found, data: any((s1 == b'\\x00\\x1a+' for n0 in found['eth.src'] "
            "for s1 in _cut(_mac(n0.value), ((0, 3),))))",
        ),
        (
            "tcp.flags & 0x12 == 0x12",
            "lambda found, data: any((n0.value & 18 == 18 for n0 in found['tcp.flags']))",
        ),
        (
            "tcp.srcport == tcp.dstport",
            "lambda found, data: any((n0.value == n1.value for n0 in found['tcp.srcport'] "
            "for n1 in found['tcp.dstport']))",
        ),
        (
            "count(ip.addr) == 2",
            "lambda found, data: len(found['ip.src']) + len(found['ip.dst']) == 2",
        ),
        (
            "len(http.host) > 5",
            "lambda found, data: any((len(n0.value.encode()) > 5 for n0 in found['http.host']))",
        ),
        (
            "tcp.srcport in {80, 8000..8080}",
            "lambda found, data: any((v1 == 80 or 8000 <= v1 <= 8080 "
            "for n0 in found['tcp.srcport'] for v1 in (n0.value,)))",
        ),
        (
            "tcp.srcport not in {80}",
            "lambda found, data: _every((not n0.value == 80 for n0 in found['tcp.srcport']))",
        ),
    ],
)
def test_a_filter_becomes_the_python_it_means(text: str, python: str) -> None:
    assert source(text) == python


def test_what_python_cannot_spell_is_kept_beside_the_code() -> None:
    compiled = compile_display_filter(
        'ip.src == 10.0.0.0/8 and tcp.port in {80, 443} and http.host matches "^www"'
    )
    assert compiled.source == (
        "lambda found, data: any((_k0 <= n0.value <= _k1 for n0 in found['ip.src'])) "
        "and any((n1.value in _k2 for n1 in found['tcp.srcport'] + found['tcp.dstport'])) "
        "and any((_k3.search(n2.value) is not None for n2 in found['http.host']))"
    )
    assert compiled.constants == {
        "_k0": IPv4Address("10.0.0.0"),
        "_k1": IPv4Address("10.255.255.255"),
        "_k2": frozenset({80, 443}),
        "_k3": re.compile("^www", re.IGNORECASE),
    }


def test_an_empty_filter_compiles_to_nothing_and_passes_everything() -> None:
    compiled = compile_display_filter("")
    assert compiled.source == ""
    assert compiled.typed is None
    assert compiled.names == frozenset()
    assert display.matched(compiled) == display.walked(compiled) == list(range(1, 12))
    assert repr(compiled) == "DisplayFilter('')"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (" or ".join(["tcp.port == 80"] * 3000), [1, 2, 3, 4, 5]),
        (" and ".join(["tcp"] * 3000), [1, 2, 3, 4, 5]),
        ("tcp.port in {" + ", ".join(str(port) for port in range(5000)) + "}", [1, 2, 3, 4, 5]),
        (" or ".join(["(tcp and not (udp or (arp xor dns)))"] * 500), [1, 2, 3, 4, 5]),
        # As deep as a filter is allowed to nest.
        ("(" * (MAX_DEPTH - 1) + "tcp" + ")" * (MAX_DEPTH - 1), [1, 2, 3, 4, 5]),
        ("not " * (MAX_DEPTH - 1) + "tcp", [6, 7, 8, 9, 10, 11]),
        (" xor ".join(["tcp"] * MAX_DEPTH), []),
        ("eth.src" + "[0:]" * (MAX_DEPTH - 1), list(range(1, 12))),
    ],
    ids=["or", "and", "set", "mixed", "brackets", "not", "xor", "slices"],
)
def test_a_filter_as_long_or_as_deep_as_it_may_be_still_runs(
    text: str, expected: list[int]
) -> None:
    compiled = compile_display_filter(text)
    assert display.matched(compiled) == expected
    assert display.walked(compiled) == expected


def test_nothing_in_a_filter_can_run_as_python() -> None:
    """A filter's text goes into the code as constants, never as code."""
    hostile = "__import__('os').system('true')"
    compiled = compile_display_filter(f'http.host == "{hostile}"')
    assert repr(hostile) in compiled.source
    assert display.matched(compiled) == []
    # A name that looks like code is refused long before it gets that far.
    with pytest.raises(DisplayFilterError):
        compile_display_filter("__import__('os')")
    with pytest.raises(DisplayFilterError):
        compile_display_filter("data.__class__ == 1")


def test_the_generated_code_is_given_only_what_it_calls() -> None:
    compiled = compile_display_filter('len(http.host) > 1 and frame contains "x"')
    function = compiled._compiled
    assert function is not None
    namespace = function.__globals__
    assert set(namespace["__builtins__"]) == {"any", "len"}
    assert {name for name in namespace if not name.startswith("__")} == {
        "_cut",
        "_every",
        "_layer",
        "_mac",
    }


class TestTheRuntime:
    """The handful of functions both ways of running a filter share."""

    def test_gather_finds_every_node_of_the_names_asked_for(self) -> None:
        _, tree = display.decoded()[6]
        found = gather(tree, frozenset({"dns.a", "udp", "tcp"}))
        assert sorted(str(node.value) for node in found["dns.a"]) == ["192.0.2.80", "192.0.2.81"]
        assert [node.name for node in found["udp"]] == ["udp"]
        # A name the packet doesn't have is there, and empty.
        assert found["tcp"] == []
        assert set(found) == {"dns.a", "udp", "tcp"}

    def test_gather_looks_at_any_depth(self) -> None:
        deep = Node("f.deep", "Deep", FieldType.UINT, 0, 1, value=3)
        middle = Node("f.middle", "Middle", FieldType.UINT, 0, 1, value=2, children=[deep])
        layer_node = Node("f", "F", FieldType.PROTOCOL, 0, 1, children=[middle])
        found = gather(ProtocolTree(layers=[layer_node]), frozenset({"f.deep", "f"}))
        assert found == {"f.deep": [deep], "f": [layer_node]}

    @pytest.mark.parametrize(
        ("ranges", "expected"),
        [
            (((0, 3),), (b"abc",)),
            (((2, 1),), (b"c",)),
            (((2, None),), (b"cdef",)),
            (((-2, None),), (b"ef",)),
            (((-1, 1),), (b"f",)),
            (((-6, 2),), (b"ab",)),
            (((0, 6),), (b"abcdef",)),
            (((0, 1), (5, 1)), (b"af",)),
            (((4, 2), (0, 2)), (b"efab",)),
            # Reaching past either end gives nothing, not fewer bytes.
            (((0, 7),), ()),
            (((5, 2),), ()),
            (((6, None),), ()),
            (((6, 1),), ()),
            (((-7, 1),), ()),
            (((0, 1), (9, 1)), ()),
        ],
    )
    def test_cut(self, ranges: tuple[tuple[int, int | None], ...], expected: tuple[bytes]) -> None:
        assert cut(b"abcdef", ranges) == expected

    def test_every_needs_something_to_be_true_of(self) -> None:
        assert every([True, True])
        assert not every([True, False])
        assert not every([])
        # Unlike all(), which is satisfied by nothing at all.
        assert all([])

    def test_every_stops_at_the_first_failure(self) -> None:
        seen = []

        def results() -> object:
            for result in (True, False, True):
                seen.append(result)
                yield result

        assert not every(results())  # type: ignore[arg-type]
        assert seen == [True, False]

    def test_mac(self) -> None:
        assert mac("00:1a:2b:3c:4d:5e") == bytes.fromhex("001a2b3c4d5e")

    def test_a_layer_runs_to_the_end_of_the_packet(self) -> None:
        packet, tree = display.decoded()[3]
        tcp = tree.find("tcp")
        assert tcp is not None
        assert layer(tcp, packet.data) == bytes(packet.data[tcp.offset :])
        assert layer(tcp, packet.data).endswith(display.REQUEST)
        # A memoryview into a capture file works as well as bytes.
        assert layer(tcp, memoryview(bytes(packet.data))) == layer(tcp, packet.data)

    def test_a_layer_decoded_from_reassembled_bytes_is_read_from_them(self) -> None:
        whole = Source("Reassembled TCP", b"0123456789")
        node = Node("http", "HTTP", FieldType.PROTOCOL, 4, 6, source=whole)
        assert layer(node, b"the packet's own bytes") == b"456789"


# What the generated filters are made of. The values are ones the test
# capture holds, or nearly, so that a comparison has a fair chance either way.
NUMBERS = (
    *("frame.number", "frame.len", "tcp.port", "tcp.srcport", "udp.port", "ip.ttl"),
    *("tcp.flags", "tcp.len", "udp.dstport", "dns.count.answers"),
)
FLAGS = ("tcp.flags.syn", "tcp.flags.ack", "dns.flags.response", "ip.flags.df")
ADDRESSES = ("ip.addr", "ip.src", "ip.dst", "dns.a")
TEXTS = ("http.host", "dns.qry.name", "http.request.method", "http.user_agent")
BYTES = ("eth.src", "eth.dst", "udp.payload", "tcp.payload", "frame", "ip", "udp", "ip.src")
PROTOCOLS = ("tcp", "udp", "dns", "http", "ip", "ipv6", "arp", "icmp", "eth", "data")

ORDERINGS = ("==", "!=", "===", "!==", "<", "<=", ">", ">=")
SOME_NUMBERS = st.sampled_from([0, 1, 2, 5, 53, 54, 64, 80, 0x12, 0x18, 1024, 50000, 50001])
SOME_ADDRESSES = st.sampled_from(
    ["192.0.2.1", "192.0.2.2", "192.0.2.53", "192.0.2.80", "10.1.2.3", "198.51.100.7"]
)
SOME_WORDS = st.sampled_from(["www", "example", "GET", "com", "pilotfish", "x", "WWW", ""])
SOME_BYTES = st.sampled_from(["02", "00", "ff", "01", "12", "c0", "0a"])


@st.composite
def numbers(draw: st.DrawFn) -> str:
    field = draw(st.sampled_from(NUMBERS))
    form = draw(st.integers(0, 4))
    if form == 0:
        quantifier = draw(st.sampled_from(["", "any ", "all "]))
        return f"{quantifier}{field} {draw(st.sampled_from(ORDERINGS))} {draw(SOME_NUMBERS)}"
    if form == 1:
        other = draw(st.sampled_from(NUMBERS))
        return f"{field} {draw(st.sampled_from(ORDERINGS))} {other}"
    if form == 2:
        low, high = sorted((draw(SOME_NUMBERS), draw(SOME_NUMBERS)))
        negated = draw(st.sampled_from(["", "not "]))
        return f"{field} {negated}in {{{draw(SOME_NUMBERS)}, {low}..{high}}}"
    if form == 3:
        mask = draw(SOME_NUMBERS)
        return f"{field} & {mask} == {draw(SOME_NUMBERS) & mask}"
    return f"count({field}) {draw(st.sampled_from(ORDERINGS))} {draw(st.integers(0, 3))}"


@st.composite
def addresses(draw: st.DrawFn) -> str:
    field = draw(st.sampled_from(ADDRESSES))
    operator = draw(st.sampled_from(ORDERINGS))
    if draw(st.booleans()):
        return f"{field} {operator} {draw(st.sampled_from(ADDRESSES))}"
    prefix = draw(st.sampled_from(["", "/32", "/24", "/28", "/8", "/0"]))
    return f"{field} {operator} {draw(SOME_ADDRESSES)}{prefix}"


@st.composite
def texts(draw: st.DrawFn) -> str:
    field = draw(st.sampled_from(TEXTS))
    word = draw(SOME_WORDS)
    form = draw(st.integers(0, 3))
    if form == 0:
        return f'{field} {draw(st.sampled_from(ORDERINGS))} "{word}"'
    if form == 1:
        operator = draw(st.sampled_from(["contains", "matches"]))
        function = draw(st.sampled_from(["", "lower", "upper"]))
        return (
            f'{function}({field}) {operator} "{word}"'
            if function
            else (f'{field} {operator} "{word}"')
        )
    if form == 2:
        return f"len({field}) {draw(st.sampled_from(ORDERINGS))} {draw(st.integers(0, 20))}"
    return f'{field} in {{"{word}", "a" .. "x"}}'


@st.composite
def slices(draw: st.DrawFn) -> str:
    field = draw(st.sampled_from(BYTES))
    offset = draw(st.integers(-8, 8))
    length = draw(st.integers(1, 4))
    written = draw(st.sampled_from([f"{offset}", f"{offset}:{length}", f"{offset}:", f":{length}"]))
    form = draw(st.integers(0, 3))
    if form == 0:
        return f"{field}[{written}]"
    if form == 1:
        value = ":".join(draw(st.lists(SOME_BYTES, min_size=2, max_size=4)))
        return f"{field}[{written}] {draw(st.sampled_from(ORDERINGS))} {value}"
    if form == 2:
        other = draw(st.sampled_from(BYTES))
        return f"{field}[{written}] == {other}[{written}]"
    return f'{field}[{written}] contains "{draw(SOME_WORDS)}"'


ATOMS = st.one_of(
    st.sampled_from(PROTOCOLS),
    numbers(),
    addresses(),
    texts(),
    slices(),
    st.builds(
        lambda field, value: f"{field} == {value}", st.sampled_from(FLAGS), st.integers(0, 1)
    ),
    st.builds(
        lambda field, word: f'{field} contains "{word}"', st.sampled_from(BYTES[:-1]), SOME_WORDS
    ),
)

FILTERS = st.recursive(
    ATOMS,
    lambda inner: st.one_of(
        st.builds(lambda a: f"not {a}", inner),
        st.builds(lambda a: f"({a})", inner),
        st.builds(
            lambda a, op, b: f"{a} {op} {b}", inner, st.sampled_from(["and", "or", "xor"]), inner
        ),
    ),
    max_leaves=6,
)


@given(FILTERS)
def test_the_generated_code_always_agrees_with_the_tree_walk(text: str) -> None:
    compiled = compile_display_filter(text)
    assert display.matched(compiled) == display.walked(compiled), text


@given(FILTERS)
def test_a_filter_and_its_negation_split_the_packets(text: str) -> None:
    passed = display.matched(compile_display_filter(text))
    failed = display.matched(compile_display_filter(f"not ({text})"))
    assert sorted(passed + failed) == list(range(1, 12))


def attempt(text: str) -> DisplayFilter | DisplayFilterError:
    """The filter compiled, or the error that refused it."""
    try:
        return compile_display_filter(text)
    except DisplayFilterError as error:
        return error


SYNTAX = 'tcp.port ip.addr == != < > ~ & && || ! ( ) { } [ ] , .. : - / " \' \\ r" 80 0x 1.5 '
SYNTAX += "and or not xor in contains matches any all len count 192.0.2.1/24 00:1a:2b fe80:: é \t"


@given(st.one_of(st.text(), st.text(alphabet=SYNTAX), st.lists(st.sampled_from(SYNTAX.split()))))
def test_anything_at_all_compiles_or_is_refused_with_a_place(typed_in: str | list[str]) -> None:
    """No text can do worse than be refused, and a refusal points into the text."""
    text = typed_in if isinstance(typed_in, str) else " ".join(typed_in)
    outcome = attempt(text)
    if isinstance(outcome, DisplayFilter):
        assert display.matched(outcome) == display.walked(outcome)
        return
    assert outcome.text == text
    assert 0 <= outcome.start < outcome.end
    assert outcome.start <= len(text)
    assert outcome.message
    assert outcome.pointer().count("\n") == 1


@given(FILTERS, st.data())
def test_a_filter_cut_short_or_scrambled_is_still_only_refused(
    text: str, data: st.DataObject
) -> None:
    """What a filter looks like half typed, which is most of the time one is on screen."""
    position = data.draw(st.integers(0, len(text)))
    for damaged in (text[:position], text[position:], text[:position] + text[position + 1 :]):
        outcome = attempt(damaged)
        if isinstance(outcome, DisplayFilter):
            assert display.matched(outcome) == display.walked(outcome)
        else:
            assert 0 <= outcome.start <= len(damaged)
