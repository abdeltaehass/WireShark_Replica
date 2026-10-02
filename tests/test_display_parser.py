"""The parser: what binds to what.

Each filter is parsed and written back out with every pair of brackets it
implies, which is the quickest way to see whether ``a or b and c`` came out
as it should. The parser knows nothing about fields, so the names here don't
have to be real.
"""

import pytest

from pilotfish.core.display.errors import DisplayFilterError
from pilotfish.core.display.parser import MAX_DEPTH, parse
from pilotfish.core.display.syntax import (
    And,
    Call,
    Comparison,
    Membership,
    Not,
    Range,
    Slice,
    Span,
    String,
    Word,
    depth,
    dump,
)


def shape(text: str) -> str:
    tree = parse(text)
    assert tree is not None
    return dump(tree)


def test_a_filter_with_nothing_in_it_has_no_tree() -> None:
    assert parse("") is None
    assert parse("   ") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # One of each thing.
        ("tcp", "tcp"),
        ("tcp.port == 80", "(== tcp.port 80)"),
        ('http.host == "a b"', '(== http.host "a b")'),
        ("frame.number == 'a'", "(== frame.number 'a')"),
        ("not tcp", "(not tcp)"),
        ("!tcp", "(not tcp)"),
        ("a and b", "(and a b)"),
        ("a && b", "(and a b)"),
        ("a or b", "(or a b)"),
        ("a || b", "(or a b)"),
        ("a xor b", "(xor a b)"),
        ("a ^^ b", "(xor a b)"),
        ('a contains "x"', '(contains a "x")'),
        ('a matches "x"', '(matches a "x")'),
        ('a ~ "x"', '(matches a "x")'),
        ("a & 0x10", "(& a 0x10)"),
        ("len(a)", "(len a)"),
        ("f(a, b)", "(f a b)"),
        ("f()", "(f)"),
        # Every spelling of the six comparisons.
        ("a eq b", "(== a b)"),
        ("a ne b", "(!= a b)"),
        ("a gt b", "(> a b)"),
        ("a lt b", "(< a b)"),
        ("a ge b", "(>= a b)"),
        ("a le b", "(<= a b)"),
        ("a > b", "(> a b)"),
        ("a < b", "(< a b)"),
        ("a >= b", "(>= a b)"),
        ("a <= b", "(<= a b)"),
        # Any value, or every value.
        ("a == b", "(== a b)"),
        ("a any_eq b", "(== a b)"),
        ("a === b", "(=== a b)"),
        ("a all_eq b", "(=== a b)"),
        ("a != b", "(!= a b)"),
        ("a all_ne b", "(!= a b)"),
        ("a !== b", "(!== a b)"),
        ("a any_ne b", "(!== a b)"),
        ("all a > b", "(all > a b)"),
        ("any a > b", "(> a b)"),
        ("all a == b", "(=== a b)"),
        ("any a != b", "(!== a b)"),
        ("all a != b", "(!= a b)"),
        ("all (a > b)", "(all > a b)"),
        # and binds tighter than xor, which binds tighter than or.
        ("a or b and c", "(or a (and b c))"),
        ("a and b or c", "(or (and a b) c)"),
        ("a or b xor c", "(or a (xor b c))"),
        ("a xor b and c", "(xor a (and b c))"),
        ("a and b xor c or d", "(or (xor (and a b) c) d)"),
        # A run of the same one is a single node, however long.
        ("a or b or c", "(or a b c)"),
        ("a and b and c and d", "(and a b c d)"),
        ("a && b and c", "(and a b c)"),
        ("a or b and c and d or e", "(or a (and b c d) e)"),
        ("(a and b) and c", "(and (and a b) c)"),
        ("a xor b xor c", "(xor (xor a b) c)"),
        # not takes the comparison after it and no more.
        ("not a == b", "(not (== a b))"),
        ("not a == b and c", "(and (not (== a b)) c)"),
        ("not a and b", "(and (not a) b)"),
        ("not not a", "(not (not a))"),
        ("!!a", "(not (not a))"),
        ("not (a and b)", "(not (and a b))"),
        ("a and not b or c", "(or (and a (not b)) c)"),
        ("not a in {1}", "(not (in a {1}))"),
        # A comparison binds tighter than any of them, and & tighter still.
        ("a == 1 and b == 2", "(and (== a 1) (== b 2))"),
        ("a == 1 or b == 2 and c == 3", "(or (== a 1) (and (== b 2) (== c 3)))"),
        ("a & 2 == 2", "(== (& a 2) 2)"),
        ("2 == a & 2", "(== 2 (& a 2))"),
        ("a & 2 and b", "(and (& a 2) b)"),
        ("a & b & c", "(& (& a b) c)"),
        # Brackets override all of it and leave nothing behind.
        ("(a)", "a"),
        ("((a))", "a"),
        ("(a or b) and c", "(and (or a b) c)"),
        ("a and (b or c)", "(and a (or b c))"),
        ("(a & 2) == 2", "(== (& a 2) 2)"),
        ("not(a)", "(not a)"),
        ("a and(b)", "(and a b)"),
        # Slices, in each of the ways a range can be written.
        ("a[2]", "(slice a 2)"),
        ("a[2:4]", "(slice a 2:4)"),
        ("a[2-5]", "(slice a 2:4)"),
        ("a[2-2]", "(slice a 2)"),
        ("a[2:]", "(slice a 2:)"),
        ("a[:4]", "(slice a 0:4)"),
        ("a[-4:]", "(slice a -4:)"),
        ("a[-1]", "(slice a -1)"),
        ("a[-4:2]", "(slice a -4:2)"),
        ("a[0,5]", "(slice a 0,5)"),
        ("a[0:2,4:2,7]", "(slice a 0:2,4:2,7)"),
        ("a[ 0 : 3 ]", "(slice a 0:3)"),
        ("a[0:3] == 00:1a:2b", "(== (slice a 0:3) 00:1a:2b)"),
        ("a[0:3] == b[3:3]", "(== (slice a 0:3) (slice b 3:3))"),
        ("a[0][0]", "(slice (slice a 0) 0)"),
        ("len(a)[0]", "(slice (len a) 0)"),
        ("not a[0] == 1", "(not (== (slice a 0) 1))"),
        ("a[0] & 1", "(& (slice a 0) 1)"),
        # Sets: commas, spaces, ranges, and not in.
        ("a in {80}", "(in a {80})"),
        ("a in {80, 443}", "(in a {80 443})"),
        ("a in {80 443}", "(in a {80 443})"),
        ("a in {80,443,8080}", "(in a {80 443 8080})"),
        ("a in {1..5}", "(in a {1..5})"),
        ("a in {1 .. 5}", "(in a {1..5})"),
        ("a in {1..5, 7, 9..11}", "(in a {1..5 7 9..11})"),
        ("a in {1..5 7 9..11}", "(in a {1..5 7 9..11})"),
        ('a in {"x", "y z"}', '(in a {"x" "y z"})'),
        ("a in {10.0.0.0/8, 192.168.0.1}", "(in a {10.0.0.0/8 192.168.0.1})"),
        ("a not in {80, 443}", "(not-in a {80 443})"),
        ("a in {1} and b in {2}", "(and (in a {1}) (in b {2}))"),
        ("a in {1} or not b not in {2}", "(or (in a {1}) (not (not-in b {2})))"),
        # A word that would be an operator elsewhere can still be a value.
        ("a == any", "(== a any)"),
        ("a == all and b", "(and (== a all) b)"),
        # Escapes come back out readable.
        (r'a == "\x00\"\\"', r'(== a "\x00\"\\")'),
    ],
)
def test_the_tree_has_the_shape_the_precedence_gives_it(text: str, expected: str) -> None:
    assert shape(text) == expected


def test_commas_and_spaces_in_a_set_parse_alike() -> None:
    with_commas = parse("tcp.port in {80, 443, 8000..8080}")
    with_spaces = parse("tcp.port in {80  443  8000..8080}")
    assert isinstance(with_commas, Membership)
    assert isinstance(with_spaces, Membership)
    assert dump(with_commas) == dump(with_spaces)
    assert len(with_commas.members) == 3


def test_every_node_knows_the_characters_it_came_from() -> None:
    text = 'not tcp.port == 80 and len(http.host[0:3]) > "a"'
    tree = parse(text)
    assert tree is not None

    def written(span: Span) -> str:
        return text[span.start : span.end]

    assert written(tree.span) == text
    assert isinstance(tree, And)
    negation, longer = tree.operands
    assert isinstance(negation, Not)
    assert written(negation.span) == "not tcp.port == 80"
    equal = negation.operand
    assert isinstance(equal, Comparison)
    assert written(equal.span) == "tcp.port == 80"
    assert written(equal.operator_span) == "=="
    assert isinstance(equal.left, Word)
    assert written(equal.left.span) == "tcp.port"
    assert isinstance(longer, Comparison)
    assert written(longer.operator_span) == ">"
    call = longer.left
    assert isinstance(call, Call)
    assert written(call.span) == "len(http.host[0:3])"
    assert written(call.name_span) == "len"
    (sliced,) = call.arguments
    assert isinstance(sliced, Slice)
    assert written(sliced.span) == "http.host[0:3]"
    assert sliced.ranges == (Range(0, 3),)
    assert isinstance(longer.right, String)
    assert written(longer.right.span) == '"a"'


def test_brackets_leave_the_span_of_what_they_hold() -> None:
    text = "( tcp ) and udp"
    tree = parse(text)
    assert tree is not None
    assert text[tree.span.start : tree.span.end] == "tcp ) and udp"


def test_a_quantifier_covers_the_comparison_it_is_in_front_of() -> None:
    text = "all tcp.port > 1024"
    tree = parse(text)
    assert isinstance(tree, Comparison)
    assert tree.every
    assert (tree.span.start, tree.span.end) == (0, len(text))


class TestDepth:
    """How deep a filter may go, and that a long one isn't a deep one."""

    def test_a_run_of_and_is_one_node_however_long(self) -> None:
        tree = parse(" and ".join(["tcp"] * 5000))
        assert isinstance(tree, And)
        assert len(tree.operands) == 5000
        assert depth(tree) == 2

    def test_depth_counts_the_longest_way_down(self) -> None:
        assert depth(Word("tcp", Span(0, 3))) == 1
        for text, expected in [
            ("tcp", 1),
            ("not tcp", 2),
            ("tcp.port == 80", 2),
            ("a and b or c", 3),
            ("a[0][1][2]", 4),
            ("a & 1 & 2 & 3", 4),
            ("a xor b xor c xor d", 4),
            ("a in {1, 2..3}", 3),
            ("len(a[0]) > 1 and b", 5),
        ]:
            tree = parse(text)
            assert tree is not None
            assert depth(tree) == expected, text

    @pytest.mark.parametrize(
        "text",
        [
            "(" * (MAX_DEPTH - 1) + "tcp" + ")" * (MAX_DEPTH - 1),
            "not " * (MAX_DEPTH - 1) + "tcp",
            "!" * (MAX_DEPTH - 1) + "tcp",
            " xor ".join(["tcp"] * MAX_DEPTH),
            "a" + "[0]" * (MAX_DEPTH - 1),
            "a" + " & 1" * (MAX_DEPTH - 1),
        ],
        ids=["brackets", "not", "!", "xor", "slices", "masks"],
    )
    def test_nesting_up_to_the_limit_parses(self, text: str) -> None:
        tree = parse(text)
        assert tree is not None
        assert depth(tree) <= MAX_DEPTH

    @pytest.mark.parametrize(
        ("text", "start"),
        [
            # Brackets inside brackets are refused where the one too many opens.
            ("(" * MAX_DEPTH + "tcp" + ")" * MAX_DEPTH, MAX_DEPTH),
            ("(" * 5000 + "tcp" + ")" * 5000, MAX_DEPTH),
            ("not " * MAX_DEPTH + "tcp", 4 * MAX_DEPTH),
            ("!" * 5000 + "tcp", MAX_DEPTH),
            ("len(" * 5000 + "a" + ")" * 5000, 4 * MAX_DEPTH),
            # A chain that grows downwards is refused whole.
            (" xor ".join(["tcp"] * (MAX_DEPTH + 1)), 0),
            ("a" + "[0]" * 5000, 0),
            ("a" + " & 1" * 5000, 0),
        ],
        ids=["brackets", "many brackets", "not", "!", "calls", "xor", "slices", "masks"],
    )
    def test_nesting_past_the_limit_is_refused_and_not_a_crash(self, text: str, start: int) -> None:
        with pytest.raises(DisplayFilterError) as caught:
            parse(text)
        assert caught.value.message == f"this filter nests more than {MAX_DEPTH} deep"
        assert caught.value.start == start
