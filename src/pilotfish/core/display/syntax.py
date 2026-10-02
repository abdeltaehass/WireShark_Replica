"""The syntax tree: what a display filter says, before anyone asks what it means.

The parser builds these nodes from the tokens alone. A :class:`Word` here may
turn out to be a field, a number or an address; the type checker decides
that, and builds the tree in :mod:`pilotfish.core.display.typed` from this
one. Every node keeps the span of the filter it was read from, so an error
found later can still point at the right characters.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Span:
    """A run of characters in the filter, ``end`` being one past the last."""

    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Word:
    """Anything written without quotes: ``tcp.port``, ``80``, ``00:1a:2b``."""

    text: str
    span: Span


@dataclass(frozen=True, slots=True)
class String:
    value: bytes
    span: Span
    offsets: tuple[int, ...] = ()
    """Where in the filter each byte of the value was written."""


@dataclass(frozen=True, slots=True)
class Character:
    """One byte in single quotes, standing for its number."""

    value: int
    span: Span


@dataclass(frozen=True, slots=True)
class Range:
    """One range of a slice, as the offset to start at and how many bytes.

    The filter can say it four ways, and they all come down to this:
    ``[2]`` is one byte, ``[2:4]`` is four bytes from the third, ``[2-5]`` is
    the third to the sixth, and ``[2:]`` runs to the end, which is a length
    of ``None``. An offset below zero counts back from the end.
    """

    offset: int
    length: int | None


@dataclass(frozen=True, slots=True)
class Slice:
    """Some of a field's bytes: ``eth.src[0:3]``."""

    operand: "Expression"
    ranges: tuple[Range, ...]
    span: Span


@dataclass(frozen=True, slots=True)
class Call:
    """A function of a field: ``len(http.host)``."""

    name: str
    arguments: tuple["Expression", ...]
    span: Span
    name_span: Span


@dataclass(frozen=True, slots=True)
class BitAnd:
    """The bits two numbers share: ``tcp.flags & 0x12``."""

    left: "Expression"
    right: "Expression"
    span: Span


@dataclass(frozen=True, slots=True)
class Comparison:
    operator: str
    """One of ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``contains`` and
    ``matches``, however the filter spelled it."""
    left: "Expression"
    right: "Expression"
    every: bool
    """Whether every value of a field has to pass, or any one of them. A
    packet has two addresses, so the difference is ``ip.addr != 10.0.0.1``
    meaning neither is, as it does, rather than one of them isn't."""
    span: Span
    operator_span: Span


@dataclass(frozen=True, slots=True)
class Interval:
    """A range of values in a set: ``8000..8080``."""

    low: "Expression"
    high: "Expression"
    span: Span


@dataclass(frozen=True, slots=True)
class Membership:
    """A field against a set of values: ``tcp.port in {80, 443}``."""

    operand: "Expression"
    members: tuple["Expression | Interval", ...]
    negated: bool
    span: Span


@dataclass(frozen=True, slots=True)
class Not:
    operand: "Expression"
    span: Span


@dataclass(frozen=True, slots=True)
class And:
    """Every one of two or more tests.

    A run of ``and`` is one node however long it is, as it is in Python's own
    syntax tree, so a filter with a thousand terms is a wide tree and not a
    deep one.
    """

    operands: tuple["Expression", ...]
    span: Span


@dataclass(frozen=True, slots=True)
class Or:
    """Any one of two or more tests."""

    operands: tuple["Expression", ...]
    span: Span


@dataclass(frozen=True, slots=True)
class Xor:
    left: "Expression"
    right: "Expression"
    span: Span


type Expression = (
    Word
    | String
    | Character
    | Slice
    | Call
    | BitAnd
    | Comparison
    | Membership
    | Not
    | And
    | Or
    | Xor
)

type Literal = Word | String | Character
"""What can be a value. A word can also be a field."""

type Test = Comparison | Membership | Not | And | Or | Xor
"""What is true or false of a packet as it stands."""


def dump(node: "Expression | Interval") -> str:
    """The tree written out with every pair of brackets it implies.

    ``tcp.port == 80 and not dns`` comes out as
    ``(and (== tcp.port 80) (not dns))``, which shows what binds to what
    without anyone having to remember the precedence of ``and``.
    """
    match node:
        case Word(text=text):
            return text
        case String(value=value):
            return '"' + "".join(_printable(byte) for byte in value) + '"'
        case Character(value=value):
            return f"'{_printable(value)}'"
        case Slice(operand=operand, ranges=ranges):
            return f"(slice {dump(operand)} {','.join(_range(each) for each in ranges)})"
        case Call(name=name, arguments=arguments):
            return f"({' '.join([name, *(dump(each) for each in arguments)])})"
        case BitAnd(left=left, right=right):
            return f"(& {dump(left)} {dump(right)})"
        case Comparison(operator=operator, left=left, right=right, every=every):
            return f"({_spelling(operator, every)} {dump(left)} {dump(right)})"
        case Interval(low=low, high=high):
            return f"{dump(low)}..{dump(high)}"
        case Membership(operand=operand, members=members, negated=negated):
            listed = " ".join(dump(each) for each in members)
            return f"({'not-in' if negated else 'in'} {dump(operand)} {{{listed}}})"
        case Not(operand=operand):
            return f"(not {dump(operand)})"
        case And(operands=operands):
            return f"(and {' '.join(dump(each) for each in operands)})"
        case Or(operands=operands):
            return f"(or {' '.join(dump(each) for each in operands)})"
        case Xor(left=left, right=right):
            return f"(xor {dump(left)} {dump(right)})"


def depth(node: "Expression | Interval") -> int:
    """How many nodes deep the tree goes, counted without recursing into it.

    Everything that reads a tree after the parser does recurse, so this is
    what tells the parser whether a tree is safe to hand on.
    """
    deepest = 0
    pending: list[tuple[Expression | Interval, int]] = [(node, 1)]
    while pending:
        each, level = pending.pop()
        deepest = max(deepest, level)
        pending.extend((child, level + 1) for child in _children(each))
    return deepest


def _children(node: "Expression | Interval") -> tuple["Expression | Interval", ...]:
    match node:
        case Word() | String() | Character():
            return ()
        case Slice(operand=operand) | Not(operand=operand):
            return (operand,)
        case Call(arguments=arguments):
            return arguments
        case BitAnd(left=left, right=right) | Comparison(left=left, right=right):
            return (left, right)
        case Xor(left=left, right=right):
            return (left, right)
        case Interval(low=low, high=high):
            return (low, high)
        case Membership(operand=operand, members=members):
            return (operand, *members)
        case And(operands=operands) | Or(operands=operands):
            return operands


def _spelling(operator: str, every: bool) -> str:
    """The operator with its quantifier, said only where it isn't the usual one."""
    usual = operator == "!="
    if every == usual:
        return operator
    if operator in {"==", "!="}:
        return f"{operator}="
    return f"{'all' if every else 'any'} {operator}"


def _range(each: Range) -> str:
    if each.length == 1:
        return str(each.offset)
    return f"{each.offset}:{'' if each.length is None else each.length}"


def _printable(byte: int) -> str:
    if byte in b'"\\':
        return "\\" + chr(byte)
    return chr(byte) if 0x20 <= byte < 0x7F else f"\\x{byte:02x}"
