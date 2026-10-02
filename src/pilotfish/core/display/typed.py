"""The typed tree: what a display filter means, once every word is resolved.

The type checker builds this from the syntax tree. Nothing here is a word any
more: a field has become the names to look its values up under and the kind
of value they are, and a literal has become the value it spells, already
converted to that kind. Both the tree walker and the code generator work
from this tree, so neither has to check anything.

An operand stands for a list of values rather than one, because a packet can
hold a field several times: two addresses, a dozen DNS answers. A test says
what has to be true of those lists.
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from pilotfish.core.dissect import FieldType


class Kind(StrEnum):
    """What sort of value an operand gives, in the words an error uses for it."""

    NUMBER = "a number"
    FLAG = "true or false"
    TIME = "a time"
    TEXT = "text"
    BYTES = "bytes"
    ETHERNET = "an Ethernet address"
    IPV4 = "an IPv4 address"
    IPV6 = "an IPv6 address"


KIND_OF = {
    FieldType.UINT: Kind.NUMBER,
    FieldType.INT: Kind.NUMBER,
    FieldType.BOOL: Kind.FLAG,
    FieldType.TIME: Kind.TIME,
    FieldType.STRING: Kind.TEXT,
    FieldType.BYTES: Kind.BYTES,
    # A protocol is its bytes, which is what makes `tcp contains "GET"` work.
    FieldType.PROTOCOL: Kind.BYTES,
    FieldType.ETHERNET: Kind.ETHERNET,
    FieldType.IPV4: Kind.IPV4,
    FieldType.IPV6: Kind.IPV6,
}

type Scalar = int | str | bytes | IPv4Address | IPv6Address
"""One value: a number, flag or time as an ``int``, an Ethernet address as
the text a dissector records it as, and the rest as themselves."""


@dataclass(frozen=True, slots=True)
class Constant:
    value: Scalar
    kind: Kind


@dataclass(frozen=True, slots=True)
class Block:
    """A subnet, as the first and last address in it.

    It is only ever what a literal turns into. ``ip.addr == 10.0.0.0/8``
    becomes a test of whether an address lies between the two.
    """

    first: Scalar
    last: Scalar
    kind: Kind


@dataclass(frozen=True, slots=True)
class FieldValues:
    """Every value of a field in the packet."""

    names: tuple[str, ...]
    """The names to look under: more than one for a field such as
    ``tcp.port``, which is either port."""
    kind: Kind


@dataclass(frozen=True, slots=True)
class LayerBytes:
    """A protocol's bytes: from where its header starts to the end of the packet."""

    names: tuple[str, ...]

    @property
    def kind(self) -> Kind:
        return Kind.BYTES


@dataclass(frozen=True, slots=True)
class AsBytes:
    """An address or a piece of text as the bytes it is made of."""

    operand: "Operand"

    @property
    def kind(self) -> Kind:
        return Kind.BYTES


@dataclass(frozen=True, slots=True)
class Sliced:
    operand: "Operand"
    ranges: tuple[tuple[int, int | None], ...]
    """Each range as an offset and a length, the length ``None`` for a range
    that runs to the end."""

    @property
    def kind(self) -> Kind:
        return Kind.BYTES


@dataclass(frozen=True, slots=True)
class Length:
    """How many bytes each value is."""

    operand: "Operand"

    @property
    def kind(self) -> Kind:
        return Kind.NUMBER


@dataclass(frozen=True, slots=True)
class Count:
    """How many times the field appears in the packet, which can be none."""

    names: tuple[str, ...]

    @property
    def kind(self) -> Kind:
        return Kind.NUMBER


@dataclass(frozen=True, slots=True)
class Cased:
    operand: "Operand"
    upper: bool

    @property
    def kind(self) -> Kind:
        return Kind.TEXT


@dataclass(frozen=True, slots=True)
class BitAnd:
    left: "Operand"
    right: "Operand"

    @property
    def kind(self) -> Kind:
        return Kind.NUMBER


type Operand = (
    Constant | FieldValues | LayerBytes | AsBytes | Sliced | Length | Count | Cased | BitAnd
)


@dataclass(frozen=True, slots=True)
class Exists:
    """The packet has the field, or the protocol, at all."""

    names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Present:
    """The operand gives at least one value: a slice that fits, say."""

    operand: Operand


@dataclass(frozen=True, slots=True)
class NonZero:
    """One of the operand's values isn't zero, as in ``tcp.flags & 0x02``."""

    operand: Operand


@dataclass(frozen=True, slots=True)
class Compare:
    operator: str
    """``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=`` or ``contains``."""
    left: Operand
    right: Operand
    every: bool
    """Whether every pairing of the two sides' values has to pass, and there
    has to be one, rather than any pairing at all."""


@dataclass(frozen=True, slots=True)
class Matches:
    operand: Operand
    pattern: re.Pattern[str] | re.Pattern[bytes]
    every: bool


@dataclass(frozen=True, slots=True)
class InSet:
    """Whether a value is one of ``values`` or inside one of ``ranges``.

    ``negated`` turns that round for each value, and ``every`` asks it of all
    of them, so ``tcp.port not in {80, 443}`` is both: neither port is.
    """

    operand: Operand
    values: frozenset[Scalar]
    ranges: tuple[tuple[Scalar, Scalar], ...]
    negated: bool
    every: bool


@dataclass(frozen=True, slots=True)
class Not:
    test: "Test"


@dataclass(frozen=True, slots=True)
class And:
    tests: tuple["Test", ...]


@dataclass(frozen=True, slots=True)
class Or:
    tests: tuple["Test", ...]


@dataclass(frozen=True, slots=True)
class Xor:
    left: "Test"
    right: "Test"


type Test = Exists | Present | NonZero | Compare | Matches | InSet | Not | And | Or | Xor
