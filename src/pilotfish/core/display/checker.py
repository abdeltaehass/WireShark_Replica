"""The type checker: from what a filter says to what it means.

Three things happen here, all against the field registry:

- every word is settled as a field or a value. ``tcp.port`` is a field
  because the registry has one of that name, and ``80`` beside it is a value
  because it has none;
- every value is read as the kind of the field it is compared with, so the
  ``80`` becomes a number, and ``ip.src == hello`` stops here because
  ``hello`` can't become an address;
- every operator is checked against the kinds it is given. A port can't
  ``contains`` anything, and a number has no bytes to slice.

What comes out is the typed tree, which can't be wrong in any of those ways,
so neither the evaluator nor the code generator checks anything again.
"""

import re
from difflib import get_close_matches

from pilotfish.core.display import syntax, typed
from pilotfish.core.display.errors import DisplayFilterError
from pilotfish.core.display.literals import LiteralError, convert
from pilotfish.core.display.typed import KIND_OF, Kind
from pilotfish.core.dissect import FieldRegistry, FieldType

FLIPPED = {"==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<="}
"""Each comparison as it reads with its two sides swapped."""

FUNCTIONS = ("count", "len", "lower", "upper")

HAS_BYTES = frozenset({Kind.BYTES, Kind.TEXT, Kind.ETHERNET, Kind.IPV4, Kind.IPV6})
"""The kinds a slice can take bytes out of."""

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_-]+)*")


def check(
    expression: syntax.Expression, text: str, fields: FieldRegistry
) -> tuple[typed.Test, frozenset[str]]:
    """The typed tree of a filter, and the names of every field it reads."""
    checker = Checker(text, fields)
    return checker.test(expression), frozenset(checker.names)


class Checker:
    def __init__(self, text: str, fields: FieldRegistry) -> None:
        self._text = text
        self._fields = fields
        self.names: set[str] = set()
        """The names the filter's fields go by in a tree."""

    def test(self, node: syntax.Expression) -> typed.Test:
        """``node`` as something true or false of a packet."""
        match node:
            case syntax.Not(operand=operand):
                return typed.Not(self.test(operand))
            case syntax.And(operands=operands):
                return typed.And(tuple(self.test(each) for each in operands))
            case syntax.Or(operands=operands):
                return typed.Or(tuple(self.test(each) for each in operands))
            case syntax.Xor(left=left, right=right):
                return typed.Xor(self.test(left), self.test(right))
            case syntax.Comparison():
                return self._comparison(node)
            case syntax.Membership():
                return self._membership(node)
            case syntax.Word(text=name):
                # A field on its own asks whether the packet has it.
                if name not in self._fields:
                    raise self._unknown(node)
                return typed.Exists(self._names(name))
            case syntax.String() | syntax.Character():
                raise self._error(
                    f"{self._source(node)} is a value, not a test; compare a field with it", node
                )
            case _:
                # A slice, a function or a mask on its own: does it give anything?
                given = self._operand(node)
                if given.kind is Kind.NUMBER:
                    return typed.NonZero(given)
                return typed.Present(given)

    def _comparison(self, node: syntax.Comparison) -> typed.Test:
        if node.operator == "matches":
            return self._matches(node)
        left_literal = self._literal(node.left)
        right_literal = self._literal(node.right)
        if left_literal is not None and right_literal is not None:
            raise self._no_field(node)
        if left_literal is not None:
            right = self._comparable(node.right, node)
            value = self._convert(left_literal, right, node.right)
            if node.operator == "contains":
                return typed.Compare("contains", self._single(value, node.left), right, node.every)
            return self._against(FLIPPED[node.operator], right, value, node)
        left = self._comparable(node.left, node)
        if right_literal is not None:
            value = self._convert(right_literal, left, node.left)
            if node.operator == "contains":
                value = self._single(value, node.right)
            return self._against(node.operator, left, value, node)
        right = self._comparable(node.right, node)
        left, right = self._paired(left, right, node)
        return typed.Compare(node.operator, left, right, node.every)

    def _comparable(self, side: syntax.Expression, node: syntax.Comparison) -> typed.Operand:
        """One side of a comparison, as its operator needs it."""
        operand = self._operand(side)
        if node.operator != "contains":
            return operand
        return self._searchable(operand, side, node, "contains looks inside")

    def _searchable(
        self, operand: typed.Operand, side: syntax.Expression, node: syntax.Comparison, verb: str
    ) -> typed.Operand:
        """``operand`` as text or bytes, which is all contains and matches work on."""
        if operand.kind is Kind.ETHERNET:
            return typed.AsBytes(operand)
        if operand.kind not in {Kind.TEXT, Kind.BYTES}:
            raise DisplayFilterError(
                f"{verb} text or bytes, and {self._source(side)} is {self._described(operand)}",
                self._text,
                node.operator_span.start,
                node.operator_span.end,
            )
        return operand

    @staticmethod
    def _against(
        operator: str,
        operand: typed.Operand,
        value: typed.Constant | typed.Block,
        node: syntax.Comparison,
    ) -> typed.Test:
        """A comparison of ``operand`` with a literal on its right."""
        if isinstance(value, typed.Constant):
            return typed.Compare(operator, operand, value, node.every)
        # Being equal to a subnet is being inside it, and an address is past
        # a subnet once it is past the subnet's last address.
        inside = ((value.first, value.last),)
        first = typed.Constant(value.first, value.kind)
        last = typed.Constant(value.last, value.kind)
        match operator:
            case "==":
                return typed.InSet(operand, frozenset(), inside, False, node.every)
            case "!=":
                return typed.InSet(operand, frozenset(), inside, True, node.every)
            case ">" | "<=":
                return typed.Compare(operator, operand, last, node.every)
            case _:
                return typed.Compare(operator, operand, first, node.every)

    def _matches(self, node: syntax.Comparison) -> typed.Test:
        if self._literal(node.left) is not None:
            raise self._no_field(node)
        operand = self._searchable(self._operand(node.left), node.left, node, "matches searches")
        if not isinstance(node.right, syntax.String):
            raise self._error(
                'matches takes a regular expression in quotes, such as "^GET"', node.right
            )
        pattern: str | bytes = node.right.value
        try:
            if operand.kind is Kind.TEXT:
                pattern = node.right.value.decode()
            # Wireshark's regular expressions ignore case unless told not to.
            return typed.Matches(operand, re.compile(pattern, re.IGNORECASE), node.every)
        except UnicodeDecodeError:
            raise self._error(
                "these escapes don't spell text: they aren't valid UTF-8", node.right
            ) from None
        except re.error as error:
            raise self._bad_pattern(node.right, pattern, error) from None

    def _bad_pattern(
        self, written: syntax.String, pattern: str | bytes, error: re.error
    ) -> DisplayFilterError:
        """A regular expression that doesn't compile, pointing at where it stops making sense."""
        message = f"this regular expression doesn't compile: {error.msg}"
        if error.pos is None:
            return self._error(message, written)
        # The position counts characters of the pattern, and the string
        # recorded where each of its bytes was written.
        before = pattern[: error.pos]
        index = len(before.encode() if isinstance(before, str) else before)
        if index >= len(written.offsets):
            return self._error(message, written)
        return DisplayFilterError(message, self._text, written.offsets[index])

    def _membership(self, node: syntax.Membership) -> typed.Test:
        if self._literal(node.operand) is not None:
            raise self._no_field(node)
        operand = self._operand(node.operand)
        values: set[typed.Scalar] = set()
        ranges: list[tuple[typed.Scalar, typed.Scalar]] = []
        for member in node.members:
            if isinstance(member, syntax.Interval):
                low = self._member(member.low, operand, node)
                high = self._member(member.high, operand, node)
                first = low.value if isinstance(low, typed.Constant) else low.first
                last = high.value if isinstance(high, typed.Constant) else high.last
                if last < first:  # type: ignore[operator]
                    raise self._error("this range runs backwards, so nothing is in it", member)
                ranges.append((first, last))
                continue
            value = self._member(member, operand, node)
            if isinstance(value, typed.Constant):
                values.add(value.value)
            else:
                ranges.append((value.first, value.last))
        # "not in" is true when none of a field's values are in the set, as
        # != is true when none of them are equal.
        return typed.InSet(operand, frozenset(values), tuple(ranges), node.negated, node.negated)

    def _member(
        self, member: syntax.Expression, operand: typed.Operand, node: syntax.Membership
    ) -> typed.Constant | typed.Block:
        literal = self._literal(member)
        if literal is None:
            raise self._error(
                f"a set holds values, and {self._source(member)} isn't one; "
                "to compare two fields, use ==",
                member,
            )
        return self._convert(literal, operand, node.operand)

    def _operand(self, node: syntax.Expression) -> typed.Operand:
        """``node`` as something that gives values: a field, or made from one."""
        match node:
            case syntax.Word(text=name):
                if name not in self._fields:
                    raise self._unknown(node)
                names = self._names(name)
                field = self._fields[name]
                if field.type is FieldType.PROTOCOL:
                    return typed.LayerBytes(names)
                return typed.FieldValues(names, KIND_OF[field.type])
            case syntax.Slice(operand=inner, ranges=ranges):
                return typed.Sliced(
                    self._sliceable(inner),
                    tuple((each.offset, each.length) for each in ranges),
                )
            case syntax.Call():
                return self._call(node)
            case syntax.BitAnd(left=left, right=right):
                return self._bit_and(left, right, node)
            case syntax.String() | syntax.Character():
                raise self._error(f"{self._source(node)} is a value, where a field is needed", node)
            case _:
                raise self._error(
                    "this is already true or false, so it can't be used as a value; "
                    'join two tests with "and" or "or"',
                    node,
                )

    def _sliceable(self, node: syntax.Expression) -> typed.Operand:
        """The operand of a slice, as bytes."""
        if self._literal(node) is not None:
            raise self._not_a_field(
                node, f"{self._source(node)} is a value; a slice takes bytes out of a field"
            )
        operand = self._operand(node)
        if operand.kind not in HAS_BYTES:
            raise self._error(
                f"{self._source(node)} is {operand.kind}, which has no bytes to slice", node
            )
        return operand if operand.kind is Kind.BYTES else typed.AsBytes(operand)

    def _call(self, node: syntax.Call) -> typed.Operand:
        if node.name not in FUNCTIONS:
            close = get_close_matches(node.name, FUNCTIONS, n=1)
            hint = f'did you mean "{close[0]}"?' if close else f"there are {', '.join(FUNCTIONS)}"
            raise DisplayFilterError(
                f'no function is called "{node.name}"; {hint}',
                self._text,
                node.name_span.start,
                node.name_span.end,
            )
        if len(node.arguments) != 1:
            raise self._error(
                f"{node.name}() takes one field, and this gives it {len(node.arguments)}", node
            )
        argument = node.arguments[0]
        if self._literal(argument) is not None:
            raise self._not_a_field(
                argument, f"{node.name}() takes a field, and {self._source(argument)} is a value"
            )
        if node.name == "count":
            if not isinstance(argument, syntax.Word):
                raise self._error("count() counts a field, so it takes a field's name", argument)
            self._operand(argument)
            return typed.Count(self._names(argument.text))
        operand = self._operand(argument)
        if node.name == "len":
            if operand.kind is Kind.ETHERNET:
                operand = typed.AsBytes(operand)
            if operand.kind not in {Kind.TEXT, Kind.BYTES}:
                raise self._error(
                    f"len() measures text or bytes, and {self._source(argument)} "
                    f"is {self._described(operand)}",
                    argument,
                )
            return typed.Length(operand)
        if operand.kind is not Kind.TEXT:
            raise self._error(
                f"{node.name}() changes the case of text, and {self._source(argument)} "
                f"is {self._described(operand)}",
                argument,
            )
        return typed.Cased(operand, upper=node.name == "upper")

    def _bit_and(
        self, left: syntax.Expression, right: syntax.Expression, node: syntax.BitAnd
    ) -> typed.Operand:
        left_literal, right_literal = self._literal(left), self._literal(right)
        if left_literal is not None and right_literal is not None:
            raise self._no_field(node)
        sides: list[typed.Operand] = []
        for side, literal, other in ((left, left_literal, right), (right, right_literal, left)):
            if literal is not None:
                value = self._convert(literal, typed.Constant(0, Kind.NUMBER), other)
                sides.append(self._single(value, side))
                continue
            operand = self._operand(side)
            if operand.kind is not Kind.NUMBER:
                raise self._error(
                    f"& works on numbers, and {self._source(side)} is {self._described(operand)}",
                    side,
                )
            sides.append(operand)
        return typed.BitAnd(sides[0], sides[1])

    def _paired(
        self, left: typed.Operand, right: typed.Operand, node: syntax.Comparison
    ) -> tuple[typed.Operand, typed.Operand]:
        """Two fields as kinds that can be compared with each other."""
        if left.kind is right.kind:
            return left, right
        # An Ethernet address and six bytes are the same thing written two ways.
        if {left.kind, right.kind} == {Kind.ETHERNET, Kind.BYTES}:
            as_bytes = typed.AsBytes(left if left.kind is Kind.ETHERNET else right)
            return (as_bytes, right) if left.kind is Kind.ETHERNET else (left, as_bytes)
        message = (
            f"{self._source(node.left)} is {self._described(left)} and "
            f"{self._source(node.right)} is {self._described(right)}, so they can't be compared"
        )
        if left.kind is Kind.TEXT and isinstance(node.right, syntax.Word):
            # The word on the right happens to be a field's name. If the text
            # was what was meant, quotes say so.
            message += f'; for the text "{node.right.text}", write it in quotes'
        raise self._error(message, node.right)

    @staticmethod
    def _described(operand: typed.Operand) -> str:
        """What an operand is, in an error's words."""
        return "a protocol" if isinstance(operand, typed.LayerBytes) else operand.kind

    def _convert(
        self, literal: syntax.Literal, operand: typed.Operand, against: syntax.Expression
    ) -> typed.Constant | typed.Block:
        """``literal`` as the kind of the operand it is compared with."""
        subject = self._source(against)
        try:
            value = convert(literal, operand.kind, subject)
        except LiteralError as error:
            start, end = self._within(literal, error)
            raise DisplayFilterError(error.message, self._text, start, end) from None
        if (
            isinstance(value, typed.Constant)
            and operand.kind is Kind.NUMBER
            and isinstance(value.value, int)
            and value.value < 0
            and self._unsigned(against)
        ):
            raise self._error(f"{subject} is never negative", literal)
        return value

    @staticmethod
    def _within(literal: syntax.Literal, error: LiteralError) -> tuple[int, int]:
        """Where in the filter the wrong part of a literal is.

        The error counts from the literal's first character. In a word that
        is so many characters on. In a string it isn't, because of the quote
        and any escapes, but the string recorded where each byte was written.
        """
        whole = (literal.span.start, literal.span.end)
        if error.end is None:
            return whole
        if isinstance(literal, syntax.Word):
            return literal.span.start + error.start, literal.span.start + error.end
        if isinstance(literal, syntax.String) and error.end <= len(literal.offsets):
            return literal.offsets[error.start], literal.offsets[error.end - 1] + 1
        return whole

    def _single(
        self, value: typed.Constant | typed.Block, literal: syntax.Expression
    ) -> typed.Constant:
        if isinstance(value, typed.Block):
            raise self._error("a subnet can only be compared with an address", literal)
        return value

    def _unsigned(self, node: syntax.Expression) -> bool:
        """Whether ``node`` is a field that can't hold a negative number."""
        if not isinstance(node, syntax.Word) or node.text not in self._fields:
            return False
        return self._fields[node.text].type is FieldType.UINT

    def _literal(self, node: syntax.Expression) -> syntax.Literal | None:
        """``node`` if it is a value: quoted, or a word that isn't a field."""
        if isinstance(node, syntax.String | syntax.Character):
            return node
        if isinstance(node, syntax.Word) and node.text not in self._fields:
            return node
        return None

    def _names(self, name: str) -> tuple[str, ...]:
        names = self._fields.found_as(name)
        self.names.update(names)
        return names

    def _no_field(
        self, node: syntax.Comparison | syntax.Membership | syntax.BitAnd
    ) -> DisplayFilterError:
        """Neither side is a field. Usually one was meant to be and is misspelt."""
        first = node.operand if isinstance(node, syntax.Membership) else node.left
        return self._not_a_field(
            first, "nothing here is a field, so this is the same for every packet", node
        )

    def _not_a_field(
        self, node: syntax.Expression, message: str, about: syntax.Expression | None = None
    ) -> DisplayFilterError:
        """A value where a field was needed: a misspelt field, if it reads like a name."""
        if isinstance(node, syntax.Word) and _NAME.fullmatch(node.text):
            return self._unknown(node)
        return self._error(message, about or node)

    def _unknown(self, word: syntax.Word) -> DisplayFilterError:
        if not _NAME.fullmatch(word.text):
            return self._error(
                f'"{word.text}" is a value, not a test; compare a field with it', word
            )
        names = [field.name for field in self._fields]
        close = get_close_matches(word.text, names, n=1, cutoff=0.75)
        if word.text.lower() in self._fields:
            close = [word.text.lower()]
        hint = f'; did you mean "{close[0]}"?' if close else ""
        return self._error(f'no field is named "{word.text}"{hint}', word)

    def _source(self, node: syntax.Expression) -> str:
        """``node`` as the filter wrote it."""
        return self._text[node.span.start : node.span.end]

    def _error(self, message: str, node: syntax.Expression | syntax.Interval) -> DisplayFilterError:
        return DisplayFilterError(message, self._text, node.span.start, node.span.end)
