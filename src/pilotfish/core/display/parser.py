"""Turning the tokens of a display filter into a syntax tree.

This is a Pratt parser, also called precedence climbing. Every operator has
a binding power, and :meth:`Parser._expression` reads an operand and then
keeps taking operators for as long as they bind tighter than the one it was
called for. That one loop replaces the function per precedence level of a
plain recursive descent parser, and the whole grammar is the table below:

======================================  =======
``or``  ``||``                          loosest
``xor``  ``^^``
``and``  ``&&``
``not``  ``!``
``==``  ``!=``  ``<``  ``contains``  ``in``  ...
``&``
``[...]``                               tightest
======================================  =======

So ``not tcp.port == 80 and udp`` is ``(not (tcp.port == 80)) and udp``, and
``a or b and c`` is ``a or (b and c)``, as they are in Wireshark.

The parser checks the shape of a filter and nothing else. Whether
``tcp.port`` is a field, and whether it can be compared with ``80``, is the
type checker's business.
"""

from pilotfish.core.display.errors import DisplayFilterError
from pilotfish.core.display.lexer import Token, TokenKind, tokenize
from pilotfish.core.display.syntax import (
    And,
    BitAnd,
    Call,
    Character,
    Comparison,
    Expression,
    Interval,
    Membership,
    Not,
    Or,
    Range,
    Slice,
    Span,
    String,
    Word,
    Xor,
    depth,
)

OR, XOR, AND, NOT, COMPARE, BIT_AND = 1, 2, 3, 4, 5, 6
"""Binding powers. A higher one holds its operands tighter."""

MAX_DEPTH = 100
"""How deep a filter may nest. Everything after the parser walks the tree by
recursion, so a tree is kept well inside what Python's stack allows. A long
run of ``and`` or ``or`` is one node and doesn't count."""

LOGICAL = {"or": OR, "||": OR, "xor": XOR, "^^": XOR, "and": AND, "&&": AND}
"""The operators that join tests, by how tightly each binds."""

COMPARISONS: dict[str, tuple[str, bool]] = {
    # How it is written: the operator it is, and whether every value of a
    # field has to pass rather than any one of them.
    "==": ("==", False),
    "eq": ("==", False),
    "any_eq": ("==", False),
    "===": ("==", True),
    "all_eq": ("==", True),
    "!=": ("!=", True),
    "ne": ("!=", True),
    "all_ne": ("!=", True),
    "!==": ("!=", False),
    "any_ne": ("!=", False),
    ">": (">", False),
    "gt": (">", False),
    "<": ("<", False),
    "lt": ("<", False),
    ">=": (">=", False),
    "ge": (">=", False),
    "<=": ("<=", False),
    "le": ("<=", False),
    "contains": ("contains", False),
    "matches": ("matches", False),
    "~": ("matches", False),
}

NEGATIONS = frozenset({"not", "!"})
QUANTIFIERS = frozenset({"any", "all"})

KEYWORDS = frozenset(name for name in (*LOGICAL, *COMPARISONS, "not", "in") if name.isalpha())
KEYWORDS |= {"any_eq", "all_eq", "any_ne", "all_ne"}
"""Words that are operators wherever they stand, and so never fields or values."""

CLOSERS = {")": "parenthesis", "}": "brace", "]": "bracket"}


def parse(text: str) -> Expression | None:
    """The syntax tree of a filter, or ``None`` for one with nothing in it."""
    return Parser(text).parse()


class Parser:
    def __init__(self, text: str) -> None:
        self._text = text
        self._tokens = tokenize(text)
        self._index = 0
        self._nesting = 0
        self._too_deep = f"this filter nests more than {MAX_DEPTH} deep"

    def parse(self) -> Expression | None:
        if self._peek().kind is TokenKind.END:
            return None
        expression = self._expression(0)
        left_over = self._peek()
        if left_over.kind is not TokenKind.END:
            raise self._unexpected(left_over)
        if depth(expression) > MAX_DEPTH:
            # Brackets inside brackets are caught as they are read. This is
            # the other way to be deep: a[0][0][0]... or a & b & c & ...
            raise DisplayFilterError(self._too_deep, self._text, 0, len(self._text))
        return expression

    def _expression(self, power: int) -> Expression:
        """An operand, and every operator after it that binds tighter than ``power``."""
        self._nesting += 1
        if self._nesting > MAX_DEPTH:
            raise self._error(self._too_deep, self._peek())
        try:
            return self._operators(self._operand(), power)
        finally:
            self._nesting -= 1

    def _operators(self, left: Expression, power: int) -> Expression:
        """``left`` with every operator after it that binds tighter than ``power``."""
        while True:
            token = self._peek()
            if self._is_symbol(token, "["):
                left = self._slice(left)
            elif self._is_symbol(token, "&") and power < BIT_AND:
                self._advance()
                right = self._expression(BIT_AND)
                left = BitAnd(left, right, _across(left, right))
            elif self._comparison_follows(token) and power < COMPARE:
                left = self._comparison(left)
            elif self._joins(token):
                if power >= self._joins(token):
                    return left
                left = self._joined(left, self._joins(token))
            else:
                return left

    def _joined(self, first: Expression, binding: int) -> Expression:
        """``first`` and what the operator after it joins it to.

        A run of ``and``, or of ``or``, is gathered into one node however
        many tests it joins.
        """
        self._advance()
        if binding == XOR:
            right = self._expression(binding)
            return Xor(first, right, _across(first, right))
        operands = [first, self._expression(binding)]
        while self._joins(self._peek()) == binding:
            self._advance()
            operands.append(self._expression(binding))
        span = _across(first, operands[-1])
        return And(tuple(operands), span) if binding == AND else Or(tuple(operands), span)

    def _joins(self, token: Token) -> int:
        """How tightly ``token`` binds as ``and``, ``or`` or ``xor``, and 0 if it is none."""
        return LOGICAL.get(token.text, 0) if self._is_operator(token) else 0

    def _operand(self) -> Expression:
        """Whatever can stand where a value or a test is expected."""
        token = self._advance()
        if token.kind is TokenKind.END:
            raise DisplayFilterError(
                "the filter ends where a field or a value was expected", self._text, token.start
            )
        if token.kind is TokenKind.STRING:
            return String(token.value, _span(token), token.offsets)
        if token.kind is TokenKind.CHARACTER:
            return Character(token.value[0], _span(token))
        if token.kind is TokenKind.SYMBOL:
            if token.text == "(":
                return self._parenthesised(token)
            if token.text == "!":
                return self._not(token)
            if token.text == "{":
                raise self._error('a set goes after "in": tcp.port in {80, 443}', token)
            if token.text in CLOSERS:
                raise self._error(
                    f"a field or a value is missing before this {CLOSERS[token.text]}", token
                )
            raise self._error(f'"{token.text}" needs a field or a value before it', token)
        if token.text in NEGATIONS:
            return self._not(token)
        if token.text in QUANTIFIERS and self._starts_operand(self._peek()):
            return self._quantified(token)
        if token.text in KEYWORDS:
            raise self._error(f'"{token.text}" needs a field or a value before it', token)
        if self._is_symbol(self._peek(), "("):
            return self._call(token)
        return Word(token.text, _span(token))

    def _parenthesised(self, opening: Token) -> Expression:
        inner = self._expression(0)
        closing = self._peek()
        if not self._is_symbol(closing, ")"):
            if closing.kind is TokenKind.END:
                raise self._error("this parenthesis is never closed", opening)
            raise self._unexpected(closing)
        self._advance()
        return inner

    def _not(self, token: Token) -> Not:
        operand = self._expression(NOT)
        return Not(operand, Span(token.start, operand.span.end))

    def _quantified(self, token: Token) -> Comparison:
        """``all tcp.port > 1024``: a comparison every value has to pass."""
        operand = self._expression(NOT)
        if not isinstance(operand, Comparison):
            raise self._error(
                f'"{token.text}" goes in front of a comparison, '
                f"such as {token.text} tcp.port > 1024",
                token,
            )
        return Comparison(
            operand.operator,
            operand.left,
            operand.right,
            token.text == "all",
            Span(token.start, operand.span.end),
            operand.operator_span,
        )

    def _call(self, name: Token) -> Call:
        opening = self._advance()
        arguments: list[Expression] = []
        while not self._is_symbol(self._peek(), ")"):
            if self._peek().kind is TokenKind.END:
                raise self._error("this parenthesis is never closed", opening)
            if arguments and not self._take(","):
                raise self._error(
                    f"{_quoted(self._peek())} isn't expected here; "
                    "a function's arguments are separated by commas",
                    self._peek(),
                )
            arguments.append(self._expression(COMPARE))
        closing = self._advance()
        return Call(name.text, tuple(arguments), Span(name.start, closing.end), _span(name))

    def _comparison(self, left: Expression) -> Expression:
        token = self._advance()
        if token.text == "not":
            # Only "not in" gets here.
            return self._membership(left, self._advance(), negated=True)
        if token.text == "in":
            return self._membership(left, token, negated=False)
        operator, every = COMPARISONS[token.text]
        right = self._expression(COMPARE)
        return Comparison(operator, left, right, every, _across(left, right), _span(token))

    def _membership(self, operand: Expression, keyword: Token, *, negated: bool) -> Membership:
        opening = self._peek()
        if not self._is_symbol(opening, "{"):
            raise DisplayFilterError(
                '"in" is followed by a set in braces, such as {80, 443}',
                self._text,
                opening.start if opening.kind is not TokenKind.END else keyword.start,
                opening.end if opening.kind is not TokenKind.END else keyword.end,
            )
        self._advance()
        members: list[Expression | Interval] = []
        while True:
            token = self._peek()
            if token.kind is TokenKind.END:
                raise self._error("this brace is never closed", opening)
            if self._is_symbol(token, "}"):
                if not members:
                    raise DisplayFilterError(
                        "an empty set matches nothing; list values in it, such as {80, 443}",
                        self._text,
                        opening.start,
                        token.end,
                    )
                closing = self._advance()
                return Membership(
                    operand, tuple(members), negated, Span(operand.span.start, closing.end)
                )
            members.append(self._member())
            # Wireshark wants commas between the values and older versions
            # wanted spaces, so either will do.
            after = self._peek()
            if self._take(","):
                if self._is_symbol(self._peek(), "}"):
                    raise self._error("a value is missing after this comma", after)
            elif not (
                after.kind is TokenKind.END
                or self._is_symbol(after, "}")
                or self._starts_operand(after)
            ):
                raise self._error(
                    f"{_quoted(after)} isn't expected in a set; its values are separated by commas",
                    after,
                )

    def _member(self) -> Expression | Interval:
        low = self._expression(COMPARE)
        if not self._take(".."):
            return low
        high = self._expression(COMPARE)
        return Interval(low, high, _across(low, high))

    def _slice(self, operand: Expression) -> Slice:
        opening = self._advance()
        ranges = [self._range(opening)]
        while self._take(","):
            ranges.append(self._range(opening))
        closing = self._peek()
        if not self._is_symbol(closing, "]"):
            if closing.kind is TokenKind.END:
                raise self._error("this bracket is never closed", opening)
            raise self._error(f'"{closing.text}" isn\'t expected in a slice', closing)
        self._advance()
        return Slice(operand, tuple(ranges), Span(operand.span.start, closing.end))

    def _range(self, opening: Token) -> Range:
        """One range of a slice: ``2``, ``2:4``, ``2-5``, ``2:`` or ``:4``."""
        first = self._peek()
        if first.kind is TokenKind.END:
            raise self._error("this bracket is never closed", opening)
        if self._take(":"):
            length, last = self._number("how many bytes to take")
            return self._sized(0, length, first, last)
        offset, last = self._offset()
        if self._take(":"):
            if self._peek().kind is not TokenKind.WORD:
                return Range(offset, None)
            length, last = self._number("how many bytes to take")
            return self._sized(offset, length, first, last)
        if self._take("-"):
            end, last = self._number("the last byte to take")
            if end < offset or offset < 0:
                raise DisplayFilterError(
                    f"{offset}-{end} runs backwards; a range is the first byte, "
                    "a dash, then the last",
                    self._text,
                    first.start,
                    last.end,
                )
            return Range(offset, end - offset + 1)
        return Range(offset, 1)

    def _sized(self, offset: int, length: int, first: Token, last: Token) -> Range:
        if length == 0:
            raise DisplayFilterError(
                "this takes no bytes; the number after the colon is how many to take",
                self._text,
                first.start,
                last.end,
            )
        return Range(offset, length)

    def _offset(self) -> tuple[int, Token]:
        """Where a range starts. Below zero counts back from the end."""
        if self._take("-"):
            number, token = self._number("where the range starts")
            return -number, token
        return self._number("where the range starts")

    def _number(self, what: str) -> tuple[int, Token]:
        token = self._peek()
        if token.kind is TokenKind.END:
            raise DisplayFilterError(
                f"the filter ends where a slice says {what}", self._text, token.start
            )
        if token.kind is not TokenKind.WORD:
            raise self._error(f'a slice says {what} here, not "{token.text}"', token)
        if not token.text.isdecimal():
            raise self._error(f'"{token.text}" isn\'t a number; a slice says {what} here', token)
        self._advance()
        return int(token.text), token

    def _comparison_follows(self, token: Token) -> bool:
        if not self._is_operator(token):
            return False
        if token.text == "not":
            following = self._tokens[self._index + 1]
            return following.kind is TokenKind.WORD and following.text == "in"
        return token.text in COMPARISONS or token.text == "in"

    def _starts_operand(self, token: Token) -> bool:
        """Whether ``token`` could begin a value, as opposed to joining two."""
        if token.kind in {TokenKind.STRING, TokenKind.CHARACTER}:
            return True
        if token.kind is TokenKind.WORD:
            return token.text not in KEYWORDS or token.text == "not"
        return token.kind is TokenKind.SYMBOL and token.text in {"(", "!"}

    def _unexpected(self, token: Token) -> DisplayFilterError:
        """A token that nothing was waiting for."""
        if token.text in CLOSERS:
            return self._error(f"this {CLOSERS[token.text]} closes nothing", token)
        if token.kind is TokenKind.WORD and token.text.lower() in KEYWORDS - {token.text}:
            return self._error(
                f'operators are written in lower case: "{token.text.lower()}"', token
            )
        return self._error(
            f'{_quoted(token)} isn\'t expected here; an operator such as == or "and" '
            "is missing before it",
            token,
        )

    def _error(self, message: str, token: Token) -> DisplayFilterError:
        return DisplayFilterError(message, self._text, token.start, token.end)

    @staticmethod
    def _is_symbol(token: Token, text: str) -> bool:
        return token.kind is TokenKind.SYMBOL and token.text == text

    @staticmethod
    def _is_operator(token: Token) -> bool:
        """Whether a token can be an operator: a symbol, or a word that is one."""
        return token.kind in {TokenKind.SYMBOL, TokenKind.WORD}

    def _peek(self) -> Token:
        return self._tokens[self._index]

    def _advance(self) -> Token:
        token = self._tokens[self._index]
        if token.kind is not TokenKind.END:
            self._index += 1
        return token

    def _take(self, symbol: str) -> bool:
        """Step over ``symbol`` if it is next, and say whether it was."""
        if self._is_symbol(self._peek(), symbol):
            self._index += 1
            return True
        return False


def _span(token: Token) -> Span:
    return Span(token.start, token.end)


def _across(left: Expression, right: Expression) -> Span:
    return Span(left.span.start, right.span.end)


def _quoted(token: Token) -> str:
    return token.text if token.kind is TokenKind.STRING else f'"{token.text}"'
