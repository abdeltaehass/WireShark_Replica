"""Cutting a display filter into tokens.

The lexer doesn't decide what a word is. ``80``, ``tcp.port``, ``00:1a:2b``
and ``192.168.0.0/16`` all come out as words, because which of them is a
number, a field, bytes or a subnet depends on what it is compared with, and
only the type checker knows that. What the lexer does settle is where each
token starts and ends, which is what lets every later error point at the
character it is about.
"""

from dataclasses import dataclass
from enum import Enum, auto
from string import ascii_letters, digits, hexdigits, octdigits

from pilotfish.core.display.errors import DisplayFilterError


class TokenKind(Enum):
    WORD = auto()
    """A field name, a keyword, or a value written without quotes."""
    STRING = auto()
    CHARACTER = auto()
    """One byte in single quotes, which stands for its number: ``'a'`` is 97."""
    SYMBOL = auto()
    END = auto()


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    text: str
    """The token as it was written, quotes and all."""
    start: int
    end: int
    value: bytes = b""
    """What a string or a character spells, once its escapes are read. Bytes
    rather than text, because ``"\\xff"`` is one byte and not a character."""
    offsets: tuple[int, ...] = ()
    """Where in the filter each byte of ``value`` was written, so a mistake
    inside a string can be pointed at too."""


# Longest first, so that == isn't read as two of something shorter.
SYMBOLS: tuple[str, ...] = (
    *("===", "!==", "==", "!=", ">=", "<=", "&&", "||", "^^", ".."),
    *(">", "<", "~", "!", "&", "(", ")", "{", "}", "[", "]", ","),
)

SLICE_SYMBOLS = (":", "-", ",", "]")
"""Inside a slice a colon and a dash are punctuation. Outside one they are
part of a word: ``00:1a:2b``, ``fe80::1``, ``-1``."""

WORD_CHARACTERS = frozenset(ascii_letters + digits + "_.:/+-")

LOOKALIKES = {
    "=": 'a single "=" isn\'t an operator; write == to compare',
    "|": 'a single "|" isn\'t an operator; write || or "or"',
    "^": 'a single "^" isn\'t an operator; write ^^ or "xor"',
}

ESCAPES = {
    "\\": b"\\",
    '"': b'"',
    "'": b"'",
    "?": b"?",
    "a": b"\a",
    "b": b"\b",
    "f": b"\f",
    "n": b"\n",
    "r": b"\r",
    "t": b"\t",
    "v": b"\v",
}

# How many hexadecimal digits each escape takes.
HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}


def tokenize(text: str) -> list[Token]:
    """Every token of the filter, in order, with an END token after the last."""
    tokens: list[Token] = []
    position = 0
    in_slice = False
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        token = _slice_token(text, position) if in_slice else _token(text, position)
        if token.kind is TokenKind.SYMBOL and token.text in ("[", "]"):
            in_slice = token.text == "["
        tokens.append(token)
        position = token.end
    tokens.append(Token(TokenKind.END, "", len(text), len(text)))
    return tokens


def _token(text: str, start: int) -> Token:
    character = text[start]
    if character == '"':
        return _string(text, start, raw=False)
    if character in "rR" and text.startswith('"', start + 1):
        return _string(text, start, raw=True)
    if character == "'":
        return _character(text, start)
    for symbol in SYMBOLS:
        if text.startswith(symbol, start):
            return Token(TokenKind.SYMBOL, symbol, start, start + len(symbol))
    if character in WORD_CHARACTERS:
        end = start
        # Two dots are the range in a set, {80..90}, not part of either number.
        while end < len(text) and text[end] in WORD_CHARACTERS and not text.startswith("..", end):
            end += 1
        return Token(TokenKind.WORD, text[start:end], start, end)
    raise DisplayFilterError(
        LOOKALIKES.get(character, f'"{character}" can\'t appear outside quotes'), text, start
    )


def _slice_token(text: str, start: int) -> Token:
    """A token between square brackets: a number, or the punctuation of a range."""
    character = text[start]
    if character in SLICE_SYMBOLS:
        return Token(TokenKind.SYMBOL, character, start, start + 1)
    if character.isascii() and character.isalnum():
        end = start
        while end < len(text) and text[end].isascii() and text[end].isalnum():
            end += 1
        return Token(TokenKind.WORD, text[start:end], start, end)
    raise DisplayFilterError(f'"{character}" can\'t appear in a slice', text, start)


def _string(text: str, start: int, *, raw: bool) -> Token:
    """A double-quoted string. In a raw one, ``r"..."``, a backslash is only
    a backslash, which is how a regular expression is easiest to write."""
    position = start + (2 if raw else 1)
    value = bytearray()
    offsets: list[int] = []
    while position < len(text):
        character = text[position]
        if character == '"':
            end = position + 1
            return Token(
                TokenKind.STRING, text[start:end], start, end, bytes(value), tuple(offsets)
            )
        if character == "\\" and not raw:
            spelled, after = _escape(text, position)
        else:
            spelled, after = character.encode(), position + 1
        offsets.extend([position] * len(spelled))
        value += spelled
        position = after
    raise DisplayFilterError("this quote is never closed", text, start)


def _character(text: str, start: int) -> Token:
    position = start + 1
    if position >= len(text):
        raise DisplayFilterError("this quote is never closed", text, start)
    if text[position] == "'":
        raise DisplayFilterError("there is nothing between these quotes", text, start, position + 1)
    if text[position] == "\\":
        spelled, after = _escape(text, position)
    else:
        spelled, after = text[position].encode(), position + 1
    if after >= len(text):
        raise DisplayFilterError("this quote is never closed", text, start)
    if not text.startswith("'", after):
        raise DisplayFilterError(
            "single quotes hold one character, which stands for its number; "
            "text goes in double quotes",
            text,
            start,
            after,
        )
    if len(spelled) != 1:
        raise DisplayFilterError(
            f'"{text[position:after]}" takes {len(spelled)} bytes, and single quotes hold one',
            text,
            position,
            after,
        )
    return Token(TokenKind.CHARACTER, text[start : after + 1], start, after + 1, spelled)


def _escape(text: str, start: int) -> tuple[bytes, int]:
    """The bytes a backslash escape spells, and where the text carries on."""
    if start + 1 >= len(text):
        raise DisplayFilterError("nothing follows this backslash", text, start)
    letter = text[start + 1]
    if letter in ESCAPES:
        return ESCAPES[letter], start + 2
    if letter in HEX_ESCAPES:
        count = HEX_ESCAPES[letter]
        end = start + 2 + count
        written = text[start + 2 : end]
        if len(written) != count or any(digit not in hexdigits for digit in written):
            raise DisplayFilterError(
                f"\\{letter} is followed by {count} hexadecimal digits", text, start, end
            )
        number = int(written, 16)
        if letter == "x":
            return bytes([number]), end
        if number > 0x10FFFF or 0xD800 <= number <= 0xDFFF:
            raise DisplayFilterError(f"\\{letter}{written} isn't a character", text, start, end)
        return chr(number).encode(), end
    if letter in octdigits:
        end = start + 1
        while end < min(start + 4, len(text)) and text[end] in octdigits:
            end += 1
        number = int(text[start + 1 : end], 8)
        if number > 0xFF:
            raise DisplayFilterError(
                f"{text[start:end]} is {number}, which is more than a byte holds", text, start, end
            )
        return bytes([number]), end
    raise DisplayFilterError(
        f'"\\{letter}" isn\'t an escape; write \\\\ for a backslash, '
        'or put an r before the string: r"..."',
        text,
        start,
        start + 2,
    )
