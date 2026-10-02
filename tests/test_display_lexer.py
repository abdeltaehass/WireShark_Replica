"""The lexer: where each token of a display filter starts and ends, and what
its quotes spell."""

import pytest

from pilotfish.core.display.errors import DisplayFilterError
from pilotfish.core.display.lexer import Token, TokenKind, tokenize

WORD, STRING, CHARACTER, SYMBOL = (
    TokenKind.WORD,
    TokenKind.STRING,
    TokenKind.CHARACTER,
    TokenKind.SYMBOL,
)


def texts(filter_text: str) -> list[str]:
    """The tokens as they were written, without the END that closes the list."""
    return [token.text for token in tokenize(filter_text)[:-1]]


def kinds(filter_text: str) -> list[TokenKind]:
    return [token.kind for token in tokenize(filter_text)[:-1]]


def test_every_token_knows_where_it_was_written() -> None:
    assert tokenize("tcp.port == 80") == [
        Token(WORD, "tcp.port", 0, 8),
        Token(SYMBOL, "==", 9, 11),
        Token(WORD, "80", 12, 14),
        Token(TokenKind.END, "", 14, 14),
    ]


def test_an_empty_filter_is_only_its_end() -> None:
    assert tokenize("") == [Token(TokenKind.END, "", 0, 0)]
    assert tokenize("  \t\n") == [Token(TokenKind.END, "", 4, 4)]


@pytest.mark.parametrize(
    "word",
    [
        "tcp.port",
        "80",
        "0x1F",
        "-1",
        "+13",
        "00:1a:2b",
        "00-1a-2b",
        "0000.0100.0000",
        "192.168.0.0/16",
        "fe80::1",
        "2001:db8::/32",
        "1700000000.5",
        "2023-11-14T22:13:20Z",
        "www.example.com",
        "tcp.options.sack_perm",
    ],
)
def test_a_value_without_quotes_is_one_word(word: str) -> None:
    # What kind of value it is depends on the field beside it, so the lexer
    # leaves the colons, dots, slashes and dashes where they are.
    assert tokenize(word)[:-1] == [Token(WORD, word, 0, len(word))]


def test_spaces_are_not_needed_between_tokens() -> None:
    assert texts("tcp.port==80&&!udp") == ["tcp.port", "==", "80", "&&", "!", "udp"]
    assert texts("not(tcp)") == ["not", "(", "tcp", ")"]


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("a === b", "==="),
        ("a !== b", "!=="),
        ("a == b", "=="),
        ("a != b", "!="),
        ("a >= b", ">="),
        ("a <= b", "<="),
        ("a > b", ">"),
        ("a < b", "<"),
        ("a ~ b", "~"),
        ("a && b", "&&"),
        ("a || b", "||"),
        ("a ^^ b", "^^"),
        ("a & b", "&"),
    ],
)
def test_the_longest_operator_wins(written: str, expected: str) -> None:
    assert tokenize(written)[1] == Token(SYMBOL, expected, 2, 2 + len(expected))


def test_two_dots_split_the_numbers_of_a_range() -> None:
    assert texts("{80..90}") == ["{", "80", "..", "90", "}"]
    assert texts("{10.0.0.1..10.0.0.9}") == ["{", "10.0.0.1", "..", "10.0.0.9", "}"]
    assert texts("{80 .. 90, 443}") == ["{", "80", "..", "90", ",", "443", "}"]


def test_colons_and_dashes_are_punctuation_inside_a_slice() -> None:
    assert texts("eth.src[0:3]") == ["eth.src", "[", "0", ":", "3", "]"]
    assert texts("eth.src[1-2,-4:]") == ["eth.src", "[", "1", "-", "2", ",", "-", "4", ":", "]"]
    # And words again once the slice is closed.
    assert texts("eth.src[0:3] == 00:1a:2b") == [
        *["eth.src", "[", "0", ":", "3", "]"],
        *["==", "00:1a:2b"],
    ]


def test_keywords_are_words_until_the_parser_says_otherwise() -> None:
    assert kinds("tcp and not udp") == [WORD, WORD, WORD, WORD]


@pytest.mark.parametrize(
    ("written", "spelled"),
    [
        ('"GET"', b"GET"),
        ('""', b""),
        ('"a b"', b"a b"),
        (r'"a\"b"', b'a"b'),
        (r'"a\\b"', b"a\\b"),
        (r'"\n\r\t\0"', b"\n\r\t\x00"),
        (r'"\a\b\f\v\?\'"', b"\a\b\f\v?'"),
        (r'"\x00\xff"', b"\x00\xff"),
        (r'"\101\60"', b"A0"),
        (r'"\7z"', b"\x07z"),
        (r'"\u00e9"', "é".encode()),
        (r'"\U0001F41F"', "\N{FISH}".encode()),
        ('"é"', "é".encode()),
        (r'r"^www\."', rb"^www\."),
        (r'R"\d+"', rb"\d+"),
    ],
)
def test_a_string_spells_bytes(written: str, spelled: bytes) -> None:
    (token,) = tokenize(written)[:-1]
    assert token.kind is STRING
    assert token.text == written
    assert token.value == spelled
    assert (token.start, token.end) == (0, len(written))


def test_a_string_remembers_where_each_byte_was_written() -> None:
    # The quote is at 0, the escape at 2 spells one byte, and é spells two.
    (token,) = tokenize(r'"a\x41é!"')[:-1]
    assert token.value == b"aA\xc3\xa9!"
    assert token.offsets == (1, 2, 6, 6, 7)


@pytest.mark.parametrize(
    ("written", "number"),
    [("'a'", 97), ("'0'", 48), (r"'\n'", 10), (r"'\x7f'", 127), (r"'\''", 39), (r"'\101'", 65)],
)
def test_a_character_stands_for_its_number(written: str, number: int) -> None:
    (token,) = tokenize(written)[:-1]
    assert token.kind is CHARACTER
    assert token.value == bytes([number])


def test_a_word_stops_at_the_first_character_that_cannot_be_in_one() -> None:
    assert texts("ip.src==10.0.0.0/8)") == ["ip.src", "==", "10.0.0.0/8", ")"]
    assert texts("a,b") == ["a", ",", "b"]


@pytest.mark.parametrize(
    ("text", "start", "end"),
    [
        ("tcp.port = 80", 9, 10),
        ("tcp $ udp", 4, 5),
        ('http.host == "open', 13, 14),
        (r'http.host == "a\qb"', 15, 17),
        (r'http.host == "\xZZ"', 14, 18),
        ("frame.number == 'ab'", 16, 18),
        ("eth.src[0;1]", 9, 10),
    ],
)
def test_what_cannot_be_a_token_is_pointed_at(text: str, start: int, end: int) -> None:
    with pytest.raises(DisplayFilterError) as caught:
        tokenize(text)
    assert (caught.value.start, caught.value.end) == (start, end)
    assert caught.value.text == text
