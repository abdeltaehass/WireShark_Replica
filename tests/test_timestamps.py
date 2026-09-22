import pytest

from pilotfish.core.linktypes import link_type_name
from pilotfish.core.timestamps import format_epoch, format_utc


@pytest.mark.parametrize(
    ("ns", "text"),
    [
        (0, "0.000000000"),
        (1_084_443_427_311_224_000, "1084443427.311224000"),
        (-1, "-0.000000001"),
        (-1_500_000_000, "-1.500000000"),
    ],
)
def test_format_epoch(ns: int, text: str) -> None:
    assert format_epoch(ns) == text


@pytest.mark.parametrize(
    ("ns", "text"),
    [
        # tshark -t ud shows this packet from http.cap as 2004-05-13T10:17:07.311224000Z.
        (1_084_443_427_311_224_000, "2004-05-13 10:17:07.311224000"),
        (-1, "1969-12-31 23:59:59.999999999"),
        (10**30, format_epoch(10**30)),  # past the year 9999
    ],
)
def test_format_utc(ns: int, text: str) -> None:
    assert format_utc(ns) == text


@pytest.mark.parametrize(
    ("link_type", "name"),
    [(0, "NULL"), (1, "ETHERNET"), (12, "RAW"), (276, "LINUX_SLL2"), (9999, "LINKTYPE_9999")],
)
def test_link_type_name(link_type: int, name: str) -> None:
    assert link_type_name(link_type) == name
