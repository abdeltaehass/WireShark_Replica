"""The packet list's columns, shared by the command line and the desktop app."""

from pathlib import Path

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.columns import DESTINATIONS, SOURCES, address, addresses
from pilotfish.core.dissect import Session, dissect
from pilotfish.core.formats import CaptureFile, CaptureFileError

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURES = sorted(
    capture
    for capture in SAMPLES_DIR.rglob("*")
    if capture.suffix in {".cap", ".ntar", ".pcap", ".pcapng"}
)


@pytest.mark.parametrize(
    "capture", CAPTURES, ids=lambda capture: str(capture.relative_to(SAMPLES_DIR))
)
def test_one_walk_finds_the_addresses_one_lookup_each_would(capture: Path) -> None:
    session = Session()
    try:
        with CaptureFile(capture) as file:
            for number, packet in enumerate(file, start=1):
                tree = dissect(packet, number, session=session)
                expected = (address(tree, SOURCES), address(tree, DESTINATIONS))
                assert addresses(tree) == expected
    except CaptureFileError:
        pass  # the packets before the damage were checked
