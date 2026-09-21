"""Keep the core independent of both front ends.

tshark and Wireshark share one dissection engine, and pilotfish does the same:
``pilotfish.core`` may import only the standard library, its own package and
``cryptography``. Third-party packet libraries belong in tests, as a second
opinion on the decoder, never in the core.
"""

import ast
import sys
from collections.abc import Iterator
from importlib.util import resolve_name
from pathlib import Path

import pytest

import pilotfish.core

CORE_DIR = Path(pilotfish.core.__file__).parent
SRC_DIR = CORE_DIR.parent.parent
ALLOWED_THIRD_PARTY = frozenset({"cryptography"})
FRONT_ENDS = frozenset({"cli", "gui"})


def imported_modules(source: str, package: str) -> Iterator[str]:
    """Yield the absolute name of every module ``source`` may import.

    ``package`` is the package the source belongs to and resolves relative
    imports. For ``from x import y`` both ``x`` and ``x.y`` are yielded, since
    ``y`` may be a submodule.
    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = resolve_name("." * node.level + (node.module or ""), package)
            yield base
            yield from (f"{base}.{alias.name}" for alias in node.names)


def is_allowed_in_core(module: str) -> bool:
    parts = module.split(".")
    if parts[0] == "pilotfish":
        return len(parts) < 2 or parts[1] not in FRONT_ENDS
    return parts[0] in sys.stdlib_module_names or parts[0] in ALLOWED_THIRD_PARTY


def package_of(path: Path) -> str:
    return ".".join(path.relative_to(SRC_DIR).parent.parts)


@pytest.mark.parametrize(
    "path",
    sorted(CORE_DIR.rglob("*.py")),
    ids=lambda path: str(path.relative_to(CORE_DIR)),
)
def test_core_imports_only_stdlib_and_itself(path: Path) -> None:
    modules = imported_modules(path.read_text(encoding="utf-8"), package_of(path))
    forbidden = [module for module in modules if not is_allowed_in_core(module)]
    assert not forbidden, f"core may not import {', '.join(forbidden)}"


@pytest.mark.parametrize(
    ("source", "allowed"),
    [
        ("import struct", True),
        ("from ctypes import CDLL", True),
        ("from cryptography.hazmat.primitives import hashes", True),
        ("from pilotfish import __version__", True),
        ("from pilotfish.core import pcap", True),
        ("from . import pcap", True),
        ("import scapy.all", False),
        ("import dpkt", False),
        ("from pyshark import FileCapture", False),
        ("from PySide6.QtWidgets import QApplication", False),
        ("import pilotfish.gui", False),
        ("from pilotfish import cli", False),
        ("from ..gui import window", False),
    ],
)
def test_import_checker(source: str, allowed: bool) -> None:
    modules = imported_modules(source, "pilotfish.core")
    assert all(is_allowed_in_core(module) for module in modules) is allowed
