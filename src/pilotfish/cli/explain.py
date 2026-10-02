"""``pilotfish filter``: check a display filter and show what it compiles to."""

import sys
from typing import TextIO

from pilotfish.core.display import DisplayFilterError, compile_display_filter
from pilotfish.core.display.syntax import dump


def run(expression: str, out: TextIO | None = None) -> int:
    """Print how the filter was read, the fields it looks up and the Python it became.

    Nothing is captured or read, so this is the quick way to find out
    whether a filter is right before pointing it at a capture.
    """
    out = out or sys.stdout
    try:
        compiled = compile_display_filter(expression)
    except DisplayFilterError as error:
        report(error)
        return 1
    if compiled.syntax is None:
        out.write("An empty filter, which every packet passes.\n")
        return 0
    out.write(f"Parsed as    {dump(compiled.syntax)}\n")
    out.write(f"Looks up     {', '.join(sorted(compiled.names))}\n")
    out.write(f"Compiled to  {compiled.source}\n")
    for name, value in compiled.constants.items():
        out.write(f"  where      {name} = {value!r}\n")
    return 0


def report(error: DisplayFilterError, err: TextIO | None = None) -> None:
    """Say what is wrong with a filter, and point at where."""
    err = err or sys.stderr
    err.write(f"pilotfish: display filter: {error.message}\n")
    for line in error.pointer().splitlines():
        err.write(f"    {line}\n")
