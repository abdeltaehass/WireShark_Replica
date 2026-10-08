"""``pilotfish filter``: check a display filter and show what it compiles to."""

import sys
from typing import TextIO

from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.display import DisplayFilter, DisplayFilterError, compile_display_filter
from pilotfish.core.display.syntax import dump


def run(expression: str, out: TextIO | None = None) -> Exit:
    """Print how the filter was read, the fields it looks up and the Python it became.

    Nothing is captured or read, so this is the quick way to find out
    whether a filter is right before pointing it at a capture.
    """
    out = out or sys.stdout
    compiled = display_filter(expression)
    if compiled.syntax is None:
        out.write("An empty filter, which every packet passes.\n")
        return Exit.OK
    out.write(f"Parsed as    {dump(compiled.syntax)}\n")
    out.write(f"Looks up     {', '.join(sorted(compiled.names))}\n")
    out.write(f"Compiled to  {compiled.source}\n")
    for name, value in compiled.constants.items():
        out.write(f"  where      {name} = {value!r}\n")
    return Exit.OK


def display_filter(expression: str) -> DisplayFilter:
    """The filter compiled, or the failure that says what is wrong and points at where."""
    try:
        return compile_display_filter(expression)
    except DisplayFilterError as error:
        raise CommandError(
            Exit.INVALID_FILTER,
            f"display filter: {error.message}",
            tuple(error.pointer().splitlines()),
        ) from None
