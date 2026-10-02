"""``pilotfish fields``: list the fields every dissector can produce."""

import sys
from typing import TextIO

from pilotfish.core.dissect import REGISTRY, FieldRegistry


def run(out: TextIO | None = None, registry: FieldRegistry | None = None) -> int:
    """Print each field's name, type and description, in name order.

    These are the names a display filter uses, so this is the list of what
    pilotfish can decode and filter on.
    """
    out = out or sys.stdout
    fields = list(registry if registry is not None else REGISTRY.fields)
    rows: list[tuple[str, str, str]] = [("Name", "Type", "Description")]
    rows += [(field.name, field.type, field.description) for field in fields]
    widths = [max(len(row[column]) for row in rows) for column in range(2)]
    for name, field_type, description in rows:
        out.write(f"{name:<{widths[0]}}  {field_type:<{widths[1]}}  {description}\n")
    return 0
