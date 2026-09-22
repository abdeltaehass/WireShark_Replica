"""``pilotfish interfaces``: list the interfaces pilotfish can capture on."""

import sys
from typing import TextIO

from pilotfish.core.capture import CaptureError, list_devices


def run(out: TextIO | None = None) -> int:
    """Print each interface's name, description, status and addresses."""
    out = out or sys.stdout
    try:
        devices = list_devices()
    except CaptureError as error:
        print(f"pilotfish: {error}", file=sys.stderr)
        return 1
    rows = [("Name", "Description", "Status", "Addresses")]
    rows += [
        (device.name, device.description or "", device.status, ", ".join(device.addresses))
        for device in devices
    ]
    widths = [max(len(row[column]) for row in rows) for column in range(3)]
    for *cells, addresses in rows:
        line = "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
        out.write(f"{line}  {addresses}".rstrip() + "\n")
    return 0
