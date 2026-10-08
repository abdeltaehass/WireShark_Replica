"""``pilotfish interfaces`` and ``pilotfish -D``: the interfaces to capture on."""

import sys
from typing import TextIO

from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.capture import CaptureError, Device, list_devices


def run(out: TextIO | None = None) -> Exit:
    """Print each interface's name, description, status and addresses."""
    out = out or sys.stdout
    devices = _devices()
    rows = [("Name", "Description", "Status", "Addresses")]
    rows += [
        (device.name, device.description or "", device.status, ", ".join(device.addresses))
        for device in devices
    ]
    widths = [max(len(row[column]) for row in rows) for column in range(3)]
    for *cells, addresses in rows:
        line = "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
        out.write(f"{line}  {addresses}".rstrip() + "\n")
    return Exit.OK


def run_numbered(out: TextIO | None = None) -> Exit:
    """Print the interfaces as tshark -D does: numbered, with their descriptions.

    Scripts written for tshark read the name off each line.
    """
    out = out or sys.stdout
    for number, device in enumerate(_devices(), start=1):
        described = f" ({device.description})" if device.description else ""
        out.write(f"{number}. {device.name}{described}\n")
    return Exit.OK


def _devices() -> list[Device]:
    try:
        return list_devices()
    except CaptureError as error:
        raise CommandError(Exit.CAPTURE_ERROR, str(error)) from None
