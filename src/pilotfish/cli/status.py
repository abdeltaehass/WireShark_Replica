"""What pilotfish's exit status means, and the error that sets it.

The numbers are the ones Wireshark's own tools use, so a script written
around tshark reads pilotfish's the same way.
"""

from enum import IntEnum


class Exit(IntEnum):
    OK = 0
    INVALID_OPTION = 1
    """The command line doesn't make sense: an unknown flag, a bad value, or
    two flags that can't go together."""
    INVALID_INTERFACE = 2
    """There is no interface by the name given to -i."""
    INVALID_FILE = 3
    """The file to read is missing, unreadable, or not a capture file."""
    INVALID_FILTER = 4
    """A display filter or a capture filter doesn't compile."""
    NO_PERMISSION = 5
    """Live capture needs access to /dev/bpf*, which this user doesn't have."""
    OPEN_ERROR = 9
    """The file to write can't be created."""
    READ_ERROR = 14
    """The file being read turned out to be cut short or damaged partway."""
    WRITE_ERROR = 15
    """Writing the capture file failed partway, as when the disk fills up."""
    CAPTURE_ERROR = 17
    """Live capture couldn't start, or stopped with an error."""
    INTERRUPTED = 130
    """Ctrl+C, other than the first one during a live capture, which stops it
    cleanly."""
    BROKEN_PIPE = 141
    """Whatever was reading the output went away, as ``| head`` does."""


class CommandError(Exception):
    """Something went wrong that ends the command with ``status``.

    The message is printed after ``pilotfish:``, and any ``details`` on the
    lines after it, indented.
    """

    def __init__(self, status: Exit, message: str, details: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.details = details
