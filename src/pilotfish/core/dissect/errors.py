class MalformedError(Exception):
    """A packet doesn't hold what its headers say it does.

    Dissectors never catch this. The engine does, marks the packet and keeps
    whatever was decoded before it, the way Wireshark marks a malformed
    packet instead of throwing the capture away.
    """
