class MalformedError(Exception):
    """A packet doesn't hold what its headers say it does.

    Dissectors never catch this. The engine does, marks the packet and keeps
    whatever was decoded before it, the way Wireshark marks a malformed
    packet instead of throwing the capture away.
    """


class DeclinedError(Exception):
    """Raised by a dissector that was handed a payload it can't decode.

    A port says what a payload usually holds, not what it always holds, and
    the middle of a message that started in an earlier packet doesn't look
    like the start of anything. A dissector that finds itself with one of
    those declines, and the bytes are left as data rather than becoming a
    layer of a protocol they aren't. Decline before reading anything: the
    bytes are handed on as they were.
    """
