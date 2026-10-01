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


class NeedMoreError(Exception):
    """Raised by a dissector whose message runs past the bytes it was given.

    TCP carries a stream of bytes, not messages, so a message can stop
    partway through one segment and carry on in the next. A dissector that
    finds the message at the front unfinished raises this, and is handed the
    same bytes again once more have arrived behind them.

    ``count`` is how many more bytes the message needs, when it says. Left
    out, the dissector is asked again as soon as anything arrives. ``to_end``
    is for a message with no length at all, which ends when its connection
    does.

    Raise it only while ``context.can_wait`` says more can come, and before
    recording anything the capture should remember: the layer is thrown away
    and decoded from the start next time.
    """

    def __init__(self, count: int | None = None, *, to_end: bool = False) -> None:
        super().__init__("the message runs past the bytes that have arrived")
        self.count = count
        self.to_end = to_end
