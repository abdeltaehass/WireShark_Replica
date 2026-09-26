"""Which conversation a packet belongs to, and what has been seen on it.

Wireshark numbers the conversations in a capture as it meets them, and shows
that number as a stream index. Sequence numbers are counted from the start of
their own connection for the same reason: both need somewhere to remember what
came before, which is what these tables are.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

type Endpoint = tuple[IPv4Address | IPv6Address | str, int]
"""One end of a conversation: an address and a port."""


@dataclass(slots=True)
class Conversation[T]:
    index: int
    """The stream number, counting from 0 in the order the capture meets them."""
    initiator: Endpoint
    """The end that sent the first packet, which fixes what "forward" means."""
    state: T


class Conversations[T]:
    """The conversations of one protocol, with a state object for each.

    Both directions of a conversation are the same conversation, so a packet
    finds it whichever way it is going.
    """

    def __init__(self, state: Callable[[], T]) -> None:
        self._state = state
        self._conversations: dict[frozenset[Endpoint], Conversation[T]] = {}

    def find(self, source: Endpoint, destination: Endpoint) -> tuple[Conversation[T], bool]:
        """The conversation between these ends, and whether this packet runs
        the way the first one did."""
        key = frozenset({source, destination})
        conversation = self._conversations.get(key)
        if conversation is None:
            conversation = Conversation(len(self._conversations), source, self._state())
            self._conversations[key] = conversation
        return conversation, source == conversation.initiator

    def __len__(self) -> int:
        return len(self._conversations)


@dataclass(slots=True)
class Counter:
    """A conversation that only needs counting, as UDP's does."""

    packets: int = field(default=0)
