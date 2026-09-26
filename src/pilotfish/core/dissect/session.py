"""What a capture remembers between its packets."""

from collections.abc import Callable
from typing import Any


class Session:
    """State that outlives a packet, such as the connections a capture holds.

    A dissector that has to remember something from one packet to the next
    keeps it here, under a name of its own, so two dissectors can't tread on
    each other and a new capture starts with nothing.
    """

    def __init__(self) -> None:
        self._stores: dict[str, Any] = {}

    def store[T](self, name: str, new: Callable[[], T]) -> T:
        """This dissector's own store, made by ``new`` the first time it's asked for."""
        if name not in self._stores:
            self._stores[name] = new()
        store: T = self._stores[name]
        return store

    def __contains__(self, name: object) -> bool:
        return name in self._stores
