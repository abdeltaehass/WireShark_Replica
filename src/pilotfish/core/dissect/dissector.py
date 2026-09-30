"""Dissectors, and the tables that decide which one decodes what."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar

from pilotfish.core.dissect.buffer import Buffer
from pilotfish.core.dissect.fields import Field, FieldRegistry, FieldType
from pilotfish.core.dissect.reader import Reader
from pilotfish.core.dissect.session import Session
from pilotfish.core.packet import Packet

LINK_TYPE = "linktype"
"""The table that picks the first dissector, by the capture's link type."""


@dataclass(frozen=True, slots=True)
class Handoff:
    """The bytes a dissector didn't decode, and where to look up what will.

    ``key`` is the value the header gave for what comes next: an EtherType,
    an IP protocol number, a port. A dissector that worked out what follows
    some other way, as a heuristic does, names it in ``dissector`` instead.
    """

    table: str
    key: int
    payload: Buffer
    also: tuple[int, ...] = ()
    """More values to try when the first doesn't match, as a transport
    protocol tries both of its ports."""
    heuristics: str = ""
    """The list of dissectors to ask when no value matched at all."""
    dissector: "Dissector | None" = None


@dataclass(slots=True)
class Context:
    """What the dissectors of one packet share."""

    packet: Packet
    number: int = 1
    """Where the packet came in the capture."""
    session: Session = field(default_factory=Session)
    """What the capture has seen so far, for dissectors that track connections."""
    info: str = ""
    """The one-line summary. The innermost dissector that sets it wins."""
    source: IPv4Address | IPv6Address | None = None
    """The address the network layer gave, which a checksum over a pseudo
    header needs. ICMPv6, UDP and TCP all take their checksum over one."""
    destination: IPv4Address | IPv6Address | None = None
    source_port: int = 0
    """The ports the transport layer read, which name the conversation an
    application protocol belongs to."""
    destination_port: int = 0
    truncated: bool = False
    """Whether the capture holds less than the network header said it carries,
    which is why a checksum over the payload can't be checked."""
    in_error: bool = False
    """Whether this is the packet quoted inside an error message rather than
    the packet itself. What it holds shouldn't take over the summary."""

    def describe(self, text: str) -> None:
        """Say what the packet is, for the packet list.

        The innermost dissector that has something to say wins, except
        inside an error message, where the packet that caused the error
        would otherwise describe the error.
        """
        if not self.in_error:
            self.info = text


class Dissector:
    """Decodes one protocol.

    A dissector reads its header through a :class:`Reader`, which records
    every field it reads, and returns a :class:`Handoff` for the bytes it
    didn't decode, or ``None`` when nothing else follows. It never catches
    :class:`MalformedError`: the engine does that, and keeps the fields read
    before the packet ran out.

    Dissectors hold no state between packets. Anything that outlives a packet
    belongs in the context.
    """

    name: ClassVar[str]
    """The protocol's short name, which starts its field names: ``ip``."""
    title: ClassVar[str]
    """What the detail view calls it: ``Internet Protocol Version 4``."""
    fields: ClassVar[tuple[Field, ...]] = ()
    """Every field this dissector can produce."""

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        raise NotImplementedError

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        """Whether this dissector recognises a payload nothing else claimed.

        A heuristic dissector answers this by looking at the first bytes. The
        transport protocols ask every heuristic registered with them when no
        port matches.
        """
        return False

    @property
    def protocol(self) -> Field:
        """The field that stands for the layer itself."""
        return Field(self.name, FieldType.PROTOCOL, self.title)


class Registry:
    """Which dissector decodes what.

    Dissectors are found by value, through tables: the link type of a
    capture, the EtherType in an Ethernet header, the protocol number in an
    IP header, a UDP port. Each table maps a value to the one dissector that
    decodes it.
    """

    def __init__(self, fields: FieldRegistry | None = None) -> None:
        self.fields = fields if fields is not None else FieldRegistry()
        self._tables: dict[str, dict[int, Dissector]] = {}
        self._heuristics: dict[str, list[Dissector]] = {}
        self._dissectors: dict[type[Dissector], Dissector] = {}

    def add(
        self, dissector: type[Dissector], table: str | None = None, keys: tuple[int, ...] = ()
    ) -> Dissector:
        """Register a dissector, and the values that route to it.

        One instance is kept per class, so registering the same dissector in
        several tables doesn't make several of it.
        """
        instance = self._dissectors.get(dissector)
        if instance is None:
            instance = self._dissectors[dissector] = dissector()
            self.fields.add(instance.protocol, *dissector.fields)
        if table is None:
            return instance
        entries = self._tables.setdefault(table, {})
        for key in keys:
            taken = entries.setdefault(key, instance)
            if taken is not instance:
                raise ValueError(f"{table} {key} already goes to {taken.name}")
        return instance

    def find(self, table: str, key: int) -> Dissector | None:
        """The dissector registered for ``key``, if there is one."""
        return self._tables.get(table, {}).get(key)

    def add_heuristic(self, dissector: type[Dissector], under: str) -> Dissector:
        """Register a dissector to be asked about payloads no port claimed."""
        instance = self.add(dissector)
        heuristics = self._heuristics.setdefault(under, [])
        if instance not in heuristics:
            heuristics.append(instance)
        return instance

    def heuristics(self, under: str) -> tuple[Dissector, ...]:
        """The dissectors to ask, in the order they were registered."""
        return tuple(self._heuristics.get(under, ()))

    def guess(self, under: str, payload: Buffer, context: Context) -> Dissector | None:
        """The first heuristic dissector that recognises ``payload``."""
        return next(
            (each for each in self.heuristics(under) if each.looks_like(payload, context)), None
        )

    def table(self, name: str) -> Mapping[int, Dissector]:
        """One routing table, for showing what a build can decode."""
        return dict(self._tables.get(name, {}))

    def tables(self) -> tuple[str, ...]:
        return tuple(sorted(self._tables))

    @property
    def dissectors(self) -> tuple[Dissector, ...]:
        """Every registered dissector, in name order."""
        return tuple(sorted(self._dissectors.values(), key=lambda each: each.name))


REGISTRY = Registry()
"""The registry the engine uses unless it is handed another."""


def heuristic(
    under: str, *, registry: Registry = REGISTRY
) -> Callable[[type[Dissector]], type[Dissector]]:
    """Ask this dissector about payloads that no value in ``under`` claimed.

    It is asked through :meth:`Dissector.looks_like`, and the first one that
    recognises a payload decodes it::

        @heuristic("tcp")
        class Http(Dissector):
            ...
    """

    def decorate(dissector: type[Dissector]) -> type[Dissector]:
        registry.add_heuristic(dissector, under)
        return dissector

    return decorate


def register(
    table: str | None = None, *keys: int, registry: Registry = REGISTRY
) -> Callable[[type[Dissector]], type[Dissector]]:
    """Add a dissector to a registry, and route ``keys`` in ``table`` to it.

    Stack the decorator for a protocol that several values route to::

        @register("udp.port", 53)
        @register("tcp.port", 53)
        class Dns(Dissector):
            ...
    """

    def decorate(dissector: type[Dissector]) -> type[Dissector]:
        registry.add(dissector, table, keys)
        return dissector

    return decorate
