"""Every field a dissector can produce, by name.

A field name such as ``ip.src`` means the same thing wherever it appears: in
the protocol tree, in the detail view, and in the display filters of a later
phase, which are type checked against this registry.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address


class FieldType(StrEnum):
    """What a field's value is, which decides how it prints and compares."""

    PROTOCOL = "protocol"
    """A layer of the tree rather than a value of its own."""
    UINT = "uint"
    INT = "int"
    """A signed number, as a field that reports -1 for "not known" needs."""
    BOOL = "bool"
    BYTES = "bytes"
    STRING = "string"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ETHERNET = "ethernet"
    """A MAC address, written ``02:00:00:00:00:01``."""
    TIME = "time"
    """Nanoseconds since the Unix epoch."""


type Value = int | bool | bytes | str | IPv4Address | IPv6Address
"""What a field can hold. The type says which of these to expect."""


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    """Dotted name, such as ``ip.src``, starting with its protocol."""
    type: FieldType
    description: str
    """What the detail view calls it, such as ``Source address``."""
    hex: bool = False
    """Whether the number reads better in hexadecimal, as a type, an
    identifier or a checksum does. Wireshark calls this the display base."""
    digits: int = 0
    """How many hexadecimal digits to show, for a field that doesn't fill the
    bytes it is read from. Zero means as many as those bytes hold."""

    @property
    def protocol(self) -> str:
        return self.name.split(".", 1)[0]


class FieldRegistry:
    """The fields of every dissector, by name."""

    def __init__(self) -> None:
        self._fields: dict[str, Field] = {}

    def add(self, *fields: Field) -> None:
        """Register fields. Registering the same field twice is fine."""
        for field in fields:
            registered = self._fields.setdefault(field.name, field)
            if registered != field:
                raise ValueError(
                    f"{field.name} is already registered as "
                    f"{registered.type} ({registered.description})"
                )

    def __getitem__(self, name: str) -> Field:
        try:
            return self._fields[name]
        except KeyError:
            raise KeyError(f"no field named {name!r} is registered") from None

    def __contains__(self, name: object) -> bool:
        return name in self._fields

    def __iter__(self) -> Iterator[Field]:
        """Every field, in name order."""
        return iter(sorted(self._fields.values(), key=lambda field: field.name))

    def __len__(self) -> int:
        return len(self._fields)
