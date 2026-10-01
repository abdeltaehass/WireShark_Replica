"""The dissector framework: how bytes become a tree of named fields.

A dissector reads one protocol's header through a :class:`Reader`, which
records each field's name, type, value and the bytes it came from, and says
which protocol carries the rest through a :class:`Handoff`. The
:class:`Registry` turns the value in that handoff, an EtherType or a port,
into the next dissector. :func:`dissect` runs the chain for one packet and
returns its :class:`ProtocolTree`.

A message that spans packets is decoded in the packet that completes it. The
dissector reading a :class:`Stream` raises :class:`NeedMoreError` until the
whole message is there, and the fields it then decodes point into a
:class:`Source` of reassembled bytes rather than into the packet.

The protocols themselves live in :mod:`pilotfish.core.protocols`; this
package is only the frame at the root of every tree and the data that nothing
claimed.
"""

from pilotfish.core.dissect.buffer import Buffer, Source
from pilotfish.core.dissect.dissector import (
    LINK_TYPE,
    REGISTRY,
    Context,
    Dissector,
    Handoff,
    Registry,
    Stream,
    heuristic,
    register,
)
from pilotfish.core.dissect.engine import MAX_LAYERS, Data, Frame, as_data, dissect
from pilotfish.core.dissect.errors import DeclinedError, MalformedError, NeedMoreError
from pilotfish.core.dissect.fields import Field, FieldRegistry, FieldType, Value
from pilotfish.core.dissect.reader import Reader
from pilotfish.core.dissect.session import Session
from pilotfish.core.dissect.tree import Node, ProtocolTree

__all__ = [
    "LINK_TYPE",
    "MAX_LAYERS",
    "REGISTRY",
    "Buffer",
    "Context",
    "Data",
    "DeclinedError",
    "Dissector",
    "Field",
    "FieldRegistry",
    "FieldType",
    "Frame",
    "Handoff",
    "MalformedError",
    "NeedMoreError",
    "Node",
    "ProtocolTree",
    "Reader",
    "Registry",
    "Session",
    "Source",
    "Stream",
    "Value",
    "as_data",
    "dissect",
    "heuristic",
    "register",
]
