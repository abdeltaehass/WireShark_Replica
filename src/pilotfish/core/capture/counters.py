"""How much traffic each interface has carried, from the kernel's own counters.

Every interface counts the packets and bytes it has received and sent since
it came up. Reading those twice a second apart gives its traffic right now,
which is what the activity graphs beside each interface show. Unlike
capturing, reading the counters needs no access to ``/dev/bpf*``, so the
graphs work before capture permission has been set up.

The counters come from ``sysctl`` with ``NET_RT_IFLIST2``, which returns one
``struct if_msghdr2`` for each interface with an ``if_data64`` inside, whose
counters are 64 bits wide and so never wrap. (``netstat -ib`` reads the same
ones.)
"""

import ctypes
import os
import socket
import struct
import sys
from dataclasses import dataclass

# From <sys/sysctl.h>, <sys/socket.h> and <net/route.h>.
CTL_NET = 4
PF_ROUTE = 17
NET_RT_IFLIST2 = 6
RTM_IFINFO2 = 0x12

# struct if_msghdr2: the message's length, version and type, then after a
# few more fields the interface's index at 12 and its if_data64 at 32.
_HEADER = struct.Struct("=HBB")
_INDEX = struct.Struct("=H")
_INDEX_AT = 12
_DATA_AT = 32
# struct if_data64: received packets at 24, sent at 40, bytes at 64 and 72.
_COUNTER = struct.Struct("=Q")
_RECEIVED_PACKETS = 24
_SENT_PACKETS = 40
_RECEIVED_BYTES = 64
_SENT_BYTES = 72


@dataclass(frozen=True, slots=True)
class Counters:
    """What one interface has carried since it came up."""

    packets_received: int
    packets_sent: int
    bytes_received: int
    bytes_sent: int

    @property
    def packets(self) -> int:
        return self.packets_received + self.packets_sent


def interface_counters() -> dict[str, Counters]:
    """The counters of every interface, by name. Empty off macOS."""
    if sys.platform != "darwin":
        return {}
    return parse(_sysctl_interface_list())


def parse(data: bytes) -> dict[str, Counters]:
    """The counters in a ``NET_RT_IFLIST2`` reply."""
    counters: dict[str, Counters] = {}
    offset = 0
    while len(data) - offset >= _HEADER.size:
        length, _version, kind = _HEADER.unpack_from(data, offset)
        if length == 0 or offset + length > len(data):
            break
        if kind == RTM_IFINFO2 and length >= _DATA_AT + _SENT_BYTES + _COUNTER.size:
            (index,) = _INDEX.unpack_from(data, offset + _INDEX_AT)
            try:
                name = socket.if_indextoname(index)
            except OSError:
                # Gone between the sysctl and now.
                name = None
            if name is not None:
                start = offset + _DATA_AT
                counters[name] = Counters(
                    *(
                        _COUNTER.unpack_from(data, start + at)[0]
                        for at in (_RECEIVED_PACKETS, _SENT_PACKETS, _RECEIVED_BYTES, _SENT_BYTES)
                    )
                )
        offset += length
    return counters


def _sysctl_interface_list() -> bytes:
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 6)(CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0)
    # Ask how much room the reply needs, then for the reply. An interface
    # appearing in between makes the second call fail, so try a few times.
    for _ in range(3):
        size = ctypes.c_size_t()
        if libc.sysctl(mib, len(mib), None, ctypes.byref(size), None, 0) != 0:
            break
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, len(mib), buffer, ctypes.byref(size), None, 0) == 0:
            return buffer.raw[: size.value]
    error = ctypes.get_errno()
    raise OSError(error, f"sysctl NET_RT_IFLIST2: {os.strerror(error)}")
