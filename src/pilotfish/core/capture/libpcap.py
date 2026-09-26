"""A ctypes binding to the libpcap that ships with macOS.

Only the functions live capture needs are bound. The prototype table below
gives each one's C declaration from ``<pcap/pcap.h>`` in the macOS SDK, and
the structures match that header field for field. ctypes releases the GIL for
the length of every call, so a thread blocked in ``pcap_next_ex`` leaves the
rest of the program running.

libpcap is loaded on first use, not at import, so the rest of pilotfish still
imports where it's missing.

Reference: https://www.tcpdump.org/manpages/pcap.3pcap.html
"""

import ctypes
import functools
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char,
    c_char_p,
    c_int,
    c_int32,
    c_long,
    c_ubyte,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint32,
    c_void_p,
)
from typing import Any

from pilotfish.core.capture.errors import CaptureError, CapturePermissionError
from pilotfish.core.capture.source import CaptureOptions, KernelStats
from pilotfish.core.filters.errors import FilterError
from pilotfish.core.filters.program import Instruction, Program
from pilotfish.core.linktypes import link_type_from_dlt
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND

LIBPCAP_PATH = "/usr/lib/libpcap.A.dylib"
"""The system libpcap. It lives in the dyld shared cache, so no file exists at
this path, but ``dlopen`` finds it there."""

ERRBUF_SIZE = 256
"""``PCAP_ERRBUF_SIZE``: room for the error messages libpcap writes."""

PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
"""Netmask to compile with when it isn't known. Only ``broadcast`` filters need it."""

# Status codes from pcap_activate and pcap_next_ex. Negative values are
# errors and positive values from pcap_activate are warnings.
PCAP_ERROR = -1
PCAP_ERROR_PERM_DENIED = -8
PCAP_ERROR_PROMISC_PERM_DENIED = -11

# pcap_if.flags
PCAP_IF_LOOPBACK = 0x01
PCAP_IF_UP = 0x02
PCAP_IF_RUNNING = 0x04
PCAP_IF_WIRELESS = 0x08
PCAP_IF_CONNECTION_STATUS = 0x30
PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x10
PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x20


class Timeval(Structure):
    """``struct timeval``: a 64-bit ``time_t`` and a 32-bit microseconds field."""

    _fields_ = [("tv_sec", c_long), ("tv_usec", c_int32)]
    tv_sec: int
    tv_usec: int


class PcapPkthdr(Structure):
    """``struct pcap_pkthdr``, the header libpcap returns with each packet."""

    _fields_ = [
        ("ts", Timeval),
        ("caplen", c_uint32),
        ("len", c_uint32),
        # Apple's libpcap adds this field; pilotfish doesn't use it.
        ("comment", c_char * 256),
    ]
    ts: Timeval
    caplen: int
    """Bytes captured."""
    len: int
    """Bytes on the wire."""


class PcapStat(Structure):
    """``struct pcap_stat``. ``ps_ifdrop`` is always 0 on macOS."""

    _fields_ = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]
    ps_recv: int
    ps_drop: int
    ps_ifdrop: int


class Sockaddr(Structure):
    """The start of every BSD ``struct sockaddr``: its length, then its family."""

    _fields_ = [("sa_len", c_uint8), ("sa_family", c_uint8)]
    sa_len: int
    sa_family: int


class PcapAddr(Structure):
    """``struct pcap_addr``, one address of an interface, in a linked list."""


PcapAddr._fields_ = [
    ("next", POINTER(PcapAddr)),
    ("addr", POINTER(Sockaddr)),
    ("netmask", POINTER(Sockaddr)),
    ("broadaddr", POINTER(Sockaddr)),
    ("dstaddr", POINTER(Sockaddr)),
]


class PcapIf(Structure):
    """``struct pcap_if``, one interface from ``pcap_findalldevs``, in a linked list."""


PcapIf._fields_ = [
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(PcapAddr)),
    ("flags", c_uint32),
]


class BpfInsn(Structure):
    """``struct bpf_insn``, one instruction of a compiled filter."""

    _fields_ = [("code", c_uint16), ("jt", c_uint8), ("jf", c_uint8), ("k", c_uint32)]
    code: int
    jt: int
    jf: int
    k: int


class BpfProgram(Structure):
    """``struct bpf_program``: how many instructions a filter has, and where."""

    _fields_ = [("bf_len", c_uint), ("bf_insns", POINTER(BpfInsn))]
    bf_len: int
    bf_insns: "ctypes._Pointer[BpfInsn]"


# pcap_t is opaque, so handles travel as c_void_p. Declaring every argument
# type matters: without it ctypes passes Python ints as 32-bit C ints and
# would cut 64-bit pointers in half.
_PROTOTYPES: tuple[tuple[str, Any, tuple[Any, ...]], ...] = (
    # int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
    ("pcap_findalldevs", c_int, (POINTER(POINTER(PcapIf)), c_char_p)),
    # void pcap_freealldevs(pcap_if_t *alldevs);
    ("pcap_freealldevs", None, (POINTER(PcapIf),)),
    # pcap_t *pcap_create(const char *source, char *errbuf);
    ("pcap_create", c_void_p, (c_char_p, c_char_p)),
    # int pcap_set_snaplen(pcap_t *p, int snaplen);
    ("pcap_set_snaplen", c_int, (c_void_p, c_int)),
    # int pcap_set_promisc(pcap_t *p, int promisc);
    ("pcap_set_promisc", c_int, (c_void_p, c_int)),
    # int pcap_set_timeout(pcap_t *p, int to_ms);
    ("pcap_set_timeout", c_int, (c_void_p, c_int)),
    # int pcap_set_buffer_size(pcap_t *p, int buffer_size);
    ("pcap_set_buffer_size", c_int, (c_void_p, c_int)),
    # int pcap_set_immediate_mode(pcap_t *p, int immediate_mode);
    ("pcap_set_immediate_mode", c_int, (c_void_p, c_int)),
    # int pcap_activate(pcap_t *p);
    ("pcap_activate", c_int, (c_void_p,)),
    # int pcap_datalink(pcap_t *p);
    ("pcap_datalink", c_int, (c_void_p,)),
    # int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    #                  const u_char **pkt_data);
    ("pcap_next_ex", c_int, (c_void_p, POINTER(POINTER(PcapPkthdr)), POINTER(POINTER(c_ubyte)))),
    # int pcap_stats(pcap_t *p, struct pcap_stat *ps);
    ("pcap_stats", c_int, (c_void_p, POINTER(PcapStat))),
    # char *pcap_geterr(pcap_t *p);
    ("pcap_geterr", c_char_p, (c_void_p,)),
    # const char *pcap_statustostr(int error);
    ("pcap_statustostr", c_char_p, (c_int,)),
    # void pcap_close(pcap_t *p);
    ("pcap_close", None, (c_void_p,)),
    # pcap_t *pcap_open_dead(int linktype, int snaplen);
    ("pcap_open_dead", c_void_p, (c_int, c_int)),
    # int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
    #                  int optimize, bpf_u_int32 netmask);
    ("pcap_compile", c_int, (c_void_p, POINTER(BpfProgram), c_char_p, c_int, c_uint32)),
    # int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
    ("pcap_setfilter", c_int, (c_void_p, POINTER(BpfProgram))),
    # void pcap_freecode(struct bpf_program *fp);
    ("pcap_freecode", None, (POINTER(BpfProgram),)),
    # int pcap_lookupnet(const char *device, bpf_u_int32 *netp,
    #                    bpf_u_int32 *maskp, char *errbuf);
    ("pcap_lookupnet", c_int, (c_char_p, POINTER(c_uint32), POINTER(c_uint32), c_char_p)),
)


@functools.cache
def load() -> ctypes.CDLL:
    """Load libpcap and declare the prototype of every function pilotfish calls."""
    try:
        lib = ctypes.CDLL(LIBPCAP_PATH)
    except OSError as error:
        raise CaptureError(f"can't load libpcap: {error}") from error
    for name, restype, argtypes in _PROTOTYPES:
        function = getattr(lib, name)
        function.restype = restype
        function.argtypes = argtypes
    return lib


def error_buffer() -> ctypes.Array[c_char]:
    return ctypes.create_string_buffer(ERRBUF_SIZE)


def text(message: bytes | None) -> str:
    return (message or b"").decode(errors="replace")


def compile_filter(
    expression: str,
    link_type: int,
    snaplen: int,
    netmask: int = PCAP_NETMASK_UNKNOWN,
) -> Program:
    """Compile filter text with libpcap's parser, the way tcpdump does.

    ``link_type`` is the DLT value of the packets the filter will run over,
    because what a filter has to look at depends on the headers in front of
    the packet. A matching packet keeps ``snaplen`` bytes.
    """
    lib = load()
    # A dead handle is one that carries a link type and snapshot length for
    # the compiler, with no interface or file behind it.
    handle: int | None = lib.pcap_open_dead(link_type, snaplen)
    if not handle:
        raise FilterError(f'capture filter "{expression}": libpcap ran out of memory')
    try:
        return compile_on(lib, handle, expression, netmask)
    finally:
        lib.pcap_close(handle)


def compile_on(lib: ctypes.CDLL, handle: int, expression: str, netmask: int) -> Program:
    """Compile ``expression`` for an open handle and copy out the instructions."""
    code = BpfProgram()
    if lib.pcap_compile(handle, byref(code), expression.encode(), 1, netmask) != 0:
        raise FilterError(f'capture filter "{expression}": {text(lib.pcap_geterr(handle))}')
    try:
        return Program(
            tuple(
                Instruction(each.code, each.jt, each.jf, each.k)
                for each in code.bf_insns[: code.bf_len]
            )
        )
    finally:
        # The instructions are libpcap's to free; pilotfish keeps its own copy.
        lib.pcap_freecode(byref(code))


def set_filter(lib: ctypes.CDLL, handle: int, program: Program) -> None:
    """Install ``program`` on an activated handle, so the kernel runs it."""
    instructions = (BpfInsn * len(program))(
        *(BpfInsn(each.code, each.jt, each.jf, each.k) for each in program)
    )
    code = BpfProgram(len(program), ctypes.cast(instructions, POINTER(BpfInsn)))
    if lib.pcap_setfilter(handle, byref(code)) != 0:
        raise FilterError(f"can't install the capture filter: {_message(lib, handle, PCAP_ERROR)}")


def interface_netmask(interface: str) -> int:
    """The interface's IPv4 netmask, which filters such as ``broadcast`` need.

    ``PCAP_NETMASK_UNKNOWN`` when libpcap can't work it out, which is what
    tcpdump uses then too.
    """
    lib = load()
    network = c_uint32()
    netmask = c_uint32()
    if lib.pcap_lookupnet(interface.encode(), byref(network), byref(netmask), error_buffer()) != 0:
        return PCAP_NETMASK_UNKNOWN
    return netmask.value


class PcapSource:
    """A live capture on one interface through libpcap."""

    def __init__(self, interface: str, options: CaptureOptions | None = None) -> None:
        options = options or CaptureOptions()
        lib = load()
        errbuf = error_buffer()
        handle: int | None = lib.pcap_create(interface.encode(), errbuf)
        if not handle:
            raise CaptureError(f"{interface}: {text(errbuf.value)}")
        try:
            for setter, value in (
                (lib.pcap_set_snaplen, options.snaplen),
                (lib.pcap_set_promisc, options.promiscuous),
                (lib.pcap_set_timeout, options.timeout_ms),
                (lib.pcap_set_buffer_size, options.buffer_size),
                (lib.pcap_set_immediate_mode, options.immediate),
            ):
                # Setters only fail on a handle that's already active.
                if (status := setter(handle, int(value))) != 0:
                    raise CaptureError(f"{interface}: {text(lib.pcap_statustostr(status))}")
            status = lib.pcap_activate(handle)
            if status < 0:
                message = f"{interface}: {_message(lib, handle, status)}"
                if status in {PCAP_ERROR_PERM_DENIED, PCAP_ERROR_PROMISC_PERM_DENIED}:
                    raise CapturePermissionError(message)
                raise CaptureError(message)
            self.warning = _message(lib, handle, status) if status > 0 else None
            self.link_type = link_type_from_dlt(lib.pcap_datalink(handle))
            self.program: Program | None = None
            if options.filter is not None:
                # Compiling against this handle uses its own link type and
                # snapshot length. The kernel runs the program from here on,
                # so packets that don't match never reach pilotfish.
                self.program = compile_on(lib, handle, options.filter, interface_netmask(interface))
                set_filter(lib, handle, self.program)
        except BaseException:
            lib.pcap_close(handle)
            raise
        self.interface = interface
        self._lib = lib
        self._handle: int | None = handle
        # pcap_next_ex points these at its own header and packet buffer.
        self._header = POINTER(PcapPkthdr)()
        self._data = POINTER(c_ubyte)()

    def read(self) -> Packet | None:
        handle = self._live_handle()
        status: int = self._lib.pcap_next_ex(handle, byref(self._header), byref(self._data))
        if status == 1:
            header = self._header.contents
            return Packet(
                timestamp_ns=header.ts.tv_sec * NS_PER_SECOND + header.ts.tv_usec * 1_000,
                original_length=header.len,
                link_type=self.link_type,
                # libpcap reuses its buffer on the next call, so copy the bytes out now.
                data=ctypes.string_at(self._data, header.caplen),
            )
        if status == 0:
            return None
        raise CaptureError(f"{self.interface}: {_message(self._lib, handle, status)}")

    def stats(self) -> KernelStats:
        handle = self._live_handle()
        stat = PcapStat()
        if self._lib.pcap_stats(handle, byref(stat)) != 0:
            raise CaptureError(f"{self.interface}: {_message(self._lib, handle, PCAP_ERROR)}")
        return KernelStats(received=stat.ps_recv, dropped=stat.ps_drop)

    def close(self) -> None:
        if self._handle is not None:
            self._lib.pcap_close(self._handle)
            self._handle = None

    def _live_handle(self) -> int:
        # libpcap would dereference a null handle and crash the interpreter.
        if self._handle is None:
            raise CaptureError(f"{self.interface}: capture is closed")
        return self._handle


def _message(lib: ctypes.CDLL, handle: int, status: int) -> str:
    """libpcap's detailed message for the last failure, or the generic text for ``status``."""
    return text(lib.pcap_geterr(handle)) or text(lib.pcap_statustostr(status))
