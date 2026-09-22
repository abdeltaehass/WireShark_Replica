"""Live capture straight from the kernel's BPF devices, without libpcap.

This does what libpcap's BPF backend does on macOS. It opens a free
``/dev/bpfN``, configures it with ioctl calls, and reads buffers of packets,
each packet behind a ``struct bpf_hdr`` that is parsed here.

The ioctl request numbers are built the way ``<sys/ioccom.h>`` builds them.
The structure layouts come from ``<net/bpf.h>`` and ``<net/if.h>`` in the
macOS SDK.

Reference: the bpf(4) man page.
"""

import ctypes
import errno
import fcntl
import io
import os
import struct
from collections.abc import Buffer, Iterator

from pilotfish.core.capture.errors import CaptureError, CapturePermissionError
from pilotfish.core.capture.source import CaptureOptions, KernelStats
from pilotfish.core.linktypes import link_type_from_dlt
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND

# An ioctl request packs the direction data is copied in, the size of the
# argument, a group letter and a command number into 32 bits.
_IOC_VOID = 0x20000000  # no argument
_IOC_OUT = 0x40000000  # the kernel copies the argument out to the caller
_IOC_IN = 0x80000000  # the kernel copies the argument in from the caller
_IOCPARM_MASK = 0x1FFF


def _bpf_ioctl(direction: int, number: int, size: int) -> int:
    return direction | (size & _IOCPARM_MASK) << 16 | ord("B") << 8 | number


BIOCGBLEN = _bpf_ioctl(_IOC_OUT, 102, 4)  # u_int: buffer length
BIOCSBLEN = _bpf_ioctl(_IOC_IN | _IOC_OUT, 102, 4)  # u_int: buffer length
BIOCSETF = _bpf_ioctl(_IOC_IN, 103, 16)  # struct bpf_program: filter program
BIOCPROMISC = _bpf_ioctl(_IOC_VOID, 105, 0)
BIOCGDLT = _bpf_ioctl(_IOC_OUT, 106, 4)  # u_int: DLT_ value of the interface
BIOCSETIF = _bpf_ioctl(_IOC_IN, 108, 32)  # struct ifreq: interface to attach to
BIOCSRTIMEOUT = _bpf_ioctl(_IOC_IN, 109, 16)  # struct timeval: read timeout
BIOCGSTATS = _bpf_ioctl(_IOC_OUT, 111, 8)  # struct bpf_stat: packets received, dropped
BIOCIMMEDIATE = _bpf_ioctl(_IOC_IN, 112, 4)  # u_int: 1 to return packets as they arrive
BIOCVERSION = _bpf_ioctl(_IOC_OUT, 113, 4)  # struct bpf_version: major, minor

BPF_MAJOR_VERSION = 1
BPF_MINOR_VERSION = 1

IFNAMSIZ = 16
"""Room for an interface name in ``struct ifreq``, including its NUL."""

_U32 = struct.Struct("=I")
_VERSION = struct.Struct("=HH")
_STATS = struct.Struct("=II")
_IFREQ = struct.Struct(f"={IFNAMSIZ}s16x")
_TIMEVAL = struct.Struct("=qi4x")
_PROGRAM = struct.Struct("=I4xQ")  # instruction count, pointer to the instructions
_INSTRUCTION = struct.Struct("=HBBI")  # opcode, jump if true, jump if false, constant

_BPF_RET_K = 0x06
"""``BPF_RET | BPF_K``: accept the packet, keeping the number of bytes in the constant."""

_BPF_HEADER = struct.Struct("=IIIIH")
"""``struct bpf_hdr`` up to its trailing padding: the timestamp as a
``struct timeval32`` (seconds, microseconds), the captured length, the
original length and the header length. The kernel writes the seconds as a
32-bit signed number. Reading them unsigned keeps timestamps right until 2106
instead of 2038."""

BPF_HEADER_SIZE = _BPF_HEADER.size
"""``SIZEOF_BPF_HDR``, the 18 bytes of ``struct bpf_hdr`` without padding."""


def _word_align(length: int) -> int:
    """``BPF_WORDALIGN``: round up to the 4-byte boundary where each record starts."""
    return (length + 3) & ~3


def parse_records(buffer: Buffer, link_type: int) -> Iterator[Packet]:
    """Split the data from one read of a BPF device into packets.

    Each record is a ``bpf_hdr`` padded out to ``bh_hdrlen`` bytes, the
    captured bytes, then padding to a 4-byte boundary. The kernel sets
    ``bh_hdrlen`` so that the header after the link-layer header is aligned,
    so it changes with the link type: 18 bytes for Ethernet, 20 for loopback.
    """
    view = memoryview(buffer)
    end = len(view)
    offset = 0
    while offset < end:
        if end - offset < BPF_HEADER_SIZE:
            raise CaptureError(
                f"BPF record at offset {offset} is cut short: "
                f"{end - offset} of {BPF_HEADER_SIZE} header bytes"
            )
        seconds, microseconds, captured_length, original_length, header_length = (
            _BPF_HEADER.unpack_from(view, offset)
        )
        if header_length < BPF_HEADER_SIZE:
            raise CaptureError(
                f"BPF record at offset {offset} has a {header_length}-byte header, "
                f"shorter than struct bpf_hdr"
            )
        start = offset + header_length
        stop = start + captured_length
        if stop > end:
            raise CaptureError(
                f"BPF record at offset {offset} claims {header_length} header and "
                f"{captured_length} packet bytes, past the end of the data"
            )
        yield Packet(
            timestamp_ns=seconds * NS_PER_SECOND + microseconds * 1_000,
            original_length=original_length,
            link_type=link_type,
            # The next read overwrites the buffer, so copy the bytes out now.
            data=bytes(view[start:stop]),
        )
        offset += _word_align(header_length + captured_length)


def open_bpf_device() -> tuple[int, str]:
    """Open the first BPF device no other program is using. Returns the descriptor and path."""
    number = 0
    while True:
        path = f"/dev/bpf{number}"
        try:
            # Reading is all capture needs; libpcap also asks for write access to send packets.
            return os.open(path, os.O_RDONLY), path
        except OSError as error:
            if error.errno == errno.EBUSY:
                number += 1
                continue
            if error.errno in {errno.EACCES, errno.EPERM}:
                raise CapturePermissionError(f"{path}: {error.strerror}") from error
            if error.errno == errno.ENOENT:
                raise CaptureError("every BPF device is in use") from error
            raise CaptureError(f"{path}: {error.strerror}") from error


class BpfSource:
    """A live capture on one interface through a BPF device of its own."""

    def __init__(self, interface: str, options: CaptureOptions | None = None) -> None:
        options = options or CaptureOptions()
        name = interface.encode()
        if len(name) >= IFNAMSIZ:
            raise CaptureError(f"{interface}: interface names are at most {IFNAMSIZ - 1} bytes")
        self.interface = interface
        self.warning: str | None = None
        fd, self.device = open_bpf_device()
        try:
            self._configure(fd, name, options)
        except BaseException:
            os.close(fd)
            raise
        self._file = io.FileIO(fd, "r")
        self._buffer = bytearray(self.buffer_length)
        self._records: Iterator[Packet] = iter(())

    def _configure(self, fd: int, name: bytes, options: CaptureOptions) -> None:
        major, minor = _VERSION.unpack(self._ioctl(fd, "BIOCVERSION", BIOCVERSION, bytes(4)))
        if major != BPF_MAJOR_VERSION or minor < BPF_MINOR_VERSION:
            raise CaptureError(f"kernel BPF version {major}.{minor} isn't supported")

        # The buffer length can only be set before attaching to an interface.
        # The kernel lowers a request above its limit instead of failing.
        self._ioctl(fd, "BIOCSBLEN", BIOCSBLEN, _U32.pack(options.buffer_size))
        try:
            fcntl.ioctl(fd, BIOCSETIF, _IFREQ.pack(name))
        except OSError as error:
            if error.errno == errno.ENXIO:
                raise CaptureError(f"{self.interface}: No such device exists") from error
            raise CaptureError(f"{self.interface}: BIOCSETIF: {error.strerror}") from error
        (dlt,) = _U32.unpack(self._ioctl(fd, "BIOCGDLT", BIOCGDLT, bytes(4)))
        self.link_type = link_type_from_dlt(dlt)

        if options.immediate:
            self._ioctl(fd, "BIOCIMMEDIATE", BIOCIMMEDIATE, _U32.pack(1))
        if options.promiscuous:
            try:
                fcntl.ioctl(fd, BIOCPROMISC)
            except OSError as error:
                self.warning = f"can't enter promiscuous mode: {error.strerror}"
        seconds, milliseconds = divmod(options.timeout_ms, 1000)
        self._ioctl(fd, "BIOCSRTIMEOUT", BIOCSRTIMEOUT, _TIMEVAL.pack(seconds, milliseconds * 1000))

        # BPF has no snapshot length setting. The filter program's return value
        # is how many bytes of each packet to keep, so a one-instruction
        # program that returns snaplen for every packet sets it.
        instructions = ctypes.create_string_buffer(
            _INSTRUCTION.pack(_BPF_RET_K, 0, 0, options.snaplen)
        )
        program = _PROGRAM.pack(1, ctypes.addressof(instructions))
        self._ioctl(fd, "BIOCSETF", BIOCSETF, program)

        # A read must ask for exactly the buffer length, so find out what the kernel chose.
        (self.buffer_length,) = _U32.unpack(self._ioctl(fd, "BIOCGBLEN", BIOCGBLEN, bytes(4)))

    def _ioctl(self, fd: int, name: str, request: int, argument: bytes) -> bytes:
        """Run an ioctl whose argument is a struct. Returns the struct as the kernel left it."""
        try:
            return fcntl.ioctl(fd, request, argument)
        except OSError as error:
            raise CaptureError(f"{self.interface}: {name}: {error.strerror}") from error

    def read(self) -> Packet | None:
        packet = next(self._records, None)
        if packet is not None:
            return packet
        if self._file.closed:
            raise CaptureError(f"{self.interface}: capture is closed")
        try:
            # Returns as soon as a packet arrives in immediate mode, and after
            # the read timeout with nothing when none do.
            length = self._file.readinto(self._buffer)
        except OSError as error:
            raise CaptureError(f"{self.interface}: {error.strerror}") from error
        if not length:
            return None
        self._records = parse_records(memoryview(self._buffer)[:length], self.link_type)
        return next(self._records, None)

    def stats(self) -> KernelStats:
        if self._file.closed:
            raise CaptureError(f"{self.interface}: capture is closed")
        received, dropped = _STATS.unpack(
            self._ioctl(self._file.fileno(), "BIOCGSTATS", BIOCGSTATS, bytes(_STATS.size))
        )
        return KernelStats(received=received, dropped=dropped)

    def close(self) -> None:
        self._file.close()
