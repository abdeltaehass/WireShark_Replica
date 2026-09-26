"""BPF programs: what a capture filter compiles to.

A filter such as ``udp port 53`` compiles to a short program of fixed-size
instructions. The kernel runs it over every packet the interface sees and
keeps the packet only if the program returns a non-zero number of bytes, so
packets that don't match never reach pilotfish at all.

Each instruction is 8 bytes: a 16-bit opcode, two 8-bit jump offsets and a
32-bit constant ``k``. The opcode packs a class and, depending on that class,
an operand size, an addressing mode or an operation, which is why the
constants below are combined with ``|``: ``BPF_LD | BPF_H | BPF_ABS`` loads
the 16-bit value at a fixed offset in the packet.

Reference: the bpf(4) man page and <net/bpf.h> in the macOS SDK.
"""

import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from typing import Self

from pilotfish.core.filters.errors import FilterError

INSTRUCTION = struct.Struct("=HBBI")
"""``struct bpf_insn``: opcode, jump if true, jump if false, constant."""

# Instruction class, the low three bits of the opcode.
BPF_CLASS = 0x07
BPF_LD = 0x00
"""Load into the accumulator A."""
BPF_LDX = 0x01
"""Load into the index register X."""
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

# Operand size, for loads.
BPF_SIZE = 0x18
BPF_W = 0x00
"""Four bytes."""
BPF_H = 0x08
"""Two bytes."""
BPF_B = 0x10
"""One byte."""

# Addressing mode, for loads.
BPF_MODE = 0xE0
BPF_IMM = 0x00
"""The constant k itself."""
BPF_ABS = 0x20
"""The packet at a fixed offset."""
BPF_IND = 0x40
"""The packet at offset X + k."""
BPF_MEM = 0x60
"""Scratch memory slot k."""
BPF_LEN = 0x80
"""The packet's length on the wire."""
BPF_MSH = 0xA0
"""Four times the low nibble of the byte at k: the length of an IPv4 header."""

# Arithmetic operation.
BPF_OP = 0xF0
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xA0

# Jump operation, sharing the BPF_OP bits.
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

# Where the second operand of an arithmetic or jump instruction comes from.
BPF_SRC = 0x08
BPF_K = 0x00
"""The constant in the instruction."""
BPF_X = 0x08
"""The index register."""

# What a return instruction returns, sharing the BPF_SIZE bits.
BPF_RVAL = 0x18
BPF_A = 0x10
"""The accumulator."""

# Register moves, in the MISC class.
BPF_TAX = 0x00
"""Copy the accumulator into the index register."""
BPF_TXA = 0x80
"""Copy the index register into the accumulator."""

MEMORY_SLOTS = 16
"""Scratch memory slots M[0] to M[15], the only memory a program has."""


@dataclass(frozen=True, slots=True)
class Instruction:
    code: int
    jt: int = 0
    """Instructions to skip when a comparison is true."""
    jf: int = 0
    """Instructions to skip when it is false."""
    k: int = 0


@dataclass(frozen=True, slots=True)
class Program:
    """A compiled capture filter."""

    instructions: tuple[Instruction, ...]

    @classmethod
    def accept(cls, length: int) -> Self:
        """A program that keeps ``length`` bytes of every packet."""
        return cls((Instruction(BPF_RET | BPF_K, k=length),))

    @classmethod
    def from_bytes(cls, data: Buffer) -> Self:
        view = memoryview(data)
        if len(view) % INSTRUCTION.size:
            raise FilterError(
                f"a BPF program is a whole number of {INSTRUCTION.size}-byte "
                f"instructions, not {len(view)} bytes"
            )
        return cls(tuple(Instruction(*fields) for fields in INSTRUCTION.iter_unpack(view)))

    def to_bytes(self) -> bytes:
        """The instructions as the kernel and libpcap expect them in memory."""
        return b"".join(
            INSTRUCTION.pack(each.code, each.jt, each.jf, each.k) for each in self.instructions
        )

    def disassemble(self) -> list[str]:
        """The program in the form tcpdump's ``-d`` flag prints."""
        return [_image(instruction, index) for index, instruction in enumerate(self.instructions)]

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self) -> Iterator[Instruction]:
        return iter(self.instructions)

    def __getitem__(self, index: int) -> Instruction:
        return self.instructions[index]


_LOAD_NAMES = {BPF_W: "ld", BPF_H: "ldh", BPF_B: "ldb"}
_ALU_NAMES = {
    BPF_ADD: "add",
    BPF_SUB: "sub",
    BPF_MUL: "mul",
    BPF_DIV: "div",
    BPF_OR: "or",
    BPF_AND: "and",
    BPF_LSH: "lsh",
    BPF_RSH: "rsh",
    BPF_MOD: "mod",
    BPF_XOR: "xor",
}
# libpcap prints the constants of the bitwise operations in hex, the rest in decimal.
_ALU_HEX = {BPF_OR, BPF_AND, BPF_XOR}
_JUMP_NAMES = {BPF_JEQ: "jeq", BPF_JGT: "jgt", BPF_JGE: "jge", BPF_JSET: "jset"}


def _build_images() -> dict[int, tuple[str, str]]:
    """Every valid instruction, with the name and operand form tcpdump prints.

    An opcode that isn't a combination the kernel understands has no name,
    and prints as ``unimp``.
    """
    table = {
        BPF_LD | BPF_IMM: ("ld", "hex"),
        BPF_LD | BPF_MEM: ("ld", "mem"),
        BPF_LD | BPF_W | BPF_LEN: ("ld", "pktlen"),
        BPF_LDX | BPF_IMM: ("ldx", "hex"),
        BPF_LDX | BPF_MEM: ("ldx", "mem"),
        # libpcap's own disassembler has no name for this one, though both the
        # kernel and pilotfish's interpreter run it.
        BPF_LDX | BPF_W | BPF_LEN: ("ldx", "pktlen"),
        BPF_LDX | BPF_B | BPF_MSH: ("ldxb", "msh"),
        BPF_ST: ("st", "mem"),
        BPF_STX: ("stx", "mem"),
        BPF_ALU | BPF_NEG: ("neg", "none"),
        BPF_JMP | BPF_JA: ("ja", "target"),
        BPF_RET | BPF_K: ("ret", "decimal"),
        BPF_RET | BPF_A: ("ret", "none"),
        BPF_MISC | BPF_TAX: ("tax", "none"),
        BPF_MISC | BPF_TXA: ("txa", "none"),
    }
    for size, name in _LOAD_NAMES.items():
        table[BPF_LD | size | BPF_ABS] = (name, "absolute")
        table[BPF_LD | size | BPF_IND] = (name, "indexed")
    for operation, name in _ALU_NAMES.items():
        constant = "hex" if operation in _ALU_HEX else "decimal"
        table[BPF_ALU | operation | BPF_K] = (name, constant)
        table[BPF_ALU | operation | BPF_X] = (name, "index")
    for operation, name in _JUMP_NAMES.items():
        table[BPF_JMP | operation | BPF_K] = (name, "hex")
        table[BPF_JMP | operation | BPF_X] = (name, "index")
    return table


_IMAGES = _build_images()

VALID_OPCODES = frozenset(_IMAGES)
"""Every opcode the kernel's BPF engine runs. It rejects any other program."""


def _image(instruction: Instruction, index: int) -> str:
    """One line of disassembly, laid out as libpcap's ``bpf_image`` lays it out."""
    code = instruction.code
    name, operand_kind = _IMAGES.get(code, ("unimp", "opcode"))
    operand = _operand(operand_kind, instruction, index)
    if code & BPF_CLASS == BPF_JMP and code & BPF_OP != BPF_JA:
        # Conditional jumps also show where each outcome goes.
        targets = f"jt {index + 1 + instruction.jt}\tjf {index + 1 + instruction.jf}"
        return f"({index:03d}) {name:<8} {operand:<16} {targets}"
    return f"({index:03d}) {name:<8} {operand}".rstrip()


def _operand(kind: str, instruction: Instruction, index: int) -> str:
    k = instruction.k
    match kind:
        case "absolute":
            return f"[{k}]"
        case "indexed":
            return f"[x + {k}]"
        case "mem":
            return f"M[{k}]"
        case "msh":
            return f"4*([{k}]&0xf)"
        case "hex":
            return f"#0x{k:x}"
        case "decimal":
            return f"#{k}"
        case "pktlen":
            return "#pktlen"
        case "index":
            return "x"
        case "target":
            return f"{index + 1 + k}"
        case "opcode":
            return f"0x{instruction.code:x}"
        case _:
            return ""
