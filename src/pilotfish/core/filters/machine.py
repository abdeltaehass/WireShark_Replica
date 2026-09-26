"""A BPF virtual machine.

For live capture the kernel runs a filter's instructions over every packet
before pilotfish sees it. This runs the same instructions in Python, which is
how the same filter can be applied to packets read from a file.

The machine has two 32-bit registers, the accumulator A and the index X, and
16 scratch memory slots. Each instruction loads a value into a register, does
arithmetic on A, jumps, or returns the number of bytes of the packet to keep.
Jumps only go forward, so a program always finishes.

Reference: ``bpf_filter`` in FreeBSD's and macOS's ``bpf_filter.c``, which is
the same interpreter in C.
"""

from collections.abc import Buffer

from pilotfish.core.filters.errors import FilterError
from pilotfish.core.filters.program import (
    BPF_A,
    BPF_ABS,
    BPF_ADD,
    BPF_ALU,
    BPF_AND,
    BPF_B,
    BPF_CLASS,
    BPF_DIV,
    BPF_H,
    BPF_IMM,
    BPF_IND,
    BPF_JA,
    BPF_JEQ,
    BPF_JGE,
    BPF_JGT,
    BPF_JMP,
    BPF_LD,
    BPF_LDX,
    BPF_LEN,
    BPF_LSH,
    BPF_MISC,
    BPF_MOD,
    BPF_MODE,
    BPF_MSH,
    BPF_MUL,
    BPF_NEG,
    BPF_OP,
    BPF_OR,
    BPF_RET,
    BPF_RVAL,
    BPF_SIZE,
    BPF_SRC,
    BPF_ST,
    BPF_STX,
    BPF_SUB,
    BPF_TXA,
    BPF_X,
    BPF_XOR,
    MEMORY_SLOTS,
    VALID_OPCODES,
    Program,
)

_WORD = 0xFFFFFFFF
"""Registers are 32 bits wide and wrap around, which Python integers don't."""

_WIDTHS = {BPF_B: 1, BPF_H: 2}


def run(program: Program, packet: Buffer, wire_length: int | None = None) -> int:
    """Run ``program`` over ``packet``. Returns the bytes to keep, 0 to drop it.

    ``wire_length`` is how long the packet was on the wire, which can be more
    than was captured. That is what ``ld #pktlen`` reads, while loads of packet
    bytes are bounded by the bytes actually there.
    """
    data = memoryview(packet)
    if wire_length is None:
        wire_length = len(data)
    accumulator = 0
    index_register = 0
    memory = [0] * MEMORY_SLOTS
    counter = 0
    while True:
        if counter >= len(program):
            raise FilterError(
                f"the program ran past its last instruction ({len(program)}); "
                "a BPF program must end by returning"
            )
        instruction = program[counter]
        code = instruction.code
        k = instruction.k
        counter += 1
        if code not in VALID_OPCODES:
            raise FilterError(f"unknown BPF instruction 0x{code:x}")
        instruction_class = code & BPF_CLASS

        if instruction_class == BPF_LD:
            mode = code & BPF_MODE
            if mode in {BPF_ABS, BPF_IND}:
                offset = k if mode == BPF_ABS else index_register + k
                value = _packet_value(data, offset, code & BPF_SIZE)
                if value is None:
                    # The kernel drops a packet too short for the filter to read.
                    return 0
                accumulator = value
            elif mode == BPF_IMM:
                accumulator = k
            elif mode == BPF_LEN:
                accumulator = wire_length
            else:  # BPF_MEM
                accumulator = memory[_slot(k)]

        elif instruction_class == BPF_LDX:
            mode = code & BPF_MODE
            if mode == BPF_MSH:
                # The IPv4 header length: its low nibble counts 32-bit words.
                value = _packet_value(data, k, BPF_B)
                if value is None:
                    return 0
                index_register = (value & 0xF) << 2
            elif mode == BPF_IMM:
                index_register = k
            elif mode == BPF_LEN:
                index_register = wire_length
            else:  # BPF_MEM
                index_register = memory[_slot(k)]

        elif instruction_class == BPF_ST:
            memory[_slot(k)] = accumulator

        elif instruction_class == BPF_STX:
            memory[_slot(k)] = index_register

        elif instruction_class == BPF_ALU:
            operation = code & BPF_OP
            if operation == BPF_NEG:
                accumulator = -accumulator & _WORD
            else:
                operand = index_register if code & BPF_SRC == BPF_X else k
                if operand == 0 and operation in {BPF_DIV, BPF_MOD}:
                    # Dividing by zero drops the packet rather than trapping.
                    return 0
                accumulator = _arithmetic(operation, accumulator, operand)

        elif instruction_class == BPF_JMP:
            operation = code & BPF_OP
            if operation == BPF_JA:
                counter += k
            else:
                operand = index_register if code & BPF_SRC == BPF_X else k
                counter += (
                    instruction.jt if _taken(operation, accumulator, operand) else instruction.jf
                )

        elif instruction_class == BPF_RET:
            return accumulator if code & BPF_RVAL == BPF_A else k

        else:  # BPF_MISC: copy one register to the other.
            if code == BPF_MISC | BPF_TXA:
                accumulator = index_register
            else:
                index_register = accumulator


def matches(program: Program, packet: Buffer, wire_length: int | None = None) -> bool:
    """Whether ``program`` keeps ``packet``."""
    return run(program, packet, wire_length) > 0


def _packet_value(data: memoryview, offset: int, size: int) -> int | None:
    """The 1, 2 or 4 bytes at ``offset``, or ``None`` if they weren't captured.

    Packet values are read in network byte order, whatever this machine uses.
    """
    width = _WIDTHS.get(size, 4)
    if offset < 0 or offset + width > len(data):
        return None
    return int.from_bytes(data[offset : offset + width], "big")


def _arithmetic(operation: int, accumulator: int, operand: int) -> int:
    if operation == BPF_ADD:
        return (accumulator + operand) & _WORD
    if operation == BPF_SUB:
        return (accumulator - operand) & _WORD
    if operation == BPF_MUL:
        return (accumulator * operand) & _WORD
    if operation == BPF_DIV:
        return accumulator // operand
    if operation == BPF_MOD:
        return accumulator % operand
    if operation == BPF_AND:
        return accumulator & operand
    if operation == BPF_OR:
        return accumulator | operand
    if operation == BPF_XOR:
        return accumulator ^ operand
    if operation == BPF_LSH:
        # C leaves a shift of 32 or more undefined; libpcap never emits one.
        return (accumulator << operand) & _WORD if operand < 32 else 0
    return accumulator >> operand if operand < 32 else 0  # BPF_RSH


def _taken(operation: int, accumulator: int, operand: int) -> bool:
    if operation == BPF_JEQ:
        return accumulator == operand
    if operation == BPF_JGT:
        return accumulator > operand
    if operation == BPF_JGE:
        return accumulator >= operand
    return bool(accumulator & operand)  # BPF_JSET


def _slot(k: int) -> int:
    if k >= MEMORY_SLOTS:
        raise FilterError(f"M[{k}] is outside the {MEMORY_SLOTS} scratch memory slots")
    return k
