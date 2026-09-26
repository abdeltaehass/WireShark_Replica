from ctypes import POINTER, byref, c_char_p, c_int

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pilotfish.core.capture.libpcap import BpfInsn, load, text
from pilotfish.core.filters import FilterError, Instruction, Program
from pilotfish.core.filters.program import (
    BPF_A,
    BPF_ABS,
    BPF_ADD,
    BPF_ALU,
    BPF_AND,
    BPF_B,
    BPF_H,
    BPF_IMM,
    BPF_IND,
    BPF_JA,
    BPF_JEQ,
    BPF_JMP,
    BPF_K,
    BPF_LD,
    BPF_LDX,
    BPF_LEN,
    BPF_MEM,
    BPF_MISC,
    BPF_MSH,
    BPF_NEG,
    BPF_RET,
    BPF_ST,
    BPF_STX,
    BPF_TAX,
    BPF_TXA,
    BPF_W,
    BPF_X,
)
from programs import DNS_OVER_ETHERNET, DNS_OVER_ETHERNET_IMAGE


def test_disassembles_like_tcpdump() -> None:
    assert DNS_OVER_ETHERNET.disassemble() == DNS_OVER_ETHERNET_IMAGE


@pytest.mark.parametrize(
    ("instruction", "line"),
    [
        (Instruction(BPF_LD | BPF_W | BPF_ABS, k=12), "(000) ld       [12]"),
        (Instruction(BPF_LD | BPF_H | BPF_ABS, k=12), "(000) ldh      [12]"),
        (Instruction(BPF_LD | BPF_B | BPF_IND, k=14), "(000) ldb      [x + 14]"),
        (Instruction(BPF_LD | BPF_IMM, k=42), "(000) ld       #0x2a"),
        (Instruction(BPF_LD | BPF_MEM, k=3), "(000) ld       M[3]"),
        (Instruction(BPF_LD | BPF_W | BPF_LEN), "(000) ld       #pktlen"),
        (Instruction(BPF_LDX | BPF_IMM, k=5), "(000) ldx      #0x5"),
        (Instruction(BPF_LDX | BPF_MEM, k=5), "(000) ldx      M[5]"),
        (Instruction(BPF_LDX | BPF_B | BPF_MSH, k=14), "(000) ldxb     4*([14]&0xf)"),
        (Instruction(BPF_ST, k=2), "(000) st       M[2]"),
        (Instruction(BPF_STX, k=2), "(000) stx      M[2]"),
        (Instruction(BPF_ALU | BPF_ADD | BPF_K, k=10), "(000) add      #10"),
        (Instruction(BPF_ALU | BPF_AND | BPF_K, k=10), "(000) and      #0xa"),
        (Instruction(BPF_ALU | BPF_ADD | BPF_X), "(000) add      x"),
        (Instruction(BPF_ALU | BPF_NEG), "(000) neg"),
        (Instruction(BPF_JMP | BPF_JA, k=4), "(000) ja       5"),
        (
            Instruction(BPF_JMP | BPF_JEQ | BPF_K, 3, 7, 53),
            "(000) jeq      #0x35            jt 4\tjf 8",
        ),
        (
            Instruction(BPF_JMP | BPF_JEQ | BPF_X, 3, 7),
            "(000) jeq      x                jt 4\tjf 8",
        ),
        (Instruction(BPF_RET | BPF_K, k=262144), "(000) ret      #262144"),
        (Instruction(BPF_RET | BPF_A), "(000) ret"),
        (Instruction(BPF_MISC | BPF_TAX), "(000) tax"),
        (Instruction(BPF_MISC | BPF_TXA), "(000) txa"),
        (Instruction(0xFF), "(000) unimp    0xff"),
    ],
    ids=lambda value: value.replace(" ", "") if isinstance(value, str) else "",
)
def test_operand_forms(instruction: Instruction, line: str) -> None:
    assert Program((instruction,)).disassemble() == [line]


def test_accept_keeps_every_packet() -> None:
    assert Program.accept(262144).disassemble() == ["(000) ret      #262144"]


instructions = st.builds(
    Instruction,
    code=st.integers(0, 0xFFFF),
    jt=st.integers(0, 0xFF),
    jf=st.integers(0, 0xFF),
    k=st.integers(0, 0xFFFFFFFF),
)


@given(st.lists(instructions))
def test_bytes_round_trip(items: list[Instruction]) -> None:
    program = Program(tuple(items))
    assert Program.from_bytes(program.to_bytes()) == program
    assert len(program.to_bytes()) == 8 * len(items)


def test_from_bytes_rejects_a_partial_instruction() -> None:
    with pytest.raises(FilterError, match="whole number of 8-byte instructions, not 9"):
        Program.from_bytes(bytes(9))


# libpcap's own disassembler, which tcpdump -d prints, as an answer key.
_LDX_PKTLEN = BPF_LDX | BPF_W | BPF_LEN


@pytest.mark.macos
def test_disassembly_matches_libpcap() -> None:
    lib = load()
    lib.bpf_image.restype = c_char_p
    lib.bpf_image.argtypes = [POINTER(BpfInsn), c_int]
    index = 9
    filler = (Instruction(BPF_RET | BPF_K),) * index
    differences = []
    for code in range(0x100):
        for k in (0, 10, 53):
            instruction = Instruction(code, 3, 7, k)
            native = BpfInsn(code, 3, 7, k)
            theirs = text(lib.bpf_image(byref(native), index)).rstrip()
            ours = Program((*filler, instruction)).disassemble()[index]
            if ours != theirs:
                differences.append((hex(code), ours, theirs))
    # libpcap has no name for `ldx #pktlen`, though the kernel runs it.
    assert {code for code, _, _ in differences} == {hex(_LDX_PKTLEN)}
