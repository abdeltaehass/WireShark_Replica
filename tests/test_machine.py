import functools
from ctypes import POINTER, c_ubyte, c_uint

import pytest
from hypothesis import given
from hypothesis import strategies as st

from packets import ACCEPTED, DNS_OVER_ETHERNET, ethernet, ipv4, ipv6, program, udp
from pilotfish.core.capture import compile_filter
from pilotfish.core.capture.libpcap import BpfInsn, load
from pilotfish.core.filters import FilterError, Instruction, Program
from pilotfish.core.filters.machine import matches, run
from pilotfish.core.filters.program import (
    BPF_A,
    BPF_ABS,
    BPF_ADD,
    BPF_ALU,
    BPF_B,
    BPF_DIV,
    BPF_H,
    BPF_IMM,
    BPF_IND,
    BPF_JA,
    BPF_JEQ,
    BPF_JGE,
    BPF_JMP,
    BPF_JSET,
    BPF_K,
    BPF_LD,
    BPF_LDX,
    BPF_LEN,
    BPF_LSH,
    BPF_MEM,
    BPF_MISC,
    BPF_MOD,
    BPF_MSH,
    BPF_MUL,
    BPF_NEG,
    BPF_RET,
    BPF_ST,
    BPF_STX,
    BPF_SUB,
    BPF_TAX,
    BPF_TXA,
    BPF_W,
    BPF_X,
)

KEEP = Instruction(BPF_RET | BPF_A)
"""Return whatever is in the accumulator, so a test can read it."""


def accumulator(
    *fields: tuple[int, int, int, int], packet: bytes = b"", wire: int | None = None
) -> int:
    """Run the instructions, then return what is left in the accumulator."""
    return run(Program((*(Instruction(*each) for each in fields), KEEP)), packet, wire)


class TestTheDnsFilter:
    """The real `udp port 53` program, over packets built by hand."""

    def test_keeps_a_dns_query(self) -> None:
        packet = ethernet(ipv4(udp(49152, 53)))
        assert run(DNS_OVER_ETHERNET, packet) == ACCEPTED

    def test_keeps_a_dns_reply(self) -> None:
        assert matches(DNS_OVER_ETHERNET, ethernet(ipv4(udp(53, 49152))))

    def test_keeps_dns_over_ipv6(self) -> None:
        assert matches(DNS_OVER_ETHERNET, ethernet(ipv6(udp(49152, 53)), ethertype=0x86DD))

    def test_drops_another_port(self) -> None:
        assert run(DNS_OVER_ETHERNET, ethernet(ipv4(udp(49152, 80)))) == 0

    def test_drops_another_protocol(self) -> None:
        assert not matches(DNS_OVER_ETHERNET, ethernet(ipv4(udp(49152, 53), protocol=6)))

    def test_drops_arp(self) -> None:
        assert not matches(DNS_OVER_ETHERNET, ethernet(b"\x00" * 28, ethertype=0x0806))

    def test_reads_ports_past_ipv4_options(self) -> None:
        # ldxb 4*([14]&0xf) is why the ports are found after a longer header.
        assert matches(DNS_OVER_ETHERNET, ethernet(ipv4(udp(49152, 53), options=bytes(12))))

    def test_drops_a_later_fragment(self) -> None:
        # A fragment past the first carries no ports to compare.
        assert not matches(DNS_OVER_ETHERNET, ethernet(ipv4(udp(49152, 53), fragment_offset=185)))

    def test_drops_a_packet_cut_short_before_the_ports(self) -> None:
        whole = ethernet(ipv4(udp(49152, 53)))
        assert run(DNS_OVER_ETHERNET, whole[:30], wire_length=len(whole)) == 0


class TestInstructions:
    def test_loads_from_the_packet(self) -> None:
        packet = bytes(range(16))
        assert accumulator((BPF_LD | BPF_B | BPF_ABS, 0, 0, 2), packet=packet) == 0x02
        assert accumulator((BPF_LD | BPF_H | BPF_ABS, 0, 0, 2), packet=packet) == 0x0203
        assert accumulator((BPF_LD | BPF_W | BPF_ABS, 0, 0, 2), packet=packet) == 0x02030405

    def test_loads_relative_to_the_index_register(self) -> None:
        packet = bytes(range(16))
        assert (
            accumulator(
                (BPF_LDX | BPF_IMM, 0, 0, 4),
                (BPF_LD | BPF_H | BPF_IND, 0, 0, 2),
                packet=packet,
            )
            == 0x0607
        )

    def test_a_load_past_the_captured_bytes_drops_the_packet(self) -> None:
        assert accumulator((BPF_LD | BPF_W | BPF_ABS, 0, 0, 5), packet=bytes(8)) == 0
        assert accumulator((BPF_LD | BPF_B | BPF_ABS, 0, 0, 8), packet=bytes(8)) == 0
        assert accumulator((BPF_LDX | BPF_B | BPF_MSH, 0, 0, 9), packet=bytes(8)) == 0

    def test_packet_length_is_the_length_on_the_wire(self) -> None:
        assert accumulator((BPF_LD | BPF_W | BPF_LEN, 0, 0, 0), packet=bytes(8), wire=1514) == 1514
        assert (
            accumulator(
                (BPF_LDX | BPF_W | BPF_LEN, 0, 0, 0),
                (BPF_MISC | BPF_TXA, 0, 0, 0),
                packet=bytes(8),
                wire=1514,
            )
            == 1514
        )

    def test_header_length_from_the_low_nibble(self) -> None:
        # 4*([0]&0xf) is how a filter steps over an IPv4 header.
        assert (
            accumulator(
                (BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
                (BPF_MISC | BPF_TXA, 0, 0, 0),
                packet=bytes([0x46]),
            )
            == 24
        )

    def test_scratch_memory(self) -> None:
        assert (
            accumulator(
                (BPF_LD | BPF_IMM, 0, 0, 7),
                (BPF_ST, 0, 0, 3),
                (BPF_LD | BPF_IMM, 0, 0, 0),
                (BPF_LD | BPF_MEM, 0, 0, 3),
            )
            == 7
        )
        assert (
            accumulator(
                (BPF_LDX | BPF_IMM, 0, 0, 9),
                (BPF_STX, 0, 0, 15),
                (BPF_LDX | BPF_MEM, 0, 0, 15),
                (BPF_MISC | BPF_TXA, 0, 0, 0),
            )
            == 9
        )

    @pytest.mark.parametrize(
        ("operation", "operand", "result"),
        [
            (BPF_ADD, 5, 15),
            (BPF_SUB, 5, 5),
            (BPF_MUL, 5, 50),
            (BPF_DIV, 3, 3),
            (BPF_MOD, 3, 1),
            (BPF_LSH, 4, 160),
            (BPF_LSH, 32, 0),
            (BPF_LSH, 31, 0),
        ],
    )
    def test_arithmetic(self, operation: int, operand: int, result: int) -> None:
        assert (
            accumulator((BPF_LD | BPF_IMM, 0, 0, 10), (BPF_ALU | operation | BPF_K, 0, 0, operand))
            == result
        )

    def test_arithmetic_wraps_at_32_bits(self) -> None:
        assert (
            accumulator((BPF_LD | BPF_IMM, 0, 0, 0xFFFFFFFF), (BPF_ALU | BPF_ADD | BPF_K, 0, 0, 2))
            == 1
        )
        assert (
            accumulator(
                (BPF_ALU | BPF_NEG, 0, 0, 0),
            )
            == 0
        )
        assert accumulator((BPF_LD | BPF_IMM, 0, 0, 1), (BPF_ALU | BPF_NEG, 0, 0, 0)) == 0xFFFFFFFF

    def test_the_second_operand_can_come_from_the_index_register(self) -> None:
        assert (
            accumulator(
                (BPF_LD | BPF_IMM, 0, 0, 10),
                (BPF_LDX | BPF_IMM, 0, 0, 4),
                (BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0),
            )
            == 40
        )

    @pytest.mark.parametrize("operation", [BPF_DIV, BPF_MOD])
    def test_dividing_by_zero_drops_the_packet(self, operation: int) -> None:
        assert (
            accumulator((BPF_LD | BPF_IMM, 0, 0, 10), (BPF_ALU | operation | BPF_K, 0, 0, 0)) == 0
        )

    def test_conditional_jumps(self) -> None:
        keep = (BPF_RET | BPF_K, 0, 0, ACCEPTED)
        drop = (BPF_RET | BPF_K, 0, 0, 0)
        for operation, k, expected in (
            (BPF_JEQ, 10, ACCEPTED),
            (BPF_JEQ, 11, 0),
            (BPF_JGE, 10, ACCEPTED),
            (BPF_JGE, 11, 0),
            (BPF_JSET, 0b0010, ACCEPTED),
            (BPF_JSET, 0b0101, 0),
        ):
            result = run(
                program(
                    (BPF_LD | BPF_IMM, 0, 0, 10),
                    (BPF_JMP | operation | BPF_K, 0, 1, k),
                    keep,
                    drop,
                ),
                b"",
            )
            assert result == expected, (operation, k)

    def test_unconditional_jump(self) -> None:
        assert (
            run(
                program(
                    (BPF_JMP | BPF_JA, 0, 0, 1),
                    (BPF_RET | BPF_K, 0, 0, 0),
                    (BPF_RET | BPF_K, 0, 0, ACCEPTED),
                ),
                b"",
            )
            == ACCEPTED
        )

    def test_registers_start_at_zero(self) -> None:
        assert accumulator((BPF_MISC | BPF_TXA, 0, 0, 0)) == 0
        assert accumulator((BPF_MISC | BPF_TAX, 0, 0, 0)) == 0


class TestBadPrograms:
    def test_unknown_instruction(self) -> None:
        with pytest.raises(FilterError, match="unknown BPF instruction 0xff"):
            run(program((0xFF, 0, 0, 0)), b"")

    def test_running_off_the_end(self) -> None:
        with pytest.raises(FilterError, match="ran past its last instruction"):
            run(program((BPF_LD | BPF_IMM, 0, 0, 1)), b"")

    def test_jumping_off_the_end(self) -> None:
        with pytest.raises(FilterError, match="ran past its last instruction"):
            run(program((BPF_JMP | BPF_JA, 0, 0, 99), (BPF_RET | BPF_K, 0, 0, 1)), b"")

    def test_a_memory_slot_that_does_not_exist(self) -> None:
        with pytest.raises(FilterError, match=r"M\[16\] is outside the 16 scratch"):
            run(program((BPF_LD | BPF_MEM, 0, 0, 16), (BPF_RET | BPF_A, 0, 0, 0)), b"")

    def test_an_empty_program(self) -> None:
        with pytest.raises(FilterError, match="ran past its last instruction"):
            run(Program(()), b"")


@pytest.mark.macos
class TestAgainstLibpcap:
    """libpcap runs the same instructions in C, in ``bpf_filter``."""

    @staticmethod
    def their_filter(program_: Program, packet: bytes, wire_length: int) -> int:
        lib = load()
        lib.bpf_filter.restype = c_uint
        lib.bpf_filter.argtypes = [POINTER(BpfInsn), POINTER(c_ubyte), c_uint, c_uint]
        instructions = (BpfInsn * len(program_))(
            *(BpfInsn(each.code, each.jt, each.jf, each.k) for each in program_)
        )
        buffer = (c_ubyte * max(len(packet), 1))(*packet)
        return int(lib.bpf_filter(instructions, buffer, wire_length, len(packet)))

    @given(packet=st.binary(max_size=80))
    def test_the_dns_filter_agrees(self, packet: bytes) -> None:
        assert run(DNS_OVER_ETHERNET, packet) == self.their_filter(
            DNS_OVER_ETHERNET, packet, len(packet)
        )

    @pytest.mark.parametrize(
        "expression",
        ["udp port 53", "tcp port 443", "ip and not port 22", "len > 100", "ip[0] & 0xf != 5"],
    )
    @given(packet=st.binary(min_size=14, max_size=80))
    def test_compiled_filters_agree(self, expression: str, packet: bytes) -> None:
        compiled = _compiled(expression)
        assert run(compiled, packet, 1514) == self.their_filter(compiled, packet, 1514)


@functools.cache
def _compiled(expression: str) -> Program:
    """Compile once for Ethernet, not once per Hypothesis example."""
    return compile_filter(expression, 1, 262144)
