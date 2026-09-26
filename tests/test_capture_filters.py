import re

import pytest

from loopback import UDP_PAYLOAD_OFFSET, LoopbackTraffic, carrying, read_until
from packets import DNS_OVER_ETHERNET
from pilotfish.core.capture import (
    MAX_SNAPLEN,
    BpfSource,
    CaptureOptions,
    PacketSource,
    PcapSource,
    compile_filter,
)
from pilotfish.core.capture.libpcap import PCAP_NETMASK_UNKNOWN, interface_netmask
from pilotfish.core.filters import FilterError
from pilotfish.core.packet import Packet

type SourceClass = type[PcapSource] | type[BpfSource]

ETHERNET = 1
LOOPBACK = 0

pytestmark = pytest.mark.macos


def test_compiles_the_same_program_as_tcpdump() -> None:
    assert compile_filter("udp port 53", ETHERNET, MAX_SNAPLEN) == DNS_OVER_ETHERNET


def test_a_filter_depends_on_the_link_type() -> None:
    # Loopback packets start with an address family, not an Ethernet header,
    # so the same filter has to look in different places.
    ethernet = compile_filter("udp port 53", ETHERNET, MAX_SNAPLEN)
    loopback = compile_filter("udp port 53", LOOPBACK, MAX_SNAPLEN)
    assert ethernet != loopback
    assert loopback.disassemble()[0] == "(000) ld       [0]"


def test_the_snapshot_length_is_what_a_match_returns() -> None:
    program = compile_filter("udp port 53", ETHERNET, 96)
    assert program.disassemble()[-2:] == ["(018) ret      #96", "(019) ret      #0"]


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        ("udp porrt 53", "can't parse filter expression: syntax error"),
        ("port 99999999", "illegal port number 99999999 > 65535"),
    ],
)
def test_a_filter_that_will_not_compile(expression: str, message: str) -> None:
    expected = re.escape(f'capture filter "{expression}": {message}')
    with pytest.raises(FilterError, match=f"^{expected}$"):
        compile_filter(expression, ETHERNET, MAX_SNAPLEN)


def test_netmask_of_an_unknown_interface() -> None:
    assert interface_netmask("nope0") == PCAP_NETMASK_UNKNOWN


@pytest.mark.usefixtures("capture_access")
class TestLiveFilters:
    @pytest.mark.parametrize("source_class", [PcapSource, BpfSource])
    def test_only_matching_packets_arrive(
        self, source_class: SourceClass, capture_access: None
    ) -> None:
        with LoopbackTraffic() as wanted, LoopbackTraffic() as other:
            source = source_class("lo0", CaptureOptions(filter=f"udp port {wanted.port}"))
            try:
                for _ in range(3):
                    other.send()
                payload = wanted.send()
                packet = read_until(source, carrying(payload))
                assert packet.data[UDP_PAYLOAD_OFFSET:] == payload
                assert all(_port(each) == wanted.port for each in _drain(source))
                statistics = source.stats()
            finally:
                source.close()
            # The kernel still counted the packets it dropped for us.
            assert statistics.received > 1

    @pytest.mark.parametrize("source_class", [PcapSource, BpfSource])
    def test_the_program_is_the_compiled_filter(self, source_class: SourceClass) -> None:
        source = source_class("lo0", CaptureOptions(filter="udp port 53"))
        try:
            assert source.program == compile_filter("udp port 53", LOOPBACK, MAX_SNAPLEN)
        finally:
            source.close()

    @pytest.mark.parametrize("source_class", [PcapSource, BpfSource])
    def test_no_filter_leaves_the_program_unset(self, source_class: SourceClass) -> None:
        source = source_class("lo0")
        try:
            assert source.program is None
        finally:
            source.close()

    @pytest.mark.parametrize("source_class", [PcapSource, BpfSource])
    def test_a_bad_filter_is_reported_with_its_text(self, source_class: SourceClass) -> None:
        with pytest.raises(FilterError, match=r'^capture filter "udp porrt 53": '):
            source_class("lo0", CaptureOptions(filter="udp porrt 53"))


def _drain(source: PacketSource, idle_reads: int = 3) -> list[Packet]:
    """Every packet waiting, up to a few reads that come back empty."""
    packets = []
    empty = 0
    while empty < idle_reads:
        packet = source.read()
        if packet is None:
            empty += 1
        else:
            packets.append(packet)
    return packets


def _port(packet: Packet) -> int:
    """The destination port of a UDP packet captured on loopback."""
    return int.from_bytes(packet.data[UDP_PAYLOAD_OFFSET - 6 : UDP_PAYLOAD_OFFSET - 4], "big")
