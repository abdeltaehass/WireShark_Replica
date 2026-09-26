"""The link and network protocols, over packets built for the purpose.

What the fields decode to is checked against tshark in test_tshark.py, over
the sample captures. These are the things tshark can't answer: the one-line
summaries, the guesses a header leaves open, and what happens when a packet
runs out in the middle of one.
"""

import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from packets import ethernet, icmp, icmp_echo, icmpv6, ipv4, ipv6, udp
from pilotfish.core.dissect import ProtocolTree, dissect
from pilotfish.core.packet import Packet
from pilotfish.core.protocols.checksum import ChecksumStatus

ETHERNET = 1
LOOPBACK = 0
RAW = 101

CLIENT = "02:00:00:00:00:02"
SERVER = "02:00:00:00:00:01"


def decode(data: bytes, link_type: int = ETHERNET) -> ProtocolTree:
    return dissect(Packet(0, len(data), link_type, data), number=1)


class TestEthernet:
    def test_addresses_and_type(self) -> None:
        tree = decode(ethernet(ipv4(udp(1, 2))))
        assert tree.get("eth.src") == CLIENT
        assert tree.get("eth.dst") == SERVER
        assert tree.get("eth.type") == 0x0800
        assert tree.layers[1].summary == f"Ethernet II, Src: {CLIENT}, Dst: {SERVER}"

    def test_a_small_type_is_an_802_3_length(self) -> None:
        # Below 1500 the field counts the bytes that follow, and an LLC
        # header comes next, which pilotfish doesn't decode.
        frame = bytes.fromhex("0180c2000000") + bytes.fromhex("020000000001")
        tree = decode(frame + struct.pack(">H", 8) + b"\x42\x42\x03\x00\x00\x00\x00\x00")
        assert tree.get("eth.len") == 8
        assert tree.get("eth.type") is None
        assert tree.protocols == ("frame", "eth", "data")

    def test_a_frame_cut_short(self) -> None:
        tree = decode(bytes(10))
        assert tree.error == "eth: eth.src needs 6 bytes at offset 6, but the packet has 4"
        assert tree.get("eth.dst") == "00:00:00:00:00:00"


class TestVlan:
    def test_the_tag_and_what_it_carries(self) -> None:
        tag = struct.pack(">HH", 3 << 13 | 100, 0x0800)
        tree = decode(ethernet(tag + ipv4(icmp_echo(), protocol=1), ethertype=0x8100))
        assert (tree.get("vlan.priority"), tree.get("vlan.id")) == (3, 100)
        assert tree.get("vlan.dei") is False
        assert tree.protocols == ("frame", "eth", "vlan", "ip", "icmp")
        assert tree.layers[2].summary == "802.1Q Virtual LAN, PRI: 3, DEI: 0, ID: 100"

    def test_the_drop_eligible_bit(self) -> None:
        tag = struct.pack(">HH", 0x1000 | 7, 0x0806)
        tree = decode(ethernet(tag + bytes(28), ethertype=0x8100))
        assert tree.get("vlan.dei") is True
        assert tree.get("vlan.id") == 7


def arp(
    opcode: int = 1,
    *,
    hardware: int = 1,
    sender: str = "192.0.2.1",
    target: str = "192.0.2.2",
    sender_mac: str = CLIENT,
) -> bytes:
    return struct.pack(
        ">HHBBH6s4s6s4s",
        hardware,
        0x0800,
        6,
        4,
        opcode,
        bytes.fromhex(sender_mac.replace(":", "")),
        IPv4Address(sender).packed,
        bytes(6),
        IPv4Address(target).packed,
    )


class TestArp:
    def test_a_request_asks_who_has_an_address(self) -> None:
        tree = decode(ethernet(arp(1), ethertype=0x0806))
        assert tree.get("arp.opcode") == 1
        assert tree.get("arp.src.proto_ipv4") == IPv4Address("192.0.2.1")
        assert tree.info == "Who has 192.0.2.2? Tell 192.0.2.1"

    def test_a_reply_says_where_it_is(self) -> None:
        tree = decode(ethernet(arp(2), ethertype=0x0806))
        assert tree.info == f"192.0.2.1 is at {CLIENT}"

    def test_addresses_of_another_kind_are_left_alone(self) -> None:
        # Only Ethernet and IPv4 addresses have fields of their own.
        tree = decode(ethernet(arp(1, hardware=6), ethertype=0x0806))
        assert tree.get("arp.hw.type") == 6
        assert tree.get("arp.src.hw_mac") is None
        assert tree.error is None

    def test_padding_after_the_addresses_is_not_decoded(self) -> None:
        # A frame is padded out to 60 bytes, which belongs to Ethernet.
        tree = decode(ethernet(arp(1) + bytes(18), ethertype=0x0806))
        assert tree.protocols == ("frame", "eth", "arp")


class TestLoopback:
    def test_the_family_in_this_machine_s_byte_order(self) -> None:
        tree = decode(struct.pack("<I", 2) + ipv4(icmp_echo(), protocol=1), LOOPBACK)
        assert tree.get("null.family") == 2
        assert tree.protocols == ("frame", "null", "ip", "icmp")

    def test_a_capture_from_a_machine_of_the_other_byte_order(self) -> None:
        tree = decode(struct.pack(">I", 30) + ipv6(b"", next_header=59), LOOPBACK)
        assert tree.get("null.family") == 30
        assert tree.protocols == ("frame", "null", "ipv6")

    @pytest.mark.parametrize("family", [24, 28, 30])
    def test_every_bsd_numbered_ipv6_differently(self, family: int) -> None:
        tree = decode(struct.pack("<I", family) + ipv6(b"", next_header=59), LOOPBACK)
        assert tree.protocols == ("frame", "null", "ipv6")

    def test_a_family_nothing_decodes(self) -> None:
        tree = decode(struct.pack("<I", 777) + bytes(4), LOOPBACK)
        assert tree.get("null.family") == 777
        assert tree.protocols == ("frame", "null", "data")


class TestIPv4:
    def test_a_good_checksum(self) -> None:
        tree = decode(ethernet(ipv4(icmp_echo(), protocol=1)))
        assert tree.get("ip.checksum.status") == ChecksumStatus.GOOD

    def test_a_checksum_that_does_not_add_up(self) -> None:
        tree = decode(ethernet(ipv4(icmp_echo(), protocol=1, break_checksum=True)))
        assert tree.get("ip.checksum.status") == ChecksumStatus.BAD

    def test_a_header_cut_short_can_t_be_checked(self) -> None:
        whole = ethernet(ipv4(icmp_echo(), protocol=1))
        tree = decode(whole[:28])  # the header runs out halfway
        assert tree.get("ip.checksum.status") == ChecksumStatus.UNVERIFIED
        assert tree.error is not None

    def test_a_header_shorter_than_it_could_be(self) -> None:
        broken = bytearray(ethernet(ipv4(b"x")))
        broken[14] = 0x43  # four words of header, where five is the least
        assert decode(bytes(broken)).error == "ip: a header of 12 bytes is shorter than IPv4's 20"

    def test_options_after_the_fixed_header(self) -> None:
        # A record route option, room for three addresses, then end-of-options.
        options = struct.pack(">BBB", 7, 11, 4) + IPv4Address("192.0.2.9").packed + bytes(5)
        tree = decode(ethernet(ipv4(icmp_echo(), protocol=1, options=options)))
        assert tree.get("ip.hdr_len") == 32
        assert tree.values("ip.opt.type") == [7, 0]  # record route, then the end
        assert tree.get("ip.opt.len") == 11
        assert tree.protocols[-1] == "icmp"  # the options didn't lose the payload

    def test_the_first_fragment_holds_the_start_of_a_message(self) -> None:
        tree = decode(ethernet(ipv4(icmp_echo(), protocol=1, flags=0b001)))
        assert tree.protocols == ("frame", "eth", "ip", "data")
        assert "Fragmented IP protocol" in tree.info

    def test_a_later_fragment_has_no_header_to_read(self) -> None:
        tree = decode(ethernet(ipv4(bytes(16), protocol=1, fragment_offset=185, flags=0)))
        assert tree.info == "Fragmented IP protocol (proto=1, off=1480, ID=0001)"

    def test_a_payload_the_capture_cut_short(self) -> None:
        whole = ethernet(ipv4(icmp_echo(payload=b"x" * 40), protocol=1))
        tree = decode(whole[:40])
        # The checksum covers bytes that weren't captured, so it isn't checked.
        assert tree.get("icmp.checksum.status") == ChecksumStatus.UNVERIFIED


class TestIPv6:
    def test_the_fixed_header(self) -> None:
        tree = decode(ethernet(ipv6(icmpv6(128, 0, bytes(4)), next_header=58), ethertype=0x86DD))
        assert tree.get("ipv6.src") == IPv6Address("2001:db8::1")
        assert tree.get("ipv6.hlim") == 64
        assert tree.layers[1].summary.startswith("Ethernet II")
        assert tree.layers[2].summary == (
            "Internet Protocol Version 6, Src: 2001:db8::1, Dst: 2001:db8::2"
        )

    def test_nothing_follows_the_header(self) -> None:
        tree = decode(ethernet(ipv6(b"", next_header=59), ethertype=0x86DD))
        assert tree.protocols == ("frame", "eth", "ipv6")

    def test_an_extension_header_chain(self) -> None:
        hop_by_hop = struct.pack(">BB", 60, 0) + struct.pack(">BB", 1, 4) + bytes(4)
        destination = struct.pack(">BB", 58, 0) + struct.pack(">BB", 1, 4) + bytes(4)
        message = icmpv6(128, 0, struct.pack(">HH", 1, 1))
        packet = ipv6(hop_by_hop + destination + message, next_header=0)
        tree = decode(ethernet(packet, ethertype=0x86DD))
        assert tree.protocols[2:] == ("ipv6", "ipv6.hopopts", "ipv6.dstopts", "icmpv6")
        assert tree.get("ipv6.hopopts.nxt") == 60
        assert tree.get("ipv6.dstopts.len_oct") == 8

    def test_a_fragment_holds_only_part_of_a_message(self) -> None:
        fragment = struct.pack(">BBHI", 58, 0, 185 << 3, 0xF00D)
        tree = decode(ethernet(ipv6(fragment + bytes(8), next_header=44), ethertype=0x86DD))
        assert tree.get("ipv6.fraghdr.offset") == 185
        assert tree.get("ipv6.fraghdr.more") is False
        assert tree.protocols[-1] == "data"


class TestIcmp:
    def test_an_echo_request(self) -> None:
        tree = decode(ethernet(ipv4(icmp_echo(8, identifier=0x1234, sequence=7), protocol=1)))
        assert tree.get("icmp.type") == 8
        assert tree.info == "Echo (ping) request  id=0x1234, seq=7"

    def test_an_error_quotes_the_packet_that_caused_it(self) -> None:
        original = ipv4(udp(50000, 53), protocol=17)
        message = icmp(3, 3, bytes(4) + original[:28])
        tree = decode(ethernet(ipv4(message, protocol=1)))
        assert tree.info == "Destination unreachable (Port unreachable)"
        # The quoted packet is decoded, but doesn't take over the summary.
        assert tree.protocols[3:] == ("icmp", "ip", "data")
        assert tree.values("ip.src") == [IPv4Address("192.0.2.1")] * 2
        assert tree.protocol == "icmp"

    def test_a_message_checksum_that_does_not_add_up(self) -> None:
        tree = decode(ethernet(ipv4(icmp_echo(break_checksum=True), protocol=1)))
        assert tree.get("icmp.checksum.status") == ChecksumStatus.BAD

    def test_a_type_pilotfish_has_nothing_to_say_about(self) -> None:
        tree = decode(ethernet(ipv4(icmp(30, 0, bytes(8)), protocol=1)))
        assert tree.info == "Type 30"
        assert tree.protocols[-1] == "data"


class TestIcmpv6:
    def message(self, kind: int, code: int, rest: bytes) -> ProtocolTree:
        packet = ipv6(icmpv6(kind, code, rest), next_header=58)
        return decode(ethernet(packet, ethertype=0x86DD))

    def test_an_echo_request_checksummed_over_the_addresses(self) -> None:
        tree = self.message(128, 0, struct.pack(">HH", 0x007F, 1))
        assert tree.get("icmpv6.checksum.status") == ChecksumStatus.GOOD
        assert tree.info == "Echo (ping) request id=0x007f, seq=1"

    def test_a_checksum_taken_over_the_wrong_addresses(self) -> None:
        # Checksummed as if it were going somewhere else.
        message = icmpv6(128, 0, struct.pack(">HH", 1, 1), destination="2001:db8::9")
        tree = decode(ethernet(ipv6(message, next_header=58), ethertype=0x86DD))
        assert tree.get("icmpv6.checksum.status") == ChecksumStatus.BAD

    def test_a_neighbour_solicitation_asks_for_an_address(self) -> None:
        option = struct.pack(">BB", 1, 1) + bytes.fromhex(CLIENT.replace(":", ""))
        tree = self.message(135, 0, bytes(4) + IPv6Address("2001:db8::2").packed + option)
        assert tree.get("icmpv6.nd.ns.target_address") == IPv6Address("2001:db8::2")
        assert tree.get("icmpv6.opt.src_linkaddr") == CLIENT
        assert tree.info == f"Neighbor Solicitation for 2001:db8::2 from {CLIENT}"

    def test_a_neighbour_advertisement_answers_with_its_flags(self) -> None:
        option = struct.pack(">BB", 2, 1) + bytes.fromhex(SERVER.replace(":", ""))
        rest = struct.pack(">I", 0b011 << 29) + IPv6Address("2001:db8::2").packed + option
        tree = self.message(136, 0, rest)
        assert tree.get("icmpv6.nd.na.flag.r") is False
        assert tree.get("icmpv6.nd.na.flag.s") is True
        assert tree.info == f"Neighbor Advertisement 2001:db8::2 (sol, ovr) is at {SERVER}"

    def test_a_router_advertisement_carries_an_mtu(self) -> None:
        option = struct.pack(">BBHI", 5, 1, 0, 1500)
        tree = self.message(134, 0, struct.pack(">BBHII", 64, 0, 1800, 0, 0) + option)
        assert tree.get("icmpv6.nd.ra.router_lifetime") == 1800
        assert tree.get("icmpv6.opt.mtu") == 1500
        assert tree.info == "Router Advertisement"

    def test_an_error_quotes_the_packet_that_caused_it(self) -> None:
        original = ipv6(udp(50000, 53), next_header=17)
        tree = self.message(1, 4, bytes(4) + original)
        assert tree.info == "Destination Unreachable (Port unreachable)"
        assert tree.protocols[3:] == ("icmpv6", "ipv6", "data")
        assert tree.protocol == "icmpv6"
