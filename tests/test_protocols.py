"""The link and network protocols, over packets built for the purpose.

What the fields decode to is checked against tshark in test_tshark.py, over
the sample captures. These are the things tshark can't answer: the one-line
summaries, the guesses a header leaves open, and what happens when a packet
runs out in the middle of one.
"""

import struct
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from packets import (
    checksum,
    ethernet,
    icmp,
    icmp_echo,
    icmpv6,
    ipv4,
    ipv6,
    pseudo_header,
    tcp,
    udp,
)
from pilotfish.core.dissect import ProtocolTree, Session, dissect
from pilotfish.core.packet import Packet
from pilotfish.core.protocols.checksum import ChecksumStatus

ETHERNET = 1
LOOPBACK = 0
RAW = 101

CLIENT = "02:00:00:00:00:02"
SERVER = "02:00:00:00:00:01"


def decode(data: bytes, link_type: int = ETHERNET, *, original: int | None = None) -> ProtocolTree:
    """Decode one packet. ``original`` says how long the frame was on the wire,
    for a capture that a snapshot length cut short."""
    length = len(data) if original is None else original
    return dissect(Packet(0, length, link_type, data), number=1)


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
        tree = decode(whole[:40], original=len(whole))
        # The checksum covers bytes that weren't captured, so it isn't checked.
        assert tree.get("icmp.checksum.status") == ChecksumStatus.UNVERIFIED

    def test_a_length_longer_than_the_frame_is_the_frame_s_word(self) -> None:
        # A sender that claimed more than it sent, rather than a capture that
        # cut a frame short: what is there is all there ever was, so the
        # checksum over it still means something. Wireshark reads it that way.
        whole = bytearray(ethernet(ipv4(icmp_echo(payload=b"x" * 8), protocol=1)))
        whole[16:18] = (600).to_bytes(2, "big")  # ip.len, far past the frame
        tree = decode(bytes(whole))
        assert tree.get("ip.len") == 600
        assert tree.get("icmp.checksum.status") == ChecksumStatus.GOOD


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
        datagram = udp(50000, 53, source="192.0.2.1", destination="192.0.2.2")
        original = ipv4(datagram, protocol=17)
        message = icmp(3, 3, bytes(4) + original[:28])
        tree = decode(ethernet(ipv4(message, protocol=1)))
        assert tree.info == "Destination unreachable (Port unreachable)"
        # The quoted packet is decoded, but doesn't take over the summary.
        assert tree.protocols[3:] == ("icmp", "ip", "udp")
        assert tree.values("ip.src") == [IPv4Address("192.0.2.1")] * 2
        assert tree.get("udp.dstport") == 53
        # An error quotes only the front of what caused it, so the checksum
        # has nothing to add up over.
        assert tree.get("udp.checksum.status") == ChecksumStatus.UNVERIFIED
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
        # This error quoted the whole datagram, so what it carried is there too.
        assert tree.protocols[3:] == ("icmpv6", "ipv6", "udp", "data")
        assert tree.protocol == "icmpv6"


CLIENT_ADDRESS = "192.0.2.1"
SERVER_ADDRESS = "192.0.2.2"
CLIENT_PORT = 50000
SERVER_PORT = 80

SYN = 0x002
ACK = 0x010
PUSH = 0x008


class Transport:
    """Builds the frames of one conversation, either way round.

    A transport checksum covers the addresses as well, and the analysis only
    makes sense if both directions are the same conversation, so which way a
    packet is going has to reach the builders.
    """

    protocol: int

    def build(self, ports: tuple[int, int], addresses: tuple[str, str], **rest: Any) -> bytes:
        raise NotImplementedError

    def frame(self, *, from_client: bool = True, **rest: Any) -> bytes:
        ports = (CLIENT_PORT, SERVER_PORT) if from_client else (SERVER_PORT, CLIENT_PORT)
        addresses = (
            (CLIENT_ADDRESS, SERVER_ADDRESS) if from_client else (SERVER_ADDRESS, CLIENT_ADDRESS)
        )
        source, destination = addresses
        segment = self.build(ports, addresses, **rest)
        return ethernet(
            ipv4(segment, self.protocol, source=source, destination=destination),
            source=CLIENT if from_client else SERVER,
            destination=SERVER if from_client else CLIENT,
        )

    def conversation(self, *frames: bytes) -> list[ProtocolTree]:
        """Decode frames of one conversation, which have to share a session.

        They are one second apart, as the frame builder stamps them.
        """
        session = Session()
        return [
            dissect(
                Packet(number * 1_000_000_000, len(data), ETHERNET, data), number, session=session
            )
            for number, data in enumerate(frames, start=1)
        ]


class TestUdp(Transport):
    protocol = 17

    def build(self, ports: tuple[int, int], addresses: tuple[str, str], **rest: Any) -> bytes:
        source, destination = addresses
        return udp(*ports, source=source, destination=destination, **rest)

    def test_the_header_and_what_it_says_about_itself(self) -> None:
        tree = decode(ethernet(ipv4(udp(CLIENT_PORT, 53, b"query"))))
        assert tree.get("udp.srcport") == CLIENT_PORT
        assert tree.get("udp.dstport") == 53
        assert tree.get("udp.length") == 13
        assert tree.get("udp.payload") == b"query"
        assert tree.info == "50000 → 53 Len=5"
        assert tree.layers[3].summary == "User Datagram Protocol, Src Port: 50000, Dst Port: 53"

    def test_a_datagram_with_no_checksum_is_not_a_damaged_one(self) -> None:
        # Over IPv4 a sender may leave the checksum out, and says so with zero.
        tree = decode(ethernet(ipv4(udp(CLIENT_PORT, 53))))
        assert tree.get("udp.checksum") == 0
        assert tree.get("udp.checksum.status") == ChecksumStatus.NOT_PRESENT

    def test_a_checksum_taken_over_the_pseudo_header(self) -> None:
        tree = decode(self.frame())
        assert tree.get("udp.checksum.status") == ChecksumStatus.GOOD

    def test_a_checksum_that_does_not_add_up(self) -> None:
        tree = decode(self.frame(break_checksum=True))
        assert tree.get("udp.checksum.status") == ChecksumStatus.BAD

    def test_over_ipv6_the_checksum_covers_the_addresses_it_travelled_between(self) -> None:
        datagram = udp(CLIENT_PORT, 53, source="2001:db8::1", destination="2001:db8::2")
        tree = decode(ethernet(ipv6(datagram), ethertype=0x86DD))
        assert tree.get("udp.checksum.status") == ChecksumStatus.GOOD

    def test_a_checksum_the_hardware_had_not_finished(self) -> None:
        # See the same case in TestTcp: the sum of the pseudo header on its own
        # is what checksum offloading leaves behind.
        half_done = bytearray(udp(CLIENT_PORT, 53))
        pseudo = pseudo_header(CLIENT_ADDRESS, SERVER_ADDRESS, 17, len(half_done))
        half_done[6:8] = (~checksum(pseudo) & 0xFFFF).to_bytes(2, "big")
        tree = decode(ethernet(ipv4(bytes(half_done))))
        assert tree.get("udp.checksum.status") == ChecksumStatus.GOOD

    def test_a_length_shorter_than_the_header_itself(self) -> None:
        broken = bytearray(udp(CLIENT_PORT, 53))
        broken[4:6] = (4).to_bytes(2, "big")
        tree = decode(ethernet(ipv4(bytes(broken))))
        assert tree.error == "udp: a length of 4 is shorter than UDP's header"

    def test_both_directions_are_one_stream(self) -> None:
        trees = self.conversation(
            self.frame(),
            self.frame(from_client=False),
            ethernet(ipv4(udp(50001, SERVER_PORT))),
        )
        assert [tree.get("udp.stream") for tree in trees] == [0, 0, 1]

    def test_a_port_nothing_is_registered_for_is_left_as_data(self) -> None:
        tree = decode(ethernet(ipv4(udp(CLIENT_PORT, 50001, b"whatever"))))
        assert tree.protocols == ("frame", "eth", "ip", "udp", "data")
        assert tree.get("data.data") == b"whatever"


def option(kind: int, *body: int) -> bytes:
    """One TCP option: its kind, its own length, and its body."""
    return bytes([kind, len(body) + 2, *body])


NOP = bytes([1])
END = bytes([0])


class TestTcp(Transport):
    protocol = 6

    def build(self, ports: tuple[int, int], addresses: tuple[str, str], **rest: Any) -> bytes:
        source, destination = addresses
        return tcp(*ports, source=source, destination=destination, **rest)

    def handshake(self, **rest: Any) -> list[bytes]:
        """The three frames that open a connection, at sequence 100 and 500."""
        return [
            self.frame(seq=100, flags=SYN, **rest),
            self.frame(seq=500, ack=101, flags=SYN | ACK, from_client=False, **rest),
            self.frame(seq=101, ack=501, flags=ACK),
        ]

    def test_the_header(self) -> None:
        tree = decode(self.frame(payload=b"hello", seq=1, flags=PUSH | ACK))
        assert tree.get("tcp.srcport") == CLIENT_PORT
        assert tree.get("tcp.dstport") == SERVER_PORT
        assert tree.get("tcp.hdr_len") == 20
        assert tree.get("tcp.len") == 5
        assert tree.get("tcp.window_size_value") == 8192
        assert tree.get("tcp.payload") == b"hello"
        assert tree.layers[3].summary == (
            "Transmission Control Protocol, Src Port: 50000, Dst Port: 80, Seq: 1, Ack: 1, Len: 5"
        )

    def test_the_flags_are_spelled_out_two_ways(self) -> None:
        tree = decode(self.frame(seq=0, flags=SYN | ACK))
        assert tree.get("tcp.flags.syn") is True
        assert tree.get("tcp.flags.ack") is True
        assert tree.get("tcp.flags.fin") is False
        assert tree.get("tcp.flags.str") == "·······A··S·"
        assert tree.info == "50000 → 80 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0"

    def test_a_header_shorter_than_it_could_be(self) -> None:
        broken = bytearray(tcp(CLIENT_PORT, SERVER_PORT))
        broken[12] = 0x40  # four words of header, where five is the least
        tree = decode(ethernet(ipv4(bytes(broken), 6)))
        assert tree.error == "tcp: a header of 16 bytes is shorter than TCP's 20"

    def test_sequence_numbers_count_from_the_handshake(self) -> None:
        # Where a connection's numbers start is its own business, so Wireshark
        # counts from there, and so does pilotfish.
        trees = self.conversation(
            *self.handshake(),
            self.frame(payload=b"hi", seq=101, ack=501, flags=PUSH | ACK),
        )
        assert [tree.get("tcp.seq") for tree in trees] == [0, 0, 1, 1]
        assert [tree.get("tcp.ack") for tree in trees] == [None, 1, 1, 1]
        assert trees[0].get("tcp.seq_raw") == 100
        assert trees[3].get("tcp.nxtseq") == 3

    def test_a_connection_joined_halfway_counts_from_the_first_segment(self) -> None:
        # With no handshake to count from, Wireshark makes the first segment it
        # sees sequence 1, so the numbers still start somewhere near zero.
        trees = self.conversation(
            self.frame(payload=b"hi", seq=4_000_000, ack=9_000_000, flags=PUSH | ACK),
            self.frame(seq=9_000_000, ack=4_000_002, flags=ACK, from_client=False),
        )
        assert (trees[0].get("tcp.seq"), trees[0].get("tcp.ack")) == (1, 1)
        assert (trees[1].get("tcp.seq"), trees[1].get("tcp.ack")) == (1, 3)
        # Nothing said what the scaling is, and Wireshark says so with -1.
        assert trees[0].get("tcp.window_size_scalefactor") == -1

    def test_the_options_a_handshake_agrees_on(self) -> None:
        options = option(2, 0x05, 0xB4) + option(3, 7) + NOP + option(4) + NOP + NOP
        tree = decode(self.frame(seq=100, flags=SYN, options=options))
        assert tree.get("tcp.hdr_len") == 32
        assert tree.get("tcp.options.mss_val") == 1460
        assert tree.get("tcp.options.wscale.shift") == 7
        assert tree.get("tcp.options.wscale.multiplier") == 128
        assert tree.get("tcp.options.sack_perm") == bytes([4, 2])
        assert tree.values("tcp.option_kind") == [2, 3, 1, 4, 1, 1]
        assert tree.get("tcp.len") == 0

    def test_the_padding_after_the_end_of_the_option_list_is_not_payload(self) -> None:
        # Wireshark counts every padding byte as another end-of-list option.
        options = option(2, 0x05, 0xB4) + END * 4
        tree = decode(self.frame(payload=b"hi", seq=1, flags=PUSH | ACK, options=options))
        assert tree.values("tcp.options.eol") == [END] * 4
        assert tree.get("tcp.len") == 2
        assert tree.get("tcp.payload") == b"hi"

    def test_an_option_that_claims_no_length(self) -> None:
        tree = decode(self.frame(seq=100, flags=SYN, options=bytes([2, 1, 0, 0])))
        assert tree.error == "tcp: option 2 claims a length of 1"

    def test_selective_acknowledgement_names_what_arrived(self) -> None:
        # The edges are sequence numbers of the other direction, so they count
        # from where that direction started.
        blocks = (201).to_bytes(4, "big") + (301).to_bytes(4, "big")
        options = bytes([5, 10]) + blocks + NOP + NOP
        trees = self.conversation(
            *self.handshake(),
            self.frame(seq=501, ack=101, flags=ACK, options=options, from_client=False),
        )
        assert trees[3].get("tcp.options.sack.count") == 1
        assert trees[3].get("tcp.options.sack_le") == 101
        assert trees[3].get("tcp.options.sack_re") == 201

    def test_timestamps(self) -> None:
        options = option(8, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x2A) + NOP + NOP
        tree = decode(self.frame(seq=1, flags=ACK, options=options))
        assert tree.get("tcp.options.timestamp.tsval") == 12345
        assert tree.get("tcp.options.timestamp.tsecr") == 42

    def test_the_window_is_scaled_once_the_handshake_has_agreed_a_shift(self) -> None:
        trees = self.conversation(*self.handshake(window=1000, options=option(3, 7) + NOP))
        # The handshake itself means what it says; after it the shift applies.
        assert trees[0].get("tcp.window_size") == 1000
        assert trees[0].get("tcp.window_size_scalefactor") is None
        assert trees[2].get("tcp.window_size_value") == 8192
        assert trees[2].get("tcp.window_size") == 8192 * 128
        assert trees[2].get("tcp.window_size_scalefactor") == 128

    def test_a_handshake_that_never_asked_for_scaling(self) -> None:
        # Wireshark tells "nobody asked" (-2) from "I never saw them ask" (-1).
        trees = self.conversation(*self.handshake())
        assert trees[2].get("tcp.window_size_scalefactor") == -2
        assert trees[2].get("tcp.window_size") == 8192

    def test_a_checksum_over_the_pseudo_header(self) -> None:
        tree = decode(self.frame(payload=b"hello", seq=1, flags=PUSH | ACK))
        assert tree.get("tcp.checksum.status") == ChecksumStatus.GOOD

    def test_a_checksum_that_does_not_add_up(self) -> None:
        tree = decode(self.frame(payload=b"hello", seq=1, break_checksum=True))
        assert tree.get("tcp.checksum.status") == ChecksumStatus.BAD

    def test_a_checksum_the_hardware_had_not_finished(self) -> None:
        # A packet captured on its way out can carry the sum of the pseudo
        # header alone, which the card would have finished. Wireshark reads
        # that as checksum offloading rather than as damage.
        half_done = bytearray(tcp(CLIENT_PORT, SERVER_PORT, b"hello", seq=1, flags=PUSH | ACK))
        pseudo = pseudo_header(CLIENT_ADDRESS, SERVER_ADDRESS, 6, len(half_done))
        half_done[16:18] = (~checksum(pseudo) & 0xFFFF).to_bytes(2, "big")
        tree = decode(ethernet(ipv4(bytes(half_done), 6)))
        assert tree.get("tcp.checksum.status") == ChecksumStatus.GOOD

    def test_a_gap_in_the_sequence_numbers_means_something_was_missed(self) -> None:
        trees = self.conversation(
            self.frame(payload=b"a" * 100, seq=1, flags=PUSH | ACK),
            self.frame(payload=b"c" * 100, seq=301, flags=PUSH | ACK),
        )
        assert "tcp.analysis.lost_segment" not in trees[0]
        assert trees[1].get("tcp.analysis.lost_segment") is True

    def test_an_acknowledgement_that_says_nothing_new_is_a_duplicate(self) -> None:
        answer = self.frame(seq=1, ack=101, flags=ACK, from_client=False)
        trees = self.conversation(
            self.frame(payload=b"a" * 100, seq=1, flags=PUSH | ACK), answer, answer, answer
        )
        assert "tcp.analysis.duplicate_ack" not in trees[1]
        assert [tree.get("tcp.analysis.duplicate_ack_num") for tree in trees[2:]] == [1, 2]
        # They point back at the acknowledgement they are repeating.
        assert trees[3].get("tcp.analysis.duplicate_ack_frame") == 2

    def test_what_a_segment_acknowledges_and_how_long_it_took(self) -> None:
        trees = self.conversation(
            self.frame(payload=b"a" * 100, seq=1, flags=PUSH | ACK),
            self.frame(seq=1, ack=101, flags=ACK, from_client=False),
        )
        assert trees[1].get("tcp.analysis.acks_frame") == 1
        # The frames are a second apart.
        assert trees[1].get("tcp.analysis.ack_rtt") == 1_000_000_000

    def test_a_payload_no_port_claims_is_left_as_data(self) -> None:
        tree = decode(self.frame(payload=b"whatever", seq=1, flags=PUSH | ACK))
        assert tree.protocols == ("frame", "eth", "ip", "tcp", "data")
        assert tree.get("data.data") == b"whatever"
