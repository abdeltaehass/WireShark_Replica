"""The application protocols, over messages built for the purpose.

What the fields decode to is checked against tshark in test_tshark.py, over
the sample captures. These are the things tshark can't answer: what happens
when a message is a lie, when it stops halfway, or when it arrives somewhere
nobody expected it.
"""

import struct

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from packets import ethernet, ipv4, tcp, udp
from pilotfish.core.dissect import MalformedError, ProtocolTree, Session, dissect
from pilotfish.core.packet import Packet
from pilotfish.core.protocols.dns import ROOT, read_name

ETHERNET = 1
CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"


def labels(name: str) -> bytes:
    """A domain name as DNS writes it, with each label's length in front."""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"


def pointer(offset: int) -> bytes:
    return struct.pack(">H", 0xC000 | offset)


def message(
    *,
    identifier: int = 0x1234,
    flags: int = 0x0100,
    questions: bytes = b"",
    answers: bytes = b"",
    counts: tuple[int, int, int, int] = (1, 0, 0, 0),
) -> bytes:
    return struct.pack(">HHHHHH", identifier, flags, *counts) + questions + answers


def question(name: str, kind: int = 1, asked_class: int = 1) -> bytes:
    return labels(name) + struct.pack(">HH", kind, asked_class)


def record(name: bytes, kind: int, data: bytes, *, ttl: int = 60, record_class: int = 1) -> bytes:
    return name + struct.pack(">HHIH", kind, record_class, ttl, len(data)) + data


def over_udp(payload: bytes, *, port: int = 53, source_port: int = 50000) -> bytes:
    return ethernet(ipv4(udp(source_port, port, payload, source=CLIENT, destination=SERVER)))


def over_tcp(payload: bytes, *, port: int = 80, source_port: int = 50000, seq: int = 1) -> bytes:
    segment = tcp(
        source_port, port, payload, seq=seq, flags=0x18, source=CLIENT, destination=SERVER
    )
    return ethernet(ipv4(segment, 6))


def decode(data: bytes, session: Session | None = None, number: int = 1) -> ProtocolTree:
    packet = Packet(number * 1_000_000_000, len(data), ETHERNET, data)
    return dissect(packet, number, session=session or Session())


class TestTheNameReader:
    """Names are the one part of DNS that can point anywhere, including home."""

    def test_a_plain_name(self) -> None:
        assert read_name(labels("www.example.com"), 0) == ("www.example.com", 17)

    def test_the_root_is_a_name_with_no_labels(self) -> None:
        assert read_name(b"\x00", 0) == ("", 1)

    def test_a_pointer_is_followed_but_only_its_own_bytes_are_counted(self) -> None:
        # The name at 0, then a name that is one label and a pointer to it.
        body = labels("example.com") + b"\x03www" + pointer(0)
        assert read_name(body, len(labels("example.com"))) == ("www.example.com", 6)

    def test_a_pointer_to_itself_is_caught(self) -> None:
        # A name that points at itself is the shortest way to hang a parser
        # that follows pointers without asking where they lead.
        with pytest.raises(MalformedError, match="not before it"):
            read_name(pointer(0), 0)

    def test_two_pointers_that_point_at_each_other_are_caught(self) -> None:
        with pytest.raises(MalformedError, match="not before it"):
            read_name(pointer(2) + pointer(0), 0)

    def test_a_pointer_that_leads_forwards_is_refused(self) -> None:
        # Pointing forwards is how a chain of them could go round for ever,
        # and it is never what a real message does.
        with pytest.raises(MalformedError, match="not before it"):
            read_name(pointer(4) + b"\x00\x00" + labels("example.com"), 0)

    def test_a_loop_that_keeps_adding_labels_runs_into_the_length_limit(self) -> None:
        # This one points backwards, as it must, but back to a label before
        # it, so the name grows a label every time round. The limit on how
        # long a name may be is what ends it.
        with pytest.raises(MalformedError, match="longer than 255 bytes"):
            read_name(b"\x03www" + pointer(0), 0)

    def test_a_name_that_runs_past_the_end(self) -> None:
        with pytest.raises(MalformedError, match="past the end"):
            read_name(b"\x05www", 0)


class TestDns:
    def test_a_query_and_what_the_packet_list_says(self) -> None:
        tree = decode(over_udp(message(questions=question("google.com", kind=16))))
        assert tree.protocols[-1] == "dns"
        assert tree.get("dns.qry.name") == "google.com"
        assert tree.get("dns.qry.name.len") == 10
        assert tree.get("dns.count.labels") == 2
        assert tree.get("dns.flags.recdesired") is True
        assert tree.info == "Standard query 0x1234 TXT google.com"

    def test_an_answer_carries_the_address_it_was_asked_for(self) -> None:
        answer = record(labels("google.com"), 1, bytes([93, 184, 216, 34]))
        body = message(
            flags=0x8180, questions=question("google.com"), answers=answer, counts=(1, 1, 0, 0)
        )
        tree = decode(over_udp(body))
        assert str(tree.get("dns.a")) == "93.184.216.34"
        assert tree.info == "Standard query response 0x1234 A google.com A 93.184.216.34"

    def test_an_answer_that_points_back_at_the_question(self) -> None:
        # The name in the answer is a pointer to the one in the question,
        # which is how nearly every real response is written.
        answer = record(pointer(12), 5, labels("www.l.google.com"))
        body = message(
            flags=0x8180,
            questions=question("www.google.com", kind=5),
            answers=answer,
            counts=(1, 1, 0, 0),
        )
        tree = decode(over_udp(body))
        assert tree.get("dns.resp.name") == "www.google.com"
        assert tree.get("dns.cname") == "www.l.google.com"

    def test_a_name_that_points_at_itself_marks_the_packet(self) -> None:
        # Nothing in the format forbids it, and a parser that follows it
        # without counting never comes back.
        body = message(questions=pointer(12) + struct.pack(">HH", 1, 1))
        tree = decode(over_udp(body))
        assert tree.error is not None
        assert "not before it" in tree.error

    def test_the_root_name_is_named(self) -> None:
        body = message(questions=b"\x00" + struct.pack(">HH", 2, 1))
        tree = decode(over_udp(body))
        assert tree.get("dns.qry.name") == ROOT
        assert tree.get("dns.qry.name.len") == 0

    def test_a_record_type_pilotfish_has_no_fields_for(self) -> None:
        answer = record(labels("example.com"), 99, b"\x01\x02\x03\x04")
        body = message(
            flags=0x8180,
            questions=question("example.com", kind=99),
            answers=answer,
            counts=(1, 1, 0, 0),
        )
        tree = decode(over_udp(body))
        assert tree.error is None
        assert tree.get("dns.resp.len") == 4
        assert tree.info.endswith("SPF example.com SPF")

    def test_a_response_points_back_at_the_question_it_answers(self) -> None:
        session = Session()
        query = over_udp(message(questions=question("example.com")))
        answer = record(pointer(12), 1, bytes([93, 184, 216, 34]))
        response = ethernet(
            ipv4(
                udp(
                    53,
                    50000,
                    message(
                        flags=0x8180,
                        questions=question("example.com"),
                        answers=answer,
                        counts=(1, 1, 0, 0),
                    ),
                    source=SERVER,
                    destination=CLIENT,
                ),
                source=SERVER,
                destination=CLIENT,
            )
        )
        decode(query, session, number=1)
        tree = decode(response, session, number=2)
        assert tree.get("dns.response_to") == 1
        assert tree.get("dns.time") == 1_000_000_000

    def test_an_answer_nobody_asked_for_says_so(self) -> None:
        answer = record(labels("example.com"), 1, bytes([93, 184, 216, 34]))
        body = message(flags=0x8180, answers=answer, counts=(0, 1, 0, 0))
        tree = decode(over_udp(body))
        assert tree.get("dns.unsolicited") is True


class TestMdns:
    def multicast(self, payload: bytes) -> ProtocolTree:
        return decode(over_udp(payload, port=5353, source_port=5353))

    def test_a_question_that_wants_its_answer_sent_straight_back(self) -> None:
        asked = labels("_airplay._tcp.local") + struct.pack(">HH", 12, 0x8001)
        tree = self.multicast(message(identifier=0, flags=0, questions=asked))
        assert tree.protocols[-1] == "mdns"
        assert tree.get("dns.qry.qu") is True
        assert tree.get("dns.qry.class") == 1
        assert tree.info.endswith('PTR _airplay._tcp.local, "QU" question')

    def test_an_answer_that_replaces_what_was_cached(self) -> None:
        answer = record(labels("host.local"), 1, bytes([192, 0, 2, 10]), record_class=0x8001)
        body = message(identifier=0, flags=0x8400, answers=answer, counts=(0, 1, 0, 0))
        tree = self.multicast(body)
        assert tree.get("dns.resp.cache_flush") is True
        assert tree.get("dns.resp.class") == 1
        assert "A, cache flush 192.0.2.10" in tree.info


class TestDhcp:
    def request(self, options: bytes, *, kind: int = 1) -> ProtocolTree:
        header = bytes([kind, 1, 6, 0]) + struct.pack(">IHH", 0x3D1D, 0, 0)
        header += bytes(4) * 4  # the four addresses, all unknown yet
        header += bytes.fromhex("0000000000") + bytes(11)  # the hardware address
        header += bytes(64) + bytes(128)  # the server and file names
        body = header + b"\x63\x82\x53\x63" + options
        return decode(
            ethernet(
                ipv4(
                    udp(68, 67, body, source="0.0.0.0", destination="255.255.255.255"),
                    source="0.0.0.0",
                    destination="255.255.255.255",
                )
            )
        )

    def test_a_discover_and_what_it_asks_for(self) -> None:
        options = bytes([53, 1, 1]) + bytes([55, 3, 1, 3, 6]) + bytes([255])
        tree = self.request(options)
        assert tree.protocols[-1] == "dhcp"
        assert tree.get("dhcp.option.dhcp") == 1
        assert tree.values("dhcp.option.request_list_item") == [1, 3, 6]
        assert tree.info == "DHCP Discover - Transaction ID 0x3d1d"

    def test_an_offer_carries_the_addresses_it_is_offering(self) -> None:
        options = bytes([53, 1, 2]) + bytes([1, 4, 255, 255, 255, 0])
        options += bytes([54, 4, 192, 168, 0, 1]) + bytes([51, 4, 0, 0, 14, 16]) + bytes([255])
        tree = self.request(options, kind=2)
        assert str(tree.get("dhcp.option.subnet_mask")) == "255.255.255.0"
        assert str(tree.get("dhcp.option.dhcp_server_id")) == "192.168.0.1"
        assert tree.get("dhcp.option.ip_address_lease_time") == 3600
        assert tree.info.startswith("DHCP Offer   ")

    def test_the_padding_after_the_end_is_not_an_option(self) -> None:
        tree = self.request(bytes([53, 1, 1]) + bytes([255]) + bytes(8))
        assert tree.get("dhcp.option.padding") == bytes(8)
        assert tree.values("dhcp.option.type") == [53, 0]

    def test_an_option_that_claims_more_than_is_there(self) -> None:
        tree = self.request(bytes([12, 40]) + b"short")
        assert tree.error is not None
        assert "claims 40 bytes" in tree.error


class TestHttp:
    def test_a_request_and_what_it_asked_for(self) -> None:
        message = (
            b"GET /index.html?q=1&lang=en HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: pilotfish\r\n"
            b"\r\n"
        )
        tree = decode(over_tcp(message))
        assert tree.protocols[-1] == "http"
        assert tree.get("http.request.method") == "GET"
        assert tree.get("http.request.uri") == "/index.html?q=1&lang=en"
        assert tree.get("http.request.uri.path") == "/index.html"
        assert tree.values("http.request.uri.query.parameter") == ["q=1", "lang=en"]
        assert tree.get("http.request.full_uri") == "http://example.com/index.html?q=1&lang=en"
        assert tree.get("http.host") == "example.com"
        assert tree.values("http.request.line") == [
            "Host: example.com\r\n",
            "User-Agent: pilotfish\r\n",
        ]
        assert tree.info == "GET /index.html?q=1&lang=en HTTP/1.1 "

    def test_a_response_points_back_at_the_request(self) -> None:
        session = Session()
        decode(over_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), session, number=1)
        answer = (
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nno!"
        )
        segment = tcp(80, 50000, answer, seq=1, flags=0x18, source=SERVER, destination=CLIENT)
        tree = decode(ethernet(ipv4(segment, 6, source=SERVER, destination=CLIENT)), session, 2)
        assert tree.get("http.response.code") == 404
        assert tree.get("http.response.code.desc") == "Not Found"
        assert tree.get("http.response.phrase") == "Not Found"
        assert tree.get("http.request_in") == 1
        assert tree.get("http.time") == 1_000_000_000
        assert tree.get("http.file_data") == b"no!"
        assert tree.info == "HTTP/1.1 404 Not Found  (text/plain)"

    def test_a_body_sent_in_pieces_with_their_sizes_in_front(self) -> None:
        message = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        tree = decode(over_tcp(message))
        assert tree.values("http.chunk_size") == [5, 6, 0]
        assert tree.values("http.chunk_data") == [b"hello", b" world"]

    def test_the_middle_of_a_message_is_left_alone(self) -> None:
        # Nothing here says what it is, and saying so would take the packets
        # before it, which is the next phase's work.
        tree = decode(over_tcp(b"</body>\r\n</html>\r\n"))
        assert "http" not in tree.protocols
        assert tree.protocols[-1] == "data"

    def test_a_server_on_a_port_nobody_registered(self) -> None:
        # The heuristic finds it by what it says rather than where it is.
        tree = decode(over_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", port=8765))
        assert tree.protocols[-1] == "http"
        assert tree.get("http.request.method") == "GET"


def record_layer(kind: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack(">BHH", kind, version, len(body)) + body


def handshake(kind: int, body: bytes) -> bytes:
    return struct.pack(">B", kind) + len(body).to_bytes(3, "big") + body


def extension(kind: int, body: bytes) -> bytes:
    return struct.pack(">HH", kind, len(body)) + body


def client_hello(
    *, server_name: str = "example.com", ciphers: tuple[int, ...] = (0x1301,)
) -> bytes:
    name = server_name.encode()
    sni = extension(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    alpn = extension(16, struct.pack(">H", 11) + b"\x02h2\x08http/1.1")
    # A group list with one of the reserved values in it, which a fingerprint
    # has to leave out.
    groups = extension(10, struct.pack(">HHH", 4, 0x0A0A, 0x001D))
    extensions = sni + alpn + groups
    body = struct.pack(">H", 0x0303) + bytes(32) + b"\x00"
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(
        struct.pack(">H", each) for each in ciphers
    )
    body += b"\x01\x00" + struct.pack(">H", len(extensions)) + extensions
    return record_layer(22, handshake(1, body))


class TestTls:
    def test_a_client_hello_says_who_it_is_looking_for(self) -> None:
        tree = decode(over_tcp(client_hello(), port=443))
        assert tree.protocols[-1] == "tls"
        assert tree.get("tls.record.content_type") == 22
        assert tree.get("tls.handshake.type") == 1
        assert tree.get("tls.handshake.extensions_server_name") == "example.com"
        assert tree.values("tls.handshake.extensions_alpn_str") == ["h2", "http/1.1"]
        assert tree.info == "Client Hello (SNI=example.com)"

    def test_the_fingerprint_leaves_out_the_padding_values(self) -> None:
        # The reserved values a client throws in to keep servers honest mean
        # nothing, so they don't belong in a fingerprint.
        tree = decode(over_tcp(client_hello(ciphers=(0x1A1A, 0x1301)), port=443))
        assert tree.get("tls.handshake.ja3_full") == "771,4865,0-16-10,29,"
        assert len(str(tree.get("tls.handshake.ja3"))) == 32

    def test_several_records_in_one_segment(self) -> None:
        payload = record_layer(20, b"\x01") + record_layer(23, bytes(16))
        tree = decode(over_tcp(payload, port=443))
        assert tree.get("tls.change_cipher_spec") is True
        assert tree.get("tls.app_data") == bytes(16)
        assert tree.info == "Change Cipher Spec, Application Data"

    def test_a_record_that_reaches_past_this_segment(self) -> None:
        # What is here is part of a record; the rest of it is in a packet
        # that hasn't been read yet, and joining them is the next phase.
        payload = struct.pack(">BHH", 23, 0x0303, 4000) + bytes(40)
        tree = decode(over_tcp(payload, port=443))
        assert tree.get("tls.segment.data") == payload
        assert "tls.record.length" not in tree

    def test_an_alert(self) -> None:
        tree = decode(over_tcp(record_layer(21, bytes([2, 40])), port=443))
        assert tree.get("tls.alert_message.level") == 2
        assert tree.get("tls.alert_message.desc") == 40
        assert tree.info == "Alert (Fatal): Handshake Failure"

    def test_a_payload_that_is_not_tls_is_left_alone(self) -> None:
        tree = decode(over_tcp(b"not a record at all", port=443))
        assert "tls" not in tree.protocols
        assert tree.protocols[-1] == "data"


def ssh_packet(payload: bytes, padding: int = 8) -> bytes:
    return struct.pack(">IB", 1 + len(payload) + padding, padding) + payload + bytes(padding)


def kex_init() -> bytes:
    lists = [
        b"curve25519-sha256",
        b"ssh-ed25519",
        b"chacha20-poly1305@openssh.com",
        b"chacha20-poly1305@openssh.com",
        b"hmac-sha2-256",
        b"hmac-sha2-256",
        b"none",
        b"none",
        b"",
        b"",
    ]
    body = bytes(16) + b"".join(struct.pack(">I", len(each)) + each for each in lists)
    return ssh_packet(bytes([20]) + body + b"\x00" + bytes(4))


class TestSsh:
    def test_the_greeting_each_end_opens_with(self) -> None:
        tree = decode(over_tcp(b"SSH-2.0-OpenSSH_9.6\r\n", port=22))
        assert tree.protocols[-1] == "ssh"
        assert tree.get("ssh.protocol") == "SSH-2.0-OpenSSH_9.6"
        assert tree.info == "Client: Protocol (SSH-2.0-OpenSSH_9.6)"

    def test_what_a_client_is_willing_to_use_and_what_that_looks_like(self) -> None:
        tree = decode(over_tcp(kex_init(), port=22))
        assert tree.get("ssh.message_code") == 20
        assert tree.get("ssh.kex_algorithms") == "curve25519-sha256"
        assert tree.get("ssh.kex.hassh_algorithms") == (
            "curve25519-sha256;chacha20-poly1305@openssh.com;hmac-sha2-256;none"
        )
        assert len(str(tree.get("ssh.kex.hassh"))) == 32
        assert tree.info == "Client: Key Exchange Init"

    def test_after_the_keys_change_there_is_nothing_left_to_read(self) -> None:
        session = Session()
        switch = ssh_packet(bytes([21]))
        decode(over_tcp(switch, port=22), session, number=1)
        encrypted = struct.pack(">I", 44) + bytes(44)
        tree = decode(over_tcp(encrypted, port=22, seq=1 + len(switch)), session, number=2)
        assert tree.get("ssh.encrypted_packet") == bytes(44)
        assert tree.info == "Client: Encrypted packet (len=48)"
