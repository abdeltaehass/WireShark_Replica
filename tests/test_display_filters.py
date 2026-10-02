"""The display filter suite: filters that are right, and filters that aren't.

Every filter in ``VALID`` is compiled and run over the eleven packets of
``display.py``, both by the generated function and by walking the tree, and
has to pick out exactly the packets listed beside it. Every filter in
``INVALID`` has to be refused with the message beside it, pointing at the
characters marked under it.

What the filters *mean* is Wireshark's to say, so ``test_display_tshark.py``
holds the same evaluator to tshark's answers over the sample captures. This
file is the readable half: one line per thing the language can do.
"""

import pytest

import display
from pilotfish.core.display import DisplayFilterError, compile_display_filter

ALL = list(range(1, 12))
TCP = [1, 2, 3, 4, 5]
IPV4 = [1, 2, 3, 4, 5, 6, 7, 8, 11]

VALID: list[tuple[str, list[int]]] = [
    # A protocol or a field on its own: is it there at all?
    ("tcp", TCP),
    ("udp", [6, 7, 11]),
    ("dns", [6, 7]),
    ("http", [4, 5]),
    ("ip", IPV4),
    ("ipv6", [10]),
    ("arp", [9]),
    ("icmp", [8]),
    ("icmpv6", [10]),
    ("eth", ALL),
    ("frame", ALL),
    ("data", [5, 10, 11]),
    ("http.request", [4]),
    ("http.response", [5]),
    ("dns.a", [7]),
    ("tcp.flags.syn", TCP),
    ("ip.addr", IPV4),
    ("tcp.port", TCP),
    ("", ALL),
    ("   ", ALL),
    # and, or, xor, not, and how tightly each binds
    ("not tcp", [6, 7, 8, 9, 10, 11]),
    ("!tcp", [6, 7, 8, 9, 10, 11]),
    ("tcp or udp", [1, 2, 3, 4, 5, 6, 7, 11]),
    ("tcp || udp", [1, 2, 3, 4, 5, 6, 7, 11]),
    ("tcp and http", [4, 5]),
    ("tcp && not http", [1, 2, 3]),
    ("udp and not dns", [11]),
    ("ip xor udp", [1, 2, 3, 4, 5, 8]),
    ("ip ^^ udp", [1, 2, 3, 4, 5, 8]),
    ("not not arp", [9]),
    ("!!arp", [9]),
    ("!(tcp or udp)", [8, 9, 10]),
    ("tcp or udp and dns", [1, 2, 3, 4, 5, 6, 7]),
    ("(tcp or udp) and dns", [6, 7]),
    ("arp or icmp xor ip", [1, 2, 3, 4, 5, 6, 7, 9, 11]),
    ("not tcp.port == 80 and ip", [6, 7, 8, 11]),
    ("not (tcp.port == 80 and ip)", [6, 7, 8, 9, 10, 11]),
    ("((udp))", [6, 7, 11]),
    # Numbers, in every base and with every operator
    ("frame.number == 1", [1]),
    ("frame.number != 1", [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
    ("frame.number > 9", [10, 11]),
    ("frame.number >= 9", [9, 10, 11]),
    ("frame.number < 3", [1, 2]),
    ("frame.number <= 3", [1, 2, 3]),
    ("frame.number eq 4", [4]),
    ("frame.number ne 4 and tcp", [1, 2, 3, 5]),
    ("frame.number gt 10", [11]),
    ("frame.number lt 2", [1]),
    ("frame.number ge 11", [11]),
    ("frame.number le 1", [1]),
    ("frame.number == 0xb", [11]),
    ("frame.number == 0XB", [11]),
    ("frame.number == 013", [11]),
    ("frame.number == 0b1011", [11]),
    ("frame.number == +11", [11]),
    ("frame.number == '\\n'", [10]),
    ("frame.number == '\\x0b'", [11]),
    ("frame.len == 54", [1, 2, 3]),
    ("frame.len > 100", [4, 5, 7]),
    ("tcp.len > 0", [4, 5]),
    ("ip.ttl == 64", IPV4),
    ("tcp.window_size_value == 8192", TCP),
    ("11 == frame.number", [11]),
    ("5 > frame.number", [1, 2, 3, 4]),
    ("tcp.srcport > tcp.dstport", [1, 3, 4]),
    ("tcp.srcport == tcp.dstport", []),
    ("udp.srcport < udp.dstport", [7, 11]),
    # Fields a packet holds twice: any of them, or all of them
    ("tcp.port == 80", TCP),
    ("tcp.port != 80", []),
    ("tcp.port !== 80", TCP),
    ("tcp.port === 80", []),
    ("tcp.port == 50000", TCP),
    ("tcp.srcport == 80", [2, 5]),
    ("tcp.dstport != 80", [2, 5]),
    ("udp.port == 53", [6, 7]),
    ("udp.port != 53", [11]),
    ("udp.port !== 53", [6, 7, 11]),
    ("udp.port any_eq 53", [6, 7]),
    ("udp.port all_eq 53", []),
    ("udp.port any_ne 53", [6, 7, 11]),
    ("udp.port all_ne 53", [11]),
    ("tcp.port >= 1024", TCP),
    ("all tcp.port >= 1024", []),
    ("all udp.port >= 1024", [11]),
    ("any udp.port < 1024", [6, 7]),
    ("all udp.port != 53", [11]),
    ("any udp.port != 53", [6, 7, 11]),
    ("count(dns.a) == 2", [7]),
    ("count(dns.a) == 0 and dns", [6]),
    ("count(ip.addr) == 2", IPV4),
    ("count(tcp.port) > 2", []),
    ("count(udp.port) == 2 and not dns", [11]),
    # IPv4 addresses and subnets
    ("ip.addr == 192.0.2.1", [1, 2, 3, 4, 5, 6, 7, 8]),
    ("ip.addr != 192.0.2.1", [11]),
    ("ip.src == 192.0.2.1", [1, 3, 4, 6, 8]),
    ("ip.dst == 192.0.2.1", [2, 5, 7]),
    ("ip.addr == 192.0.2.0/24", [1, 2, 3, 4, 5, 6, 7, 8]),
    ("ip.addr != 192.0.2.0/24", [11]),
    ("ip.addr !== 192.0.2.0/24", [8, 11]),
    ("ip.addr === 192.0.2.0/24", [1, 2, 3, 4, 5, 6, 7]),
    ("ip.addr == 192.0.2.77/24", [1, 2, 3, 4, 5, 6, 7, 8]),
    ("ip.dst == 192.0.2.48/28", [6]),
    ("ip.addr == 10.0.0.0/8", [11]),
    ("ip.addr == 192.168.0.0/16", [11]),
    ("ip.src == 10.1.2.3/32", [11]),
    ("ip.addr == 0.0.0.0/0", IPV4),
    ("ip.src > 192.0.2.2", [7]),
    ("ip.src >= 192.0.2.0/24", [1, 2, 3, 4, 5, 6, 7, 8]),
    ("ip.src > 192.0.2.0/24", []),
    ("ip.src < 192.0.2.0/24", [11]),
    ("ip.src <= 192.0.2.0/24", IPV4),
    ("ip.dst > 192.0.2.0/24", [8, 11]),
    ("192.0.2.0/24 < ip.dst", [8, 11]),
    ("ip.src == ip.dst", []),
    ("ip.src < ip.dst", [1, 3, 4, 6, 8, 11]),
    ("dns.a == 192.0.2.80", [7]),
    ("dns.a == 192.0.2.81", [7]),
    ("dns.a != 192.0.2.80", []),
    ("dns.a !== 192.0.2.80", [7]),
    ("dns.a === 192.0.2.80/31", [7]),
    ("arp.src.proto_ipv4 == 192.0.2.1", [9]),
    # IPv6
    ("ipv6.addr == 2001:db8::/32", [10]),
    ("ipv6.src == 2001:db8::1", [10]),
    ("ipv6.src == 2001:0db8:0:0:0:0:0:1", [10]),
    ("ipv6.dst == 2001:db8::1", []),
    ("ipv6.addr != fe80::/10", [10]),
    ("ipv6.src < ipv6.dst", [10]),
    ("ipv6.addr in {2001:db8::2, ::1}", [10]),
    # Ethernet addresses
    ("eth.dst == ff:ff:ff:ff:ff:ff", [9]),
    ("eth.dst == FF-FF-FF-FF-FF-FF", [9]),
    ("eth.dst == ffff.ffff.ffff", [9]),
    ("eth.addr == 02:00:00:00:00:01", [1, 2, 3, 4, 5, 6, 7, 8, 10, 11]),
    ("eth.src == 02:00:00:00:00:02", ALL),
    ("eth.addr != 02:00:00:00:00:01", [9]),
    ("eth.dst > 02:00:00:00:00:01", [9]),
    ("eth.src == eth.dst", []),
    ("arp.dst.hw_mac == 00:00:00:00:00:00", [9]),
    ("arp.opcode == 1", [9]),
    # Flags
    ("tcp.flags.syn == 1", [1, 2]),
    ("tcp.flags.syn == true", [1, 2]),
    ("tcp.flags.syn == True", [1, 2]),
    ("tcp.flags.syn == TRUE", [1, 2]),
    ("tcp.flags.syn == 0", [3, 4, 5]),
    ("tcp.flags.syn == false", [3, 4, 5]),
    ("tcp.flags.syn == 7", [1, 2]),
    ("tcp.flags.syn != 1", [3, 4, 5]),
    ("tcp.flags.syn == 1 and tcp.flags.ack == 0", [1]),
    ("tcp.flags.syn == tcp.flags.ack", [2]),
    ("tcp.flags.push == 1", [4, 5]),
    ("tcp.flags == 0x002", [1]),
    ("tcp.flags == 2", [1]),
    ("tcp.flags == 0x12", [2]),
    ("tcp.flags & 0x02", [1, 2]),
    ("tcp.flags & 0x12 == 0x12", [2]),
    ("tcp.flags & 0x10 != 0", [2, 3, 4, 5]),
    ("0x18 == tcp.flags & 0x18", [4, 5]),
    ("(tcp.flags & 0x18) == 0x18", [4, 5]),
    ("dns.flags.response == 1", [7]),
    ("dns.flags.response == 0", [6]),
    ("ip.flags.df == 1", IPV4),
    # Sets, with commas or with spaces
    ("tcp.port in {80, 443}", TCP),
    ("tcp.port in {80 443}", TCP),
    ("tcp.port in {443, 8080}", []),
    ("tcp.port not in {80, 443}", []),
    ("tcp.port not in {443}", TCP),
    ("not tcp.port in {443}", ALL),
    ("udp.port in {53, 5000}", [6, 7, 11]),
    ("udp.port in {5000..6000}", [11]),
    ("udp.port in {1..52, 54..4999}", []),
    ("udp.port in {1 .. 52 54 .. 5000}", [11]),
    ("udp.port not in {53}", [11]),
    ("frame.number in {1, 3, 5..7}", [1, 3, 5, 6, 7]),
    ("frame.number in {9 .. 20}", [9, 10, 11]),
    ("ip.src in {192.0.2.53, 10.1.2.3}", [7, 11]),
    ("ip.src in {10.0.0.0/8}", [11]),
    ("ip.dst in {192.0.2.50 .. 192.0.2.60}", [6]),
    ("ip.addr not in {192.0.2.0/24}", [11]),
    ("eth.dst in {ff:ff:ff:ff:ff:ff}", [9]),
    ('http.request.method in {"GET", "POST"}', [4]),
    ("http.response.code in {200, 404}", [5]),
    ('dns.qry.name in {"www.example.com"}', [6, 7]),
    ('dns.qry.name in {"a" .. "x"}', [6, 7]),
    ("tcp.flags.syn in {1}", [1, 2]),
    ("frame.time_epoch in {0.004 .. 0.006}", [4, 5, 6]),
    ("count(dns.a) in {1, 2}", [7]),
    # Text
    ('http.request.method == "GET"', [4]),
    ("http.request.method == GET", [4]),
    ('http.request.method != "GET"', []),
    ('http.host == "www.example.com"', [4]),
    ("http.host == www.example.com", [4]),
    ('"www.example.com" == http.host', [4]),
    ('http.host contains "example"', [4]),
    ('http.host contains "EXAMPLE"', []),
    ('http.host matches "EXAMPLE"', [4]),
    ('http.host matches "(?-i:EXAMPLE)"', []),
    ('http.host matches "^www\\\\."', [4]),
    ('http.host matches r"^www\\."', [4]),
    ('http.host ~ "com$"', [4]),
    ('http.request.uri == "/index.html"', [4, 5]),
    ('http.request.uri matches r"\\.html$"', [4, 5]),
    ('http.user_agent contains "pilotfish"', [4]),
    ("http.response.code == 200", [5]),
    ('http.response.phrase == "OK"', [5]),
    ('http.content_type == "text/html"', [5]),
    ('dns.qry.name == "www.example.com"', [6, 7]),
    ('dns.qry.name contains "example"', [6, 7]),
    ('dns.qry.name < "x"', [6, 7]),
    ('dns.qry.name > "x"', []),
    ("dns.qry.name == http.host", []),
    ('lower(http.request.method) == "get"', [4]),
    ('upper(http.host) contains "EXAMPLE"', [4]),
    ("len(http.host) == 15", [4]),
    ("len(dns.qry.name) > 10", [6, 7]),
    ('http.host == "www.example.com" or dns.qry.name == "www.example.com"', [4, 6, 7]),
    ('http.request.method == "\\x47ET"', [4]),
    ('http.request.method == "\\107ET"', [4]),
    ('http.request.method == "\\u0047ET"', [4]),
    ('tcp.flags.str contains "S"', [1, 2]),
    # Bytes: a protocol's, a field's, and slices of either
    ('frame contains "GET"', [4]),
    ('tcp contains "HTTP/1.1"', [4, 5]),
    ('udp contains "example"', [6, 7]),
    ('ip contains "hello"', [5]),
    ("eth contains ff:ff:ff:ff:ff:ff", [9]),
    ("frame contains 00:01:02:03:ff", [11]),
    ('frame contains "\\x00\\x01\\x02\\x03\\xff"', [11]),
    ('frame matches "content-length: \\\\d+"', [5]),
    ('frame matches r"GET /\\S+ HTTP"', [4]),
    ('http contains "Content-Type"', [5]),
    ('tcp.payload contains "GET"', [4]),
    ('tcp.payload matches "^HTTP"', [5]),
    ("tcp.payload contains 0d:0a:0d:0a", [4, 5]),
    ("udp.payload == 00:01:02:03:ff", [11]),
    ("udp.payload == 00-01-02-03-ff", [11]),
    ('udp.payload == "\\x00\\x01\\x02\\x03\\xff"', [11]),
    ("udp.payload[0:2] == 00:01", [11]),
    # A run of digits is a number before it is bytes, so this is the one byte 01.
    ("udp.payload[0:2] == 0001", []),
    ("udp.payload[4] == 0xff", [11]),
    ("udp.payload[4] == 255", [11]),
    ("udp.payload[4] == ff", [11]),
    ("udp.payload[-1] == ff:", [11]),
    ("udp.payload[-1] == :ff", [11]),
    ("udp.payload[3] == '\\x03'", [11]),
    ("udp.payload[-2:] == 03:ff", [11]),
    ("udp.payload[1:] == 01:02:03:ff", [11]),
    ("udp.payload[:2] == 00:01", [11]),
    ("udp.payload[1-3] == 01:02:03", [11]),
    ("udp.payload[2-2] == 02:", [11]),
    ("udp.payload[0,4] == 00:ff", [11]),
    ("udp.payload[0:2,3:2] == 00:01:03:ff", [11]),
    ("udp.payload[3:5] == 03:ff", []),
    ("udp.payload[5]", [6, 7]),
    ("udp.payload[0:2] == 12:34", [6, 7]),
    ("udp[0:2] == 00:35", [7]),
    ("udp[2:2] == 00:35", [6]),
    ("eth.src[0:3] == 02:00:00", ALL),
    ("eth.src[0:3]", ALL),
    ("eth.dst[0:3] == ff:ff:ff", [9]),
    ("eth.dst[0] == 0xff", [9]),
    ("eth.dst == frame[0:6]", ALL),
    ("eth.src == frame[6:6]", ALL),
    ("frame[6:6] == eth.src", ALL),
    ("eth.dst[0:3] == eth.src[0:3]", [1, 2, 3, 4, 5, 6, 7, 8, 10, 11]),
    ("eth.src[10:2] == 00:00", []),
    ("eth.src contains 00:02", ALL),
    ('eth.dst matches "^\\xff+$"', [9]),
    ("ip.src[0:2] == c0:00", [1, 2, 3, 4, 5, 6, 7, 8]),
    ("ip.dst[3] == 53", [6]),
    ("ipv6.dst[15] == 2", [10]),
    ("ip[0] == 0x45", IPV4),
    ("ip[9] == 17", [6, 7, 11]),
    ("tcp[13] == 0x02", [1]),
    ("frame[12:2] == 08:06", [9]),
    ("frame[12:2] == 86:dd", [10]),
    ('dns.qry.name[0:3] == "www"', [6, 7]),
    ('http.request.method[0:1] == "G"', [4]),
    ("http.request.method[0] == 'G'", [4]),
    ('tcp.payload[0:4] == "HTTP"', [5]),
    ("tcp.payload[0:3] == 47:45:54", [4]),
    ("len(tcp.payload) > 70", [4]),
    ("len(udp.payload) == 5", [11]),
    ("len(eth.src) == 6", ALL),
    ('http.file_data == "hello"', [5]),
    ('http.file_data contains "ell"', [5]),
    ("len(http.file_data) == 5", [5]),
    ("data.len == 5", [5, 11]),
    ("data.data == 00:01:02:03:ff", [11]),
    # Times
    ("frame.time_epoch > 0.0095", [10, 11]),
    ("frame.time_epoch == 0.001", [1]),
    ("frame.time_epoch <= 0.002", [1, 2]),
    ('frame.time_epoch < "1970-01-01 00:00:01"', ALL),
    ('frame.time_epoch >= "1970-01-01T00:00:00.010Z"', [10, 11]),
    ("frame.time_epoch < 1970-01-01T00:00:00.002Z", [1]),
    ('frame.time_epoch >= "1970-01-01 01:00:00+01:00"', ALL),
    ('frame.time_epoch < "1970-01-01 00:00:00 UTC"', []),
    ("dns.time > 0", [7]),
    ("dns.time == 0.001", [7]),
    ("http.time == 0.001", [5]),
    # What people type
    ("tcp.port == 80 and tcp.flags.syn == 1 and tcp.flags.ack == 0", [1]),
    ("tcp.port==80&&tcp.flags.syn==1", [1, 2]),
    ("ip.addr == 192.0.2.1 and not tcp", [6, 7, 8]),
    ("(http or dns) and ip.src == 192.0.2.1", [4, 6]),
    ("!(ip.addr == 192.0.2.0/24)", [9, 10, 11]),
    ("http.request or http.response", [4, 5]),
    ("icmp.type == 8 or icmpv6.type == 128", [8, 10]),
    ("tcp and not (tcp.flags.syn == 1 or tcp.len > 0)", [3]),
    ("\ttcp.port == 80\nand http\n", [4, 5]),
]

INVALID: list[tuple[str, str, str]] = [
    # Characters and quotes the lexer can't make a token of
    (
        "tcp.port = 80",
        "         ^",
        'a single "=" isn\'t an operator; write == to compare',
    ),
    (
        "tcp | udp",
        "    ^",
        'a single "|" isn\'t an operator; write || or "or"',
    ),
    (
        "tcp ^ udp",
        "    ^",
        'a single "^" isn\'t an operator; write ^^ or "xor"',
    ),
    (
        "tcp.port == 80 $",
        "               ^",
        '"$" can\'t appear outside quotes',
    ),
    (
        'http.host == "unterminated',
        "             ^",
        "this quote is never closed",
    ),
    (
        'http.host == "bad \\q escape"',
        "                  ^~",
        (
            '"\\q" isn\'t an escape; write \\\\ for a backslash, or put an r before the '
            'string: r"..."'
        ),
    ),
    (
        'http.host == "\\x4"',
        "              ^~~~",
        "\\x is followed by 2 hexadecimal digits",
    ),
    (
        'http.host == "\\400"',
        "              ^~~~",
        "\\400 is 256, which is more than a byte holds",
    ),
    (
        'http.host == "ends with \\',
        "                        ^",
        "nothing follows this backslash",
    ),
    (
        'http.host == "\\ud800"',
        "              ^~~~~~",
        "\\ud800 isn't a character",
    ),
    (
        "frame.number == 'ab'",
        "                ^~",
        (
            "single quotes hold one character, which stands for its number; text goes in "
            "double quotes"
        ),
    ),
    (
        "frame.number == ''",
        "                ^~",
        "there is nothing between these quotes",
    ),
    (
        "frame.number == 'é'",
        "                 ^",
        '"é" takes 2 bytes, and single quotes hold one',
    ),
    (
        "frame.number == 'a",
        "                ^",
        "this quote is never closed",
    ),
    (
        "http.host == café",
        "                ^",
        '"é" can\'t appear outside quotes',
    ),
    (
        "eth.src[0:$] == 00",
        "          ^",
        '"$" can\'t appear in a slice',
    ),
    (
        "eth.src[1;2] == 00",
        "         ^",
        '";" can\'t appear in a slice',
    ),
    # Shapes the parser has no rule for
    (
        "tcp.port ==",
        "           ^",
        "the filter ends where a field or a value was expected",
    ),
    (
        "tcp and",
        "       ^",
        "the filter ends where a field or a value was expected",
    ),
    (
        "not",
        "   ^",
        "the filter ends where a field or a value was expected",
    ),
    (
        "(tcp.port == 80",
        "^",
        "this parenthesis is never closed",
    ),
    (
        "tcp.port == 80)",
        "              ^",
        "this parenthesis closes nothing",
    ),
    (
        "()",
        " ^",
        "a field or a value is missing before this parenthesis",
    ),
    (
        "tcp.port == 80 443",
        "               ^~~",
        '"443" isn\'t expected here; an operator such as == or "and" is missing before it',
    ),
    (
        "udp tcp",
        "    ^~~",
        '"tcp" isn\'t expected here; an operator such as == or "and" is missing before it',
    ),
    (
        'udp "tcp"',
        "    ^~~~~",
        '"tcp" isn\'t expected here; an operator such as == or "and" is missing before it',
    ),
    (
        "tcp AND udp",
        "    ^~~",
        'operators are written in lower case: "and"',
    ),
    (
        "tcp.port EQ 80",
        "         ^~",
        'operators are written in lower case: "eq"',
    ),
    (
        "and tcp",
        "^~~",
        '"and" needs a field or a value before it',
    ),
    (
        "== 80",
        "^~",
        '"==" needs a field or a value before it',
    ),
    (
        "tcp.port in 80",
        "            ^~",
        '"in" is followed by a set in braces, such as {80, 443}',
    ),
    (
        "tcp.port in",
        "         ^~",
        '"in" is followed by a set in braces, such as {80, 443}',
    ),
    (
        "tcp.port in {}",
        "            ^~",
        "an empty set matches nothing; list values in it, such as {80, 443}",
    ),
    (
        "tcp.port in {80,}",
        "               ^",
        "a value is missing after this comma",
    ),
    (
        "tcp.port in {80",
        "            ^",
        "this brace is never closed",
    ),
    (
        "tcp.port in {80 ..}",
        "                  ^",
        "a field or a value is missing before this brace",
    ),
    (
        "tcp.port in {80 == 90}",
        "                ^~",
        '"==" isn\'t expected in a set; its values are separated by commas',
    ),
    (
        "{80}",
        "^",
        'a set goes after "in": tcp.port in {80, 443}',
    ),
    (
        "eth.src[1:2",
        "       ^",
        "this bracket is never closed",
    ),
    (
        "eth.src[",
        "       ^",
        "this bracket is never closed",
    ),
    (
        "eth.src[] == 00",
        "        ^",
        'a slice says where the range starts here, not "]"',
    ),
    (
        "eth.src[a] == 00",
        "        ^",
        '"a" isn\'t a number; a slice says where the range starts here',
    ),
    (
        "eth.src[3:0] == 00",
        "        ^~~",
        "this takes no bytes; the number after the colon is how many to take",
    ),
    (
        "eth.src[:0] == 00",
        "        ^~",
        "this takes no bytes; the number after the colon is how many to take",
    ),
    (
        "eth.src[5-2] == 00",
        "        ^~~",
        "5-2 runs backwards; a range is the first byte, a dash, then the last",
    ),
    (
        "eth.src[1:2:3] == 00",
        "           ^",
        '":" isn\'t expected in a slice',
    ),
    (
        "eth.src[1:2 == 00",
        "            ^",
        '"=" can\'t appear in a slice',
    ),
    (
        "len(http.host",
        "   ^",
        "this parenthesis is never closed",
    ),
    (
        "len(http.host udp)",
        "              ^~~",
        "\"udp\" isn't expected here; a function's arguments are separated by commas",
    ),
    (
        "any tcp",
        "^~~",
        '"any" goes in front of a comparison, such as any tcp.port > 1024',
    ),
    (
        "all (tcp or udp)",
        "^~~",
        '"all" goes in front of a comparison, such as all tcp.port > 1024',
    ),
    (
        "tcp.port not 80",
        "         ^~~",
        '"not" isn\'t expected here; an operator such as == or "and" is missing before it',
    ),
    (
        "udp ]",
        "    ^",
        "this bracket closes nothing",
    ),
    (
        "tcp.port == 80 }",
        "               ^",
        "this brace closes nothing",
    ),
    # Names that aren't fields, and values where a test belongs
    (
        "dnss",
        "^~~~",
        'no field is named "dnss"; did you mean "dns"?',
    ),
    (
        "tcp.prot == 80",
        "^~~~~~~~",
        'no field is named "tcp.prot"; did you mean "tcp.port"?',
    ),
    (
        "TCP",
        "^~~",
        'no field is named "TCP"; did you mean "tcp"?',
    ),
    (
        "Tcp.Port == 80",
        "^~~~~~~~",
        'no field is named "Tcp.Port"; did you mean "tcp.port"?',
    ),
    (
        "80",
        "^~",
        '"80" is a value, not a test; compare a field with it',
    ),
    (
        '"abc"',
        "^~~~~",
        '"abc" is a value, not a test; compare a field with it',
    ),
    (
        "'a'",
        "^~~",
        "'a' is a value, not a test; compare a field with it",
    ),
    (
        "80 == 80",
        "^~~~~~~~",
        "nothing here is a field, so this is the same for every packet",
    ),
    (
        '"a" == "b"',
        "^~~~~~~~~~",
        "nothing here is a field, so this is the same for every packet",
    ),
    # Values that can't be read as the kind of field they are compared with
    (
        "ip.src == hello",
        "          ^~~~~",
        'ip.src is an IPv4 address, and "hello" isn\'t one',
    ),
    (
        "ip.src == 192.168.300.1",
        "                  ^~~",
        ("ip.src is an IPv4 address, and 300 is too large for a part of one: each is 0 to 255"),
    ),
    (
        "ip.src == 192.168.1",
        "          ^~~~~~~~~",
        'ip.src is an IPv4 address, and "192.168.1" isn\'t one',
    ),
    (
        "ip.src == 192.168.1.1.5",
        "          ^~~~~~~~~~~~~",
        'ip.src is an IPv4 address, and "192.168.1.1.5" isn\'t one',
    ),
    (
        "ip.src == 192.168.01.1",
        "          ^~~~~~~~~~~~",
        'ip.src is an IPv4 address, and "192.168.01.1" isn\'t one',
    ),
    (
        "ip.addr == 10.0.0.0/33",
        "                    ^~",
        'an IPv4 prefix is 0 to 32 bits, not "33"',
    ),
    (
        "ip.addr == 10.0.0.0/",
        "                   ^",
        "a number of bits goes after this slash, from 0 to 32",
    ),
    (
        "ip.addr == 10.0.0.0/x",
        "                    ^",
        'an IPv4 prefix is 0 to 32 bits, not "x"',
    ),
    (
        'ip.src == "192.0.2.1"',
        "          ^~~~~~~~~~~",
        'ip.src is an IPv4 address, and "192.0.2.1" is text; write it without the quotes',
    ),
    (
        "ipv6.src == 192.0.2.1",
        "            ^~~~~~~~~",
        'ipv6.src is an IPv6 address, and "192.0.2.1" isn\'t one',
    ),
    (
        "ipv6.addr == fe80::/129",
        "                    ^~~",
        'an IPv6 prefix is 0 to 128 bits, not "129"',
    ),
    (
        "ipv6.src == fe80::zz",
        "            ^~~~~~~~",
        'ipv6.src is an IPv6 address, and "fe80::zz" isn\'t one',
    ),
    (
        "tcp.port == http",
        "            ^~~~",
        "tcp.port is a number and http is a protocol, so they can't be compared",
    ),
    (
        'tcp.port == "80"',
        "            ^~~~",
        'tcp.port is a number, and "80" is text; write it without the quotes',
    ),
    (
        'tcp.port == "http"',
        "            ^~~~~~",
        'tcp.port is a number, and "http" is text',
    ),
    (
        "tcp.port == -1",
        "            ^~",
        "tcp.port is never negative",
    ),
    (
        "tcp.port == 1.5",
        "            ^~~",
        "tcp.port is a whole number, and 1.5 isn't one",
    ),
    (
        "tcp.port == 089",
        "             ^",
        '"089" starts with 0, which makes it octal, and 8 isn\'t an octal digit',
    ),
    (
        "tcp.port == 0x",
        "            ^~",
        'tcp.port is a number, and "0x" isn\'t one',
    ),
    (
        "tcp.port == 12abc",
        "            ^~~~~",
        'tcp.port is a number, and "12abc" isn\'t one',
    ),
    (
        "tcp.flags.syn == yes",
        "                 ^~~",
        'tcp.flags.syn is true or false; compare it with true, false, 1 or 0, not "yes"',
    ),
    (
        'tcp.flags.syn == "1"',
        "                 ^~~",
        'tcp.flags.syn is true or false, and "1" is text; write it without the quotes',
    ),
    (
        'frame.time_epoch > "abc"',
        "                   ^~~~~",
        (
            "frame.time_epoch is a time; write seconds, such as 1700000000.5, or a date, "
            'such as "2023-11-14 22:13:20", not "abc"'
        ),
    ),
    (
        'frame.time_epoch > "2023-13-01 00:00:00"',
        "                         ^~",
        "13 isn't a month",
    ),
    (
        'frame.time_epoch > "2023-02-29 00:00:00"',
        "                            ^~",
        "29 isn't a day of that month",
    ),
    (
        "frame.time_epoch > 2023-11-14T22:61:20Z",
        "                                 ^~",
        "61 isn't a minute",
    ),
    (
        'frame.time_epoch > "0000-01-01 00:00:00"',
        "                    ^~~~",
        "0000 isn't a year",
    ),
    (
        'frame.time_epoch > "2023-11-14 22:13:20+25:00"',
        "                                       ^~~~~~",
        "+25:00 isn't a distance from UTC",
    ),
    (
        "frame.time_epoch == 'a'",
        "                    ^~~",
        (
            "frame.time_epoch is a time; write seconds, such as 1700000000.5, or a date, "
            "such as \"2023-11-14 22:13:20\", not 'a'"
        ),
    ),
    (
        "http.host == 5",
        "             ^",
        'http.host is text; to compare it with the text "5", write it in quotes',
    ),
    (
        "http.host == 'a'",
        "             ^~~",
        "http.host is text, and single quotes spell a number; text goes in double quotes",
    ),
    (
        'http.host == "\\xff"',
        "             ^~~~~~",
        "these escapes don't spell text: they aren't valid UTF-8",
    ),
    (
        "eth.src == 00:00:01",
        "           ^~~~~~~~",
        (
            'eth.src is an Ethernet address, which is six bytes, and "00:00:01" is 3; to '
            "compare part of it, slice it: eth.src[0:3]"
        ),
    ),
    (
        "eth.src == zz:00:01:00:00:00",
        "           ^~",
        '"zz" isn\'t a byte; each one is two hexadecimal digits, as in 00:1a:2b',
    ),
    (
        "eth.src == 000001000000",
        "           ^~~~~~~~~~~~",
        (
            "eth.src is an Ethernet address, such as 00:1a:2b:3c:4d:5e, and "
            '"000001000000" isn\'t one'
        ),
    ),
    (
        'eth.src == "00:00:00:00:00:00"',
        "           ^~~~~~~~~~~~~~~~~~~",
        (
            'eth.src is an Ethernet address, and "00:00:00:00:00:00" is text; write it '
            "without the quotes"
        ),
    ),
    (
        "eth.src[0:3] == 00:1a:2g",
        "                      ^~",
        '"2g" isn\'t a byte; each one is two hexadecimal digits, as in 00:1a:2b',
    ),
    (
        "eth.src[0:3] == zz",
        "                ^~",
        ('"zz" isn\'t bytes; write them in hexadecimal, such as 00:1a:2b, or as text in quotes'),
    ),
    (
        "eth.src[0] == 256",
        "              ^~~",
        "256 doesn't fit in one byte; write several as 00:1a:2b",
    ),
    (
        "udp.payload == 0:1",
        "               ^",
        '"0" isn\'t a byte; each one is two hexadecimal digits, as in 00:1a:2b',
    ),
    (
        "udp.payload == 00:1a-2b",
        "                  ^~~~~",
        '"1a-2b" isn\'t a byte; each one is two hexadecimal digits, as in 00:1a:2b',
    ),
    # Operators given a kind they don't work on
    (
        "tcp.port contains 80",
        "         ^~~~~~~~",
        "contains looks inside text or bytes, and tcp.port is a number",
    ),
    (
        "ip.src contains 10",
        "       ^~~~~~~~",
        "contains looks inside text or bytes, and ip.src is an IPv4 address",
    ),
    (
        "tcp.flags.syn contains 1",
        "              ^~~~~~~~",
        "contains looks inside text or bytes, and tcp.flags.syn is true or false",
    ),
    (
        '"x" contains tcp.port',
        "    ^~~~~~~~",
        "contains looks inside text or bytes, and tcp.port is a number",
    ),
    (
        'tcp.port matches "80"',
        "         ^~~~~~~",
        "matches searches text or bytes, and tcp.port is a number",
    ),
    (
        'ip.src matches "10"',
        "       ^~~~~~~",
        "matches searches text or bytes, and ip.src is an IPv4 address",
    ),
    (
        "http.host matches GET",
        "                  ^~~",
        'matches takes a regular expression in quotes, such as "^GET"',
    ),
    (
        'http.host matches "a(b"',
        "                    ^",
        "this regular expression doesn't compile: missing ), unterminated subpattern",
    ),
    (
        'http.host matches "ab)"',
        "                     ^",
        "this regular expression doesn't compile: unbalanced parenthesis",
    ),
    (
        'http.host matches "[a-"',
        "                   ^",
        "this regular expression doesn't compile: unterminated character set",
    ),
    (
        'http.host matches "\\\\"',
        "                   ^",
        "this regular expression doesn't compile: bad escape (end of pattern)",
    ),
    (
        'http.host matches r"x{2,1}"',
        "                      ^",
        "this regular expression doesn't compile: min repeat greater than max repeat",
    ),
    (
        'http.host matches "\\xff"',
        "                  ^~~~~~",
        "these escapes don't spell text: they aren't valid UTF-8",
    ),
    (
        'tcp.payload matches "*x"',
        "                     ^",
        "this regular expression doesn't compile: nothing to repeat",
    ),
    (
        '"x" matches "x"',
        "^~~~~~~~~~~~~~~",
        "nothing here is a field, so this is the same for every packet",
    ),
    (
        "tcp.srcport[0:1] == 00",
        "^~~~~~~~~~~",
        "tcp.srcport is a number, which has no bytes to slice",
    ),
    (
        "tcp.flags.syn[0] == 1",
        "^~~~~~~~~~~~~",
        "tcp.flags.syn is true or false, which has no bytes to slice",
    ),
    (
        "frame.time_epoch[0:2] == 00:00",
        "^~~~~~~~~~~~~~~~",
        "frame.time_epoch is a time, which has no bytes to slice",
    ),
    (
        '"abc"[0:1] == "a"',
        "^~~~~",
        '"abc" is a value; a slice takes bytes out of a field',
    ),
    (
        "dnss[0:1] == 00",
        "^~~~",
        'no field is named "dnss"; did you mean "dns"?',
    ),
    # Two fields of kinds that don't compare
    (
        "ip.src == tcp.port",
        "          ^~~~~~~~",
        "ip.src is an IPv4 address and tcp.port is a number, so they can't be compared",
    ),
    (
        "http.host == tcp.port",
        "             ^~~~~~~~",
        (
            "http.host is text and tcp.port is a number, so they can't be compared; for "
            'the text "tcp.port", write it in quotes'
        ),
    ),
    (
        "http.request.method == data",
        "                       ^~~~",
        (
            "http.request.method is text and data is a protocol, so they can't be "
            'compared; for the text "data", write it in quotes'
        ),
    ),
    (
        "eth.src == ip.src",
        "           ^~~~~~",
        ("eth.src is an Ethernet address and ip.src is an IPv4 address, so they can't be compared"),
    ),
    (
        "tcp.flags.syn == tcp.flags",
        "                 ^~~~~~~~~",
        ("tcp.flags.syn is true or false and tcp.flags is a number, so they can't be compared"),
    ),
    # Sets
    (
        'tcp.port in {"http"}',
        "             ^~~~~~",
        'tcp.port is a number, and "http" is text',
    ),
    (
        "tcp.port in {90..80}",
        "             ^~~~~~",
        "this range runs backwards, so nothing is in it",
    ),
    (
        "tcp.port in {tcp.srcport}",
        "             ^~~~~~~~~~~",
        "a set holds values, and tcp.srcport isn't one; to compare two fields, use ==",
    ),
    (
        "tcp.port in {80, x}",
        "                 ^",
        'tcp.port is a number, and "x" isn\'t one',
    ),
    (
        "ip.src in {10.0.0.0/40}",
        "                    ^~",
        'an IPv4 prefix is 0 to 32 bits, not "40"',
    ),
    (
        "ip.src in {10.0.0.9 .. 10.0.0.1}",
        "           ^~~~~~~~~~~~~~~~~~~~",
        "this range runs backwards, so nothing is in it",
    ),
    (
        "80 in {80}",
        "^~~~~~~~~~",
        "nothing here is a field, so this is the same for every packet",
    ),
    # Masks and functions
    (
        "http.host & 1",
        "^~~~~~~~~",
        "& works on numbers, and http.host is text",
    ),
    (
        'tcp.flags & "a"',
        "            ^~~",
        'tcp.flags is a number, and "a" is text',
    ),
    (
        "tcp.flags & eth.src",
        "            ^~~~~~~",
        "& works on numbers, and eth.src is an Ethernet address",
    ),
    (
        "1 & 2",
        "^~~~~",
        "nothing here is a field, so this is the same for every packet",
    ),
    (
        "nosuch(tcp.port) == 1",
        "^~~~~~",
        'no function is called "nosuch"; there are count, len, lower, upper',
    ),
    (
        "lenn(http.host) == 1",
        "^~~~",
        'no function is called "lenn"; did you mean "len"?',
    ),
    (
        "len() == 1",
        "^~~~~",
        "len() takes one field, and this gives it 0",
    ),
    (
        "len(http.host, udp) == 1",
        "^~~~~~~~~~~~~~~~~~~",
        "len() takes one field, and this gives it 2",
    ),
    (
        "len(tcp.port) > 1",
        "    ^~~~~~~~",
        "len() measures text or bytes, and tcp.port is a number",
    ),
    (
        'len("abc") == 3',
        "    ^~~~~",
        'len() takes a field, and "abc" is a value',
    ),
    (
        'lower(tcp.port) == "x"',
        "      ^~~~~~~~",
        "lower() changes the case of text, and tcp.port is a number",
    ),
    (
        "count(eth.src[0:1]) == 1",
        "      ^~~~~~~~~~~~",
        "count() counts a field, so it takes a field's name",
    ),
    (
        "count(dnss) == 1",
        "      ^~~~",
        'no field is named "dnss"; did you mean "dns"?',
    ),
    # A test used as a value
    (
        "frame.number == 1 == 1",
        "^~~~~~~~~~~~~~~~~",
        (
            "this is already true or false, so it can't be used as a value; join two "
            'tests with "and" or "or"'
        ),
    ),
    (
        "1 < frame.number < 4",
        "^~~~~~~~~~~~~~~~",
        (
            "this is already true or false, so it can't be used as a value; join two "
            'tests with "and" or "or"'
        ),
    ),
    (
        "(tcp or udp) == 1",
        " ^~~~~~~~~~",
        (
            "this is already true or false, so it can't be used as a value; join two "
            'tests with "and" or "or"'
        ),
    ),
    (
        "tcp == udp == ip",
        "^~~~~~~~~~",
        (
            "this is already true or false, so it can't be used as a value; join two "
            'tests with "and" or "or"'
        ),
    ),
    (
        "(tcp.port == 80)[0:1]",
        " ^~~~~~~~~~~~~~",
        (
            "this is already true or false, so it can't be used as a value; join two "
            'tests with "and" or "or"'
        ),
    ),
    (
        "ip.addr contains 10.0.0.0/8",
        "        ^~~~~~~~",
        "contains looks inside text or bytes, and ip.addr is an IPv4 address",
    ),
    (
        "tcp.flags & 10.0.0.0/8",
        "            ^~~~~~~~~~",
        'tcp.flags is a number, and "10.0.0.0/8" isn\'t one',
    ),
    (
        "not 80",
        "    ^~",
        '"80" is a value, not a test; compare a field with it',
    ),
    (
        'tcp and "x"',
        "        ^~~",
        '"x" is a value, not a test; compare a field with it',
    ),
    # The marker stays under the right column when the filter has tabs or line breaks
    (
        "tcp.port\t== hello",
        "            ^~~~~",
        'tcp.port is a number, and "hello" isn\'t one',
    ),
    (
        "tcp.port == 80 and\n udp.port == x",
        "                                ^",
        'udp.port is a number, and "x" isn\'t one',
    ),
]


@pytest.mark.parametrize(("text", "expected"), VALID, ids=[text for text, _ in VALID])
def test_a_filter_matches_the_packets_it_should(text: str, expected: list[int]) -> None:
    compiled = compile_display_filter(text)
    assert display.matched(compiled) == expected
    assert display.walked(compiled) == expected


@pytest.mark.parametrize(("text", "marker", "message"), INVALID, ids=[each[0] for each in INVALID])
def test_a_wrong_filter_says_what_is_wrong_and_where(text: str, marker: str, message: str) -> None:
    with pytest.raises(DisplayFilterError) as caught:
        compile_display_filter(text)
    assert caught.value.message == message
    assert str(caught.value) == message
    # The filter is printed with anything that isn't a space turned into
    # one, so that the marker lines up whatever the filter was typed with.
    shown = "".join(" " if character.isspace() else character for character in text)
    assert caught.value.pointer() == f"{shown}\n{marker}"
    assert caught.value.text == text


def test_the_suite_covers_both_kinds_of_filter() -> None:
    assert len(VALID) >= 100
    assert len(INVALID) >= 100
    assert len({text for text, _ in VALID}) == len(VALID)
    assert len({text for text, _, _ in INVALID}) == len(INVALID)
