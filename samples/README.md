# Sample captures

Capture files for the tests. Next to each one are answer keys recorded from
Wireshark's own tools by `scripts/update_answer_keys.py`:

- `<file>.tshark.tsv`: tshark's time, length, captured length and interface
  for every packet
- `<file>.capinfos.tsv`: capinfos's packet count and earliest and latest time
- `<file>.tshark.json.gz`: every field tshark decodes, gzipped because it is
  large. The dissector tests compare field values against it. Captures that
  only exercise the file format don't have one.
- `<file>.filters.json`: the packets `tshark -Y` matches for each display
  filter listed in `display-filters.txt`, written as runs such as `1-3,7`.
  `tests/test_display_tshark.py` holds pilotfish's display filters to them.

The tests check pilotfish against all of these, so CI doesn't need Wireshark
installed.

## Display filters

`display-filters.txt` is the list of filters tshark is asked about, one per
line. Each has to be valid in Wireshark and use only fields pilotfish decodes.
After adding one, record its answers for every capture, which takes a couple
of minutes:

```sh
uv run scripts/update_answer_keys.py --filters
```

Two things to know when a filter's answers surprise you. Wireshark knows far
more fields than pilotfish, so a short hexadecimal value can be a field's name
there: `ff` is one, which makes `eth.dst[0] == ff` a comparison of two fields.
And when both sides of a comparison are slices that reach past the end of
their field, Wireshark calls them equal, where pilotfish says a slice that
doesn't fit has no value to compare.

## Sources

### `wireshark-wiki/`

From the [Wireshark sample captures page](https://wiki.wireshark.org/SampleCaptures),
unchanged except that `.gz` files were decompressed.

| File | Format | What it covers |
|---|---|---|
| `http.cap` | pcap | Ethernet, microseconds |
| `dhcp.pcap` | pcap | The same four packets in three formats |
| `dhcp-nanosecond.pcap` | pcap | Nanosecond timestamps (magic 0xa1b23c4d) |
| `dhcp.pcapng` | pcapng | |
| `nlmon-big.pcap` | pcap | Big-endian file, Linux netlink |
| `RawPacketIPv6Tunnel-UK6x.cap` | pcap | Raw IP under the legacy link type 12 |
| `dns.cap`, `arp-storm.pcap`, `telnet-cooked.pcap` | pcap | Ethernet, up to 622 packets |
| `pcapng-example.pcapng` | pcapng | Two interfaces with different link types, nanosecond resolution |
| `6lowpan-rfrag-icmpv6.pcapng` | pcapng | IEEE 802.15.4 TAP, two interfaces |
| `IrDA_Traffic.ntar` | pcapng | Linux IrDA. Wireshark strips a 16-byte pseudo-header from these packets, so its lengths are 16 bytes shorter than the file's; the test allows for that. |

### `pcapng-test-generator/`

The `output_be` and `output_le` files from
[hadrielk/pcapng-test-generator](https://github.com/hadrielk/pcapng-test-generator)
at commit `9a5c416`, flattened into `be/` and `le/`. MIT licensed; see
`pcapng-test-generator/LICENSE`. They cover every standard block type, Simple
Packet Blocks, custom blocks, all options, and files with several sections
in different byte orders, each written in both byte orders.

### `made/`

Small captures built by `scripts/make_test_captures.py`, a few packets each,
for what the wiki samples don't carry: VLAN tags, ICMP over Ethernet, ICMPv6
with neighbour discovery, IPv6 extension header chains, BSD loopback, and
headers whose checksums deliberately don't add up. `tcp.pcap` is two
connections written to provoke every judgement the TCP analysis can make —
retransmissions of three kinds, duplicate acknowledgements, a gap, a
re-ordered segment, a shut window with its probe and answer, a keep-alive, a
full window, a window update, and acknowledgements of data the capture never
saw — because real captures of a healthy network hardly ever contain them.
The times matter as much as the sequence numbers there: whether a late segment
counts as re-ordering or as a resend depends on how long after the other end's
last acknowledgement it arrived. `mdns.pcap` is a Bonjour question and the
announcement that answers it, whose names are written once and pointed at
afterwards, so it exercises the compression pointers that make DNS names
awkward. `ssh.pcap` is a session from the greeting to the point where the
keys change and there is nothing left to read, and `tls.pcap` is a handshake
up to the same point, carrying the server name a client asks for in the clear.

Three more are for messages that don't fit in one packet. `fragments.pcap` is
datagrams cut into IPv4 and IPv6 fragments that arrive in order, backwards,
with a piece sent twice, and with a piece that never comes. `segments.pcap`
is a TLS server's records cut wherever a segment happened to end — inside a
record, inside a record's header, and between records — followed by an SSH
key exchange message that takes two segments. `http-download.pcap` is a
20,000-byte file fetched over HTTP, whose fourth segment overtakes its third
and whose last is sent twice, then a body sent compressed and in chunks, and
on a second connection a body with no length at all, which ends when the
server hangs up. The file is the SHA-256 digests of the numbers 0 to 624,
one after another, and its own SHA-256 is

    4cfd36429b493d7232195a49be8270f51031a8bcc0878052b4c753eff45b9b85

which is what `tests/test_follow.py` expects to get back from following the
stream.

The script writes each packet field by field, and tshark decoding them in the
answer keys is the check that they were built right.

### `private/`

Captures you record yourself. Git ignores this folder, answer keys
included, because your own traffic can include IP addresses, hostnames and
DNS lookups that you may not want to publish. The tests still check any
capture here that has answer keys.

## Adding a capture

```sh
uv run scripts/update_answer_keys.py samples/private/my-capture.pcapng
uv run pytest tests/test_samples.py
```

Run the script with no arguments to regenerate every answer key, for example
after upgrading Wireshark.
