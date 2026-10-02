"""Time a display filter run two ways: walking its tree, and as compiled Python.

Every packet in the sample captures is decoded once, and then each filter is
run over all of them both ways. Three times are reported per packet:

    gather     finding the filter's fields in the packet's tree, which both
               ways need before they can start
    walk       evaluating by walking the typed tree
    compiled   evaluating by calling the generated function

The speedup is walk over compiled, which is what compiling buys.

    uv run scripts/benchmark_display_filters.py
    uv run scripts/benchmark_display_filters.py 'tcp.port == 80' 'dns or http'
"""

import sys
import time
from collections.abc import Callable
from pathlib import Path

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.display import compile_display_filter
from pilotfish.core.display.evaluate import test
from pilotfish.core.display.runtime import Found, gather
from pilotfish.core.dissect import LINK_TYPE, REGISTRY, ProtocolTree, Session, dissect
from pilotfish.core.formats import CaptureFile

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURE_SUFFIXES = frozenset({".cap", ".pcap", ".pcapng"})

FILTERS = (
    "dns",
    "tcp.port == 80",
    "ip.addr == 192.168.0.0/16",
    "tcp.port in {80, 443, 8000..8080}",
    'http.host contains "example"',
    'frame contains "GET"',
    "eth.src[0:3] == 00:00:01",
    "tcp.flags & 0x12 == 0x12",
    'http.request.uri matches "\\\\.html$"',
    "tcp.flags.syn == 1 and tcp.flags.ack == 0",
    "(tcp.port == 80 or udp.port == 53) and not ip.addr == 10.0.0.0/8",
    "ip.src == 192.0.2.1 and tcp.port in {80, 443} and tcp.len > 0 and not tcp.flags.reset == 1",
)

REPEATS = 7
"""Each measurement is the fastest of this many runs, which is the one least
disturbed by whatever else the machine was doing."""

type Decoded = list[tuple[ProtocolTree, bytes]]


def decode_samples() -> Decoded:
    """Every packet of every capture pilotfish can decode, with its tree."""
    decoded: Decoded = []
    for capture in sorted(SAMPLES_DIR.rglob("*")):
        if capture.suffix not in CAPTURE_SUFFIXES:
            continue
        session = Session()
        with CaptureFile(capture) as file:
            for number, packet in enumerate(file, start=1):
                if REGISTRY.find(LINK_TYPE, packet.link_type) is None:
                    break
                decoded.append((dissect(packet, number, session=session), bytes(packet.data)))
    return decoded


def fastest(run: Callable[[], object]) -> int:
    """The shortest time ``run`` takes, in nanoseconds."""
    best = None
    for _ in range(REPEATS):
        started = time.perf_counter_ns()
        run()
        elapsed = time.perf_counter_ns() - started
        best = elapsed if best is None else min(best, elapsed)
    assert best is not None
    return best


def measure(text: str, decoded: Decoded) -> tuple[float, float, float, int]:
    """Nanoseconds per packet to gather, to walk and to run compiled, and how
    many packets the filter matched."""
    compiled = compile_display_filter(text)
    typed = compiled.typed
    function = compiled._compiled
    assert typed is not None
    assert function is not None
    names = compiled.names
    gathered: list[tuple[Found, bytes]] = [(gather(tree, names), data) for tree, data in decoded]

    walked = [test(typed, found, data) for found, data in gathered]
    ran = [function(found, data) for found, data in gathered]
    assert walked == ran, f"the two ways disagree about {text}"

    count = len(decoded)
    gather_ns = fastest(lambda: [gather(tree, names) for tree, _ in decoded]) / count
    walk_ns = fastest(lambda: [test(typed, found, data) for found, data in gathered]) / count
    compiled_ns = fastest(lambda: [function(found, data) for found, data in gathered]) / count
    return gather_ns, walk_ns, compiled_ns, sum(ran)


def main(argv: list[str]) -> None:
    filters = argv or list(FILTERS)
    decoded = decode_samples()
    print(f"{len(decoded)} packets, fastest of {REPEATS} runs, nanoseconds per packet\n")
    width = max(len(text) for text in filters)
    print(f"{'filter':<{width}}  matched  gather    walk  compiled  speedup")
    speedups = []
    for text in filters:
        gather_ns, walk_ns, compiled_ns, matched = measure(text, decoded)
        speedups.append(walk_ns / compiled_ns)
        print(
            f"{text:<{width}}  {matched:>7}  {gather_ns:>6.0f}  {walk_ns:>6.0f}  "
            f"{compiled_ns:>8.0f}  {walk_ns / compiled_ns:>6.1f}x"
        )
    speedups.sort()
    print(f"\nmedian speedup {speedups[len(speedups) // 2]:.1f}x")


if __name__ == "__main__":
    main(sys.argv[1:])
