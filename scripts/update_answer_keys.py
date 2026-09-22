"""Record what tshark and capinfos report for each sample capture.

For every capture file under samples/, this writes two answer keys beside it:

    <capture>.tshark.tsv    one row per packet, from ``tshark -T fields``
    <capture>.capinfos.tsv  packet count and earliest and latest packet time

The tests compare pilotfish's reader with these files, so CI doesn't need
Wireshark installed. Run it after adding a sample:

    uv run scripts/update_answer_keys.py              # every sample
    uv run scripts/update_answer_keys.py FILE [FILE ...]
"""

import subprocess
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURE_SUFFIXES = frozenset({".cap", ".ntar", ".pcap", ".pcapng"})

TSHARK_FIELDS = ("frame.time_epoch", "frame.len", "frame.cap_len", "frame.interface_id")
# tshark lists pcapng Custom Blocks as frames even though they aren't packets.
# They're the only records with a Private Enterprise Number, so filter on it.
TSHARK_FILTER = "not frame.cb_pen"
# Table output, exact counts, packet count, earliest and latest time, epoch seconds.
CAPINFOS_FLAGS = ("-T", "-M", "-c", "-a", "-e", "-S")


def find_captures() -> list[Path]:
    return sorted(p for p in SAMPLES_DIR.rglob("*") if p.suffix in CAPTURE_SUFFIXES)


def run_tool(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"{' '.join(command)} failed in {cwd}:\n{result.stderr}")
    return result.stdout


def write_answer_keys(capture: Path) -> None:
    # Run from the capture's folder so capinfos records only the file name,
    # not a path from this machine.
    fields = [arg for field in TSHARK_FIELDS for arg in ("-e", field)]
    tshark = ["tshark", "-n", "-r", capture.name, "-Y", TSHARK_FILTER, "-T", "fields"]
    tshark += ["-E", "header=y", *fields]
    capture.with_name(capture.name + ".tshark.tsv").write_text(run_tool(tshark, capture.parent))
    capinfos = ["capinfos", *CAPINFOS_FLAGS, capture.name]
    capture.with_name(capture.name + ".capinfos.tsv").write_text(run_tool(capinfos, capture.parent))


def main(argv: list[str]) -> None:
    captures = [Path(arg).resolve() for arg in argv] or find_captures()
    for capture in captures:
        write_answer_keys(capture)
        print(f"wrote answer keys for {capture.relative_to(SAMPLES_DIR.parent)}")


if __name__ == "__main__":
    main(sys.argv[1:])
