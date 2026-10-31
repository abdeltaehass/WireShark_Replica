"""The app's live capture, display filter bar, interface picker and status bar.

Most of these drive the window with a stand-in for the capture helper, a
script that streams a sample capture as the helper would, so they need no
permission to capture. The last one runs the real helper on loopback.
"""

import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import pilotfish.core.protocols  # noqa: E402, F401  (registers the dissectors)
from loopback import LoopbackTraffic  # noqa: E402
from pilotfish.core.capture import Device  # noqa: E402
from pilotfish.core.capture.counters import Counters  # noqa: E402
from pilotfish.core.display import compile_display_filter  # noqa: E402
from pilotfish.core.dissect import ProtocolTree, Session, dissect  # noqa: E402
from pilotfish.core.formats import CaptureFile  # noqa: E402
from pilotfish.core.packet import Packet  # noqa: E402
from pilotfish.gui.filter_bar import (  # noqa: E402
    INVALID_COLOUR,
    VALID_COLOUR,
    FilterEdit,
    Validity,
)
from pilotfish.gui.interfaces import InterfacePicker  # noqa: E402
from pilotfish.gui.packet_list import REFRESH_MS, PacketListModel  # noqa: E402
from pilotfish.gui.window import MainWindow  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
HTTP = SAMPLES / "wireshark-wiki" / "http.cap"
EXAMPLE = SAMPLES / "wireshark-wiki" / "pcapng-example.pcapng"

# Streams a capture file to standard output a piece at a time, reporting as
# the helper does, then waits to be told to stop.
FAKE_HELPER = """
import json, signal, sys, time
capture, how = sys.argv[1], sys.argv[2]
def say(event, **fields):
    print(json.dumps({"event": event, **fields}), file=sys.stderr, flush=True)
if how == "refuse":
    say("error", kind="permission", message="/dev/bpf0: Permission denied")
    sys.exit(1)
stop = []
signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
say("started", interface="fake0", link_type=1)
data = open(capture, "rb").read()
for start in range(0, len(data), 4000):
    sys.stdout.buffer.write(data[start:start + 4000])
    sys.stdout.buffer.flush()
    time.sleep(0.005)
say("stats", captured=631, dropped=3)
while not stop:
    time.sleep(0.01)
say("stopped", captured=631, dropped=3)
"""


def fake_helper(tmp_path: Path, capture: Path, how: str = "stream") -> list[str]:
    script = tmp_path / "fake_helper.py"
    script.write_text(FAKE_HELPER)
    return [sys.executable, str(script), str(capture), how]


@pytest.fixture(scope="module")
def app() -> QApplication:
    found = QApplication.instance()
    return found if isinstance(found, QApplication) else QApplication([])


def fake_devices() -> list[Device]:
    return [
        Device("en0", 0x16, ("192.0.2.10",), "Wi-Fi"),
        Device("lo0", 0x17, ("127.0.0.1",), "Loopback"),
    ]


class FakeCounters:
    def __init__(self) -> None:
        self.packets = {"en0": 1000, "lo0": 50}

    def __call__(self) -> dict[str, Counters]:
        return {name: Counters(count, 0, 0, 0) for name, count in self.packets.items()}


@pytest.fixture
def window(app: QApplication) -> Iterator[MainWindow]:
    picker = InterfacePicker(devices=fake_devices, counters=FakeCounters())
    shown = MainWindow(picker=picker)
    shown.warnings = []  # type: ignore[attr-defined]
    shown.warn = shown.warnings.append  # type: ignore[attr-defined, method-assign]
    shown.resize(1000, 700)
    shown.show()
    yield shown
    shown.close()
    shown.deleteLater()
    app.processEvents()


def wait_until(app: QApplication, done: Callable[[], bool], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not done():
        assert time.monotonic() < deadline, "timed out"
        app.processEvents()
        time.sleep(0.002)


def in_order(capture: Path) -> list[tuple[Packet, ProtocolTree]]:
    session = Session()
    with CaptureFile(capture) as file:
        return [
            (packet, dissect(packet, number, session=session))
            for number, packet in enumerate(file, start=1)
        ]


def numbers(window: MainWindow) -> list[int]:
    assert window.model is not None
    model = window.model
    return [int(str(model.data(model.index(row, 0)))) for row in range(model.rowCount())]


def validity(edit: FilterEdit) -> Validity:
    """Read afresh, rather than as last asserted."""
    return edit.validity


def test_the_filter_bar_turns_green_or_red_as_it_is_typed(
    app: QApplication, window: MainWindow
) -> None:
    edit = window.filter_bar.edit
    QTest.keyClicks(edit, "tcp.port == 80")
    assert edit.validity == Validity.VALID
    assert VALID_COLOUR in edit.styleSheet()
    QTest.keyClick(edit, Qt.Key.Key_Backspace)
    QTest.keyClicks(edit, " and")
    assert validity(edit) == Validity.INVALID
    assert INVALID_COLOUR in edit.styleSheet()
    assert edit.toolTip() == "the filter ends where a field or a value was expected"
    assert window.statusBar().currentMessage().startswith("Display filter: the filter ends")
    edit.clear()
    assert validity(edit) == Validity.EMPTY
    assert edit.styleSheet() == ""


def test_a_filter_shows_only_the_packets_it_matches(app: QApplication, window: MainWindow) -> None:
    window.open_file(HTTP)
    display = compile_display_filter("http || tcp.flags.syn == 1")
    expected = [
        number
        for number, (packet, tree) in enumerate(in_order(HTTP), start=1)
        if display.matches(tree, packet.data)
    ]
    window.filter_bar.edit.setText(display.text)
    assert window.filter_bar.apply()
    assert window.model is not None
    wait_until(app, lambda: window.model is not None and not window.model.filtering)
    window.model.refresh()
    assert numbers(window) == expected
    share = 100 * len(expected) / 43
    assert window.counts_label.text() == f"Packets: 43 · Displayed: {len(expected)} ({share:.1f}%)"

    # A row shows its own packet, wherever it is in the file.
    window.packet_list.selectRow(len(expected) - 1)
    app.processEvents()
    frame = window.tree.topLevelItem(0)
    assert frame is not None
    assert frame.text(0).startswith(f"Frame {expected[-1]}:")

    # A filter that doesn't compile isn't applied.
    window.filter_bar.edit.setText("http and")
    assert not window.filter_bar.apply()
    assert numbers(window) == expected

    window.filter_bar.edit.clear()
    window.filter_bar.apply()
    assert numbers(window) == list(range(1, 44))
    assert window.counts_label.text() == "Packets: 43"


class Growing:
    def __init__(self, packets: list[Packet]) -> None:
        self.waiting = packets
        self.arrived: list[Packet] = []

    def arrive(self, count: int) -> None:
        self.arrived += self.waiting[:count]
        del self.waiting[:count]

    def __len__(self) -> int:
        return len(self.arrived)

    def __getitem__(self, row: int) -> Packet:
        return self.arrived[row]


def test_new_rows_reach_the_view_in_batches(app: QApplication) -> None:
    with CaptureFile(EXAMPLE) as file:
        growing = Growing([packet for packet in file])
    model = PacketListModel(growing)
    inserts: list[tuple[int, int]] = []
    model.rowsInserted.connect(lambda _parent, first, last: inserts.append((first, last)))
    started = time.monotonic()
    # Packets arriving a few at a time, far faster than ten times a second.
    while growing.waiting:
        growing.arrive(7)
        app.processEvents()
    elapsed = time.monotonic() - started
    assert model.rowCount() <= len(growing)
    wait_until(app, lambda: model.rowCount() == len(growing))
    assert sum(last - first + 1 for first, last in inserts) == len(growing)
    # One insert each time the timer fired, not one for each arrival.
    assert len(inserts) <= elapsed * 1000 / REFRESH_MS + 2
    assert len(inserts) < 631 / 7
    model.stop()


def test_a_live_capture_fills_the_list_as_it_comes(
    app: QApplication, window: MainWindow, tmp_path: Path
) -> None:
    window.helper = tuple(fake_helper(tmp_path, EXAMPLE))
    assert window.start_capture("fake0")
    session = window.session
    assert session is not None
    assert window.windowTitle() == "Capturing from fake0 — pilotfish"
    assert not window.start_action.isEnabled()
    assert window.stop_action.isEnabled()
    wait_until(app, lambda: window.model is not None and window.model.rowCount() == 631)
    wait_until(app, lambda: session.dropped == 3)
    assert window.counts_label.text() == "Packets: 631 · Dropped: 3 (0.5%)"

    # Filtering while capturing, which decodes every packet to decide.
    window.filter_bar.edit.setText("dns")
    window.filter_bar.apply()
    expected = [
        number
        for number, (packet, tree) in enumerate(in_order(EXAMPLE), start=1)
        if compile_display_filter("dns").matches(tree, packet.data)
    ]
    wait_until(app, lambda: window.model is not None and window.model.rowCount() == len(expected))
    assert numbers(window) == expected

    window.stop_capture()
    wait_until(app, lambda: not session.running)
    app.processEvents()
    assert window.windowTitle() == "fake0 — pilotfish"
    assert window.start_action.isEnabled()
    assert window.restart_action.isEnabled()
    spool = session.stream.path
    assert spool.read_bytes() == EXAMPLE.read_bytes()

    # Restarting throws the capture away and starts again.
    window.restart_capture()
    assert window.session is not session
    assert not spool.exists()
    window.close_file()
    assert window.pages.currentWidget() is window.picker


def test_a_capture_without_permission_offers_the_installer(
    app: QApplication, window: MainWindow, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[str] = []
    ran: list[Sequence[str]] = []

    def ask(text: str) -> bool:
        asked.append(text)
        return True

    def run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        ran.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(window, "ask_to_install", ask)
    window.run_command = run
    window.helper = tuple(fake_helper(tmp_path, EXAMPLE, "refuse"))
    monkeypatch.setattr(
        "pilotfish.core.capture.access.check",
        lambda user=None: access_state(readable=False),
    )
    window.start_capture("fake0")
    wait_until(app, lambda: bool(ran))
    assert "Install it once with" in asked[0]
    [command] = ran
    assert command[:2] == ["osascript", "-e"]
    assert command[2].startswith('do shell script "')
    assert command[2].endswith('" with administrator privileges')
    assert " -m pilotfish bpf-access install --user " in command[2]
    assert window.file_label.text() == "Capture failed: /dev/bpf0: Permission denied"


def access_state(**changes: object) -> object:
    from pilotfish.core.capture.access import Access

    fields: dict[str, object] = {
        "user": "someone",
        "daemon": False,
        "wireshark_daemon": False,
        "member": False,
        "effective": False,
        "readable": True,
    }
    fields.update(changes)
    return Access(**fields)  # type: ignore[arg-type]


def test_the_picker_graphs_each_interfaces_traffic(app: QApplication) -> None:
    counters = FakeCounters()
    picker = InterfacePicker(devices=fake_devices, counters=counters)
    assert picker.selected() == "en0"
    for step in (10, 30, 5):
        counters.packets["en0"] += step
        picker.sample()
    assert list(picker.rates["en0"]) == [10, 30, 5]
    assert list(picker.rates["lo0"]) == [0, 0, 0]
    item = picker.list.topLevelItem(0)
    assert item is not None
    assert item.toolTip(1) == "5 packets in the last second"
    picker.resize(700, 300)
    picker.show()
    picker.grab()  # paints the graphs

    started: list[str] = []
    picker.start_requested.connect(started.append)
    lo0 = picker.list.topLevelItem(1)
    assert lo0 is not None
    picker.list.itemActivated.emit(lo0, 0)
    assert started == ["lo0"]

    QTest.keyClicks(picker.filter, "tcp porrt 80")
    assert validity(picker.filter) == Validity.INVALID
    picker.list.itemActivated.emit(lo0, 0)
    assert started == ["lo0"]  # not with a filter that doesn't compile
    picker.close()


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
def test_capturing_loopback_with_the_real_helper(app: QApplication, window: MainWindow) -> None:
    with LoopbackTraffic() as traffic:
        assert window.start_capture("lo0", f"udp port {traffic.port}")
        session = window.session
        assert session is not None
        started: list[bool] = []
        session.started.connect(lambda: started.append(True))
        wait_until(app, lambda: bool(started) or session.error is not None)
        assert session.error is None
        for _ in range(200):
            traffic.send(64)
        wait_until(app, lambda: window.model is not None and window.model.rowCount() >= 200)
        window.filter_bar.edit.setText("udp.length == 72")
        window.filter_bar.apply()
        wait_until(app, lambda: window.model is not None and window.model.rowCount() == 200)
        window.stop_capture()
        wait_until(app, lambda: not session.running)
    assert session.error is None
    assert window.counts_label.text().startswith("Packets: 200 · Displayed: 200 (100.0%)")
