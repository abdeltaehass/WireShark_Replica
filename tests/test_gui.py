"""The desktop app's window, driven the way a person would drive it.

Qt draws offscreen here, so these run without a display. They need PySide6,
from the gui extra, and are skipped without it, as on the Linux CI job.
"""

import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import pilotfish.core.protocols  # noqa: E402, F401  (registers the dissectors)
from builders import pcap_header, pcap_record  # noqa: E402
from pilotfish.core.columns import DESTINATIONS, SOURCES, address, protocol, summary  # noqa: E402
from pilotfish.core.dissect import ProtocolTree, Session, dissect  # noqa: E402
from pilotfish.core.formats import CaptureFile, CaptureFileError  # noqa: E402
from pilotfish.core.packet import Interface  # noqa: E402
from pilotfish.gui.app import main  # noqa: E402
from pilotfish.gui.bytes_view import HexView  # noqa: E402
from pilotfish.gui.packet_list import COLUMNS, relative_time  # noqa: E402
from pilotfish.gui.window import MainWindow  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
DNS = SAMPLES / "wireshark-wiki" / "dns.cap"
HTTP = SAMPLES / "wireshark-wiki" / "http.cap"
MANY = SAMPLES / "wireshark-wiki" / "pcapng-example.pcapng"


@pytest.fixture(scope="module")
def app() -> QApplication:
    found = QApplication.instance()
    return found if isinstance(found, QApplication) else QApplication([])


@pytest.fixture
def window(app: QApplication) -> Iterator[MainWindow]:
    shown = MainWindow()
    shown.resize(1000, 700)
    shown.show()
    yield shown
    shown.close()
    shown.deleteLater()
    app.processEvents()


def settle(app: QApplication, window: MainWindow) -> None:
    """Let the window paint and decode until it has nothing left to do."""
    deadline = time.monotonic() + 10
    app.processEvents()
    while window.model is not None and window.model.busy:
        assert time.monotonic() < deadline, "decoding never caught up"
        app.processEvents()
    app.processEvents()


def in_order(capture: Path) -> list[ProtocolTree]:
    session = Session()
    with CaptureFile(capture) as file:
        return [dissect(packet, number, session=session) for number, packet in enumerate(file, 1)]


def cell(window: MainWindow, row: int, column: int) -> str:
    assert window.model is not None
    text = window.model.data(window.model.index(row, column))
    assert isinstance(text, str)
    return text


def test_the_columns_are_wiresharks(app: QApplication, window: MainWindow) -> None:
    window.open_file(DNS)
    assert window.model is not None
    headers = [
        window.model.headerData(column, Qt.Orientation.Horizontal)
        for column in range(window.model.columnCount())
    ]
    assert headers == list(COLUMNS)
    assert window.model.rowCount() == 38
    assert window.windowTitle() == "dns.cap — pilotfish"
    assert window.file_label.text() == "dns.cap: 38 packets"


def test_each_row_says_what_the_command_line_says(app: QApplication, window: MainWindow) -> None:
    window.open_file(HTTP)
    assert window.model is not None
    window.model.decoder.advance(len(window.model.decoder))
    with CaptureFile(HTTP) as file:
        packets = list(file)
    for row, tree in enumerate(in_order(HTTP)):
        assert cell(window, row, 0) == str(row + 1)
        assert cell(window, row, 2) == address(tree, SOURCES)
        assert cell(window, row, 3) == address(tree, DESTINATIONS)
        assert cell(window, row, 4) == protocol(tree)
        assert cell(window, row, 5) == str(packets[row].original_length)
        assert cell(window, row, 6) == summary(tree)
    assert cell(window, 0, 1) == "0.000000"
    assert cell(window, 37, 1) == "4.846969"


def test_only_the_rows_on_screen_are_decoded(app: QApplication, window: MainWindow) -> None:
    window.open_file(MANY)
    settle(app, window)
    assert window.model is not None
    decoder = window.model.decoder
    shown = window.packet_list.rowAt(window.packet_list.viewport().height() - 1) + 1
    assert 5 < shown < 60
    # The rows on screen, and not the hundreds below them.
    assert shown <= decoder.decoded <= shown + 1
    assert len(decoder) == 631
    for row in range(decoder.decoded):
        assert cell(window, row, 6)
    assert cell(window, decoder.decoded + 5, 6) == ""

    window.packet_list.scrollToBottom()
    settle(app, window)
    # The packets between have to be decoded first, for what they say about
    # the ones after.
    assert decoder.decoded == 631
    assert window.progress_label.text() == ""


def test_selecting_a_packet_shows_its_tree_and_bytes(app: QApplication, window: MainWindow) -> None:
    window.open_file(DNS)
    window.packet_list.selectRow(1)
    app.processEvents()
    tree = in_order(DNS)[1]
    items = [window.tree.topLevelItem(i) for i in range(window.tree.topLevelItemCount())]
    shown = [item.text(0) for item in items if item is not None]
    assert shown == [layer.summary or layer.label for layer in tree.layers]
    [frame] = window.bytes.views()
    assert window.bytes.tabBar().isHidden()
    with CaptureFile(DNS) as file:
        data = bytes(list(file)[1].data)
    assert frame.data == data
    assert frame.toPlainText().splitlines()[0] == (
        "0000  00 e0 18 b1 0c ad 00 c0  9f 32 41 8c 08 00 45 00   ........ .2A...E."
    )


def test_a_packet_not_decoded_yet_shows_its_tree_once_it_is(
    app: QApplication, window: MainWindow
) -> None:
    window.open_file(MANY)
    assert window.model is not None
    decoder = window.model.decoder
    window.packet_list.selectRow(600)
    # Nothing waits: the bytes are there at once, and the tree says why it isn't.
    assert decoder.decoded < 600
    waiting = window.tree.topLevelItem(0)
    assert waiting is not None
    assert waiting.text(0) == "Decoding the packets before packet 601…"
    [frame] = window.bytes.views()
    with CaptureFile(MANY) as file:
        assert frame.data == bytes(list(file)[600].data)

    settle(app, window)
    assert decoder.decoded >= 601
    expected = in_order(MANY)[600]
    shown = window.tree.topLevelItem(0)
    assert shown is not None
    assert shown.text(0) == expected.layers[0].summary


def test_selecting_a_field_lights_up_its_bytes(app: QApplication, window: MainWindow) -> None:
    window.open_file(DNS)
    window.packet_list.selectRow(0)
    app.processEvents()
    item = window.tree.item_for("ip.src")
    assert item is not None
    window.tree.setCurrentItem(item)
    app.processEvents()
    [frame] = window.bytes.views()
    # Ethernet's 14 bytes, then the IPv4 header up to its source address.
    assert frame.highlighted == (26, 4)
    lit = [selection.cursor.selectedText() for selection in frame.extraSelections()]
    assert lit == ["c0 a8 aa 08", "...."]

    # A field worked out rather than read has no bytes to light.
    item = window.tree.item_for("frame.number")
    assert item is not None
    window.tree.setCurrentItem(item)
    app.processEvents()
    assert lit_up(frame) is None
    assert frame.extraSelections() == []


def lit_up(view: HexView) -> tuple[int, int] | None:
    """What a view has lit up, read afresh rather than as last asserted."""
    return view.highlighted


def click(view: HexView, offset: int, *, text: bool = False) -> None:
    """Click a byte, in the hexadecimal or in the text."""
    line, index = divmod(offset, 16)
    column = view.text_column(index) if text else view.hex_column(index) + 1
    cursor = view.textCursor()
    cursor.setPosition(view.document().findBlockByNumber(line).position() + column)
    rectangle = view.cursorRect(cursor)
    QTest.mouseClick(
        view.viewport(),
        Qt.MouseButton.LeftButton,
        pos=QPoint(rectangle.left() + 2, rectangle.center().y()),
    )


def test_clicking_a_byte_selects_its_field(app: QApplication, window: MainWindow) -> None:
    window.open_file(DNS)
    window.packet_list.selectRow(0)
    app.processEvents()
    [frame] = window.bytes.views()
    click(frame, 27)
    app.processEvents()
    node = window.tree.node_of(window.tree.currentItem())
    assert node is not None
    assert (node.name, node.offset, node.length) == ("ip.src", 26, 4)
    assert frame.highlighted == (26, 4)

    # The same byte as text, and a byte of flags, which selects the flags.
    click(frame, 20, text=True)
    app.processEvents()
    node = window.tree.node_of(window.tree.currentItem())
    assert node is not None
    assert node.name == "ip.flags"


def test_reassembled_bytes_have_a_tab_of_their_own(app: QApplication, window: MainWindow) -> None:
    window.open_file(HTTP)
    window.packet_list.selectRow(37)
    app.processEvents()
    frame, reassembled = window.bytes.views()
    assert window.bytes.tabText(1) == "Reassembled TCP (18364 bytes)"
    assert not window.bytes.tabBar().isHidden()

    item = window.tree.item_for("http.response.code")
    assert item is not None
    window.tree.setCurrentItem(item)
    app.processEvents()
    assert window.bytes.currentIndex() == 1
    assert reassembled.highlighted == (9, 3)
    assert reassembled.data[9:12] == b"200"

    click(reassembled, reassembled.data.index(b"Server") + 2)
    app.processEvents()
    node = window.tree.node_of(window.tree.currentItem())
    assert node is not None
    assert node.name == "http.response.line"
    current = window.tree.currentItem()
    assert current is not None
    assert current.text(0) == r"Response line: Server: Apache\r\n"

    # Back to the frame's own bytes for a field read from the frame.
    item = window.tree.item_for("tcp.srcport")
    assert item is not None
    window.tree.setCurrentItem(item)
    app.processEvents()
    assert window.bytes.currentIndex() == 0
    assert frame.highlighted == (34, 2)


def test_opened_subtrees_stay_open_on_the_next_packet(
    app: QApplication, window: MainWindow
) -> None:
    window.open_file(DNS)
    window.packet_list.selectRow(0)
    app.processEvents()
    ip = window.tree.item_for("ip")
    assert ip is not None
    assert not ip.isExpanded()
    ip.setExpanded(True)
    window.packet_list.selectRow(2)
    app.processEvents()
    ip = window.tree.item_for("ip")
    assert ip is not None
    assert ip.isExpanded()


def test_a_file_that_isnt_a_capture_leaves_the_open_one(
    app: QApplication, window: MainWindow, tmp_path: Path
) -> None:
    window.open_file(DNS)
    junk = tmp_path / "notes.txt"
    junk.write_text("not a capture")
    with pytest.raises(CaptureFileError, match="not a pcap or pcapng file"):
        window.open_file(junk)
    assert window.model is not None
    assert window.model.rowCount() == 38
    with pytest.raises(FileNotFoundError):
        window.open_file(tmp_path / "missing.pcap")


def test_a_damaged_file_opens_with_what_came_before(
    app: QApplication, window: MainWindow, tmp_path: Path
) -> None:
    capture = tmp_path / "cut.pcap"
    capture.write_bytes(
        pcap_header() + pcap_record("<", 1, 0, b"whole") + pcap_record("<", 2, 0, b"cut")[:-1]
    )
    window.open_file(capture)
    assert window.model is not None
    assert window.model.rowCount() == 1
    assert window.file_label.text() == (
        "cut.pcap: 1 packet. The file is damaged after that: "
        "packet at offset 45 is cut short: 2 of 3 bytes"
    )


def test_closing_the_file_empties_the_window(app: QApplication, window: MainWindow) -> None:
    window.open_file(DNS)
    window.packet_list.selectRow(0)
    app.processEvents()
    window.close_file()
    assert window.model is None
    assert window.packet_list.model() is None
    assert window.tree.topLevelItemCount() == 0
    assert window.bytes.count() == 0
    assert window.windowTitle() == "pilotfish"


def test_times_have_as_many_decimals_as_the_file_counts() -> None:
    microseconds = Interface(1, units_per_second=1_000_000)
    nanoseconds = Interface(1, units_per_second=1_000_000_000)
    assert relative_time(1_500_000_000, microseconds) == "1.500000"
    assert relative_time(1_500_000_001, nanoseconds) == "1.500000001"
    assert relative_time(-250_000_000, None) == "-0.250000"
    assert relative_time(2_000_000_000, Interface(1, units_per_second=1)) == "2"
    # A resolution in powers of two shows nanoseconds.
    assert relative_time(1, Interface(1, units_per_second=2**20)) == "0.000000001"


def test_the_app_without_qt_says_how_to_get_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import builtins

    real_import = builtins.__import__

    def without_qt(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("PySide6"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", without_qt)
    assert main([]) == 1
    assert "uv sync --extra gui" in capsys.readouterr().err
