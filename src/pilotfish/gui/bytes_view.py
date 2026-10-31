"""The packet's bytes, in hexadecimal and as text, under the protocol tree.

Each line is an offset, sixteen bytes in hexadecimal and the same bytes as
text, with a gap after the eighth so a byte's place in the line is easy to
read::

    0000  00 c0 9f 32 41 8c 00 e0  18 b1 0c ad 08 00 45 00   ...2A... ......E.

A field selected in the tree lights up its bytes in both halves, and a byte
clicked names its offset so the tree can select the field it belongs to.
A message reassembled from several packets is in none of them, so its bytes
get a tab of their own beside the frame's, as in Wireshark.
"""

from typing import override

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase, QMouseEvent, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit, QTabWidget, QTextEdit, QWidget

from pilotfish.core.dissect import Node, Source

BYTES_PER_LINE = 16
_HALF = BYTES_PER_LINE // 2
_GAP = "   "
"""Between the hexadecimal and the text."""


class HexView(QPlainTextEdit):
    """One run of bytes as a hex dump that can light up a stretch of them."""

    byte_clicked = Signal(int)
    """The offset of a byte clicked, in either half."""

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.data = data
        self.highlighted: tuple[int, int] | None = None
        """The offset and length lit up, if any."""
        # Four digits of offset, or as many as the last offset needs.
        self._prefix = max(4, len(f"{max(len(data) - 1, 0):x}")) + 2
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setPlainText(self._dump())

    def hex_column(self, index: int) -> int:
        """Where the byte at ``index`` in its line starts, in hexadecimal."""
        return self._prefix + 3 * index + (index >= _HALF)

    def text_column(self, index: int) -> int:
        """Where the byte at ``index`` in its line is, as text."""
        start = self.hex_column(BYTES_PER_LINE - 1) + 2 + len(_GAP)
        return start + index + (index >= _HALF)

    def byte_at(self, line: int, column: int) -> int | None:
        """The offset of the byte at a place in the dump, if there is one there."""
        for index in range(BYTES_PER_LINE):
            hex_start = self.hex_column(index)
            if hex_start <= column < hex_start + 2 or column == self.text_column(index):
                offset = line * BYTES_PER_LINE + index
                return offset if offset < len(self.data) else None
        return None

    def position_of(self, offset: int) -> int:
        """The place in the document where a byte's hexadecimal starts."""
        line, index = divmod(offset, BYTES_PER_LINE)
        block = self.document().findBlockByNumber(line)
        return block.position() + self.hex_column(index)

    def highlight(self, offset: int, length: int) -> None:
        """Light up ``length`` bytes from ``offset``, in both halves."""
        end = min(offset + length, len(self.data))
        if length <= 0 or offset >= end:
            self.clear_highlight()
            return
        self.highlighted = (offset, end - offset)
        shade = QTextCharFormat()
        shade.setBackground(self.palette().highlight())
        shade.setForeground(self.palette().highlightedText())
        selections = []
        for line in range(offset // BYTES_PER_LINE, (end - 1) // BYTES_PER_LINE + 1):
            first = max(offset, line * BYTES_PER_LINE) - line * BYTES_PER_LINE
            last = min(end, (line + 1) * BYTES_PER_LINE) - 1 - line * BYTES_PER_LINE
            for start, stop in (
                (self.hex_column(first), self.hex_column(last) + 2),
                (self.text_column(first), self.text_column(last) + 1),
            ):
                selection = QTextEdit.ExtraSelection()
                selection.cursor = self._cursor(line, start, stop)
                selection.format = shade
                selections.append(selection)
        self.setExtraSelections(selections)
        # Bring the first byte into view without moving anything else.
        self.setTextCursor(self._cursor(offset // BYTES_PER_LINE, 0, 0))
        self.ensureCursorVisible()

    def clear_highlight(self) -> None:
        self.highlighted = None
        self.setExtraSelections([])

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        super().mousePressEvent(event)
        if event.button() != Qt.MouseButton.LeftButton:
            return
        cursor = self.cursorForPosition(event.position().toPoint())
        offset = self.byte_at(cursor.blockNumber(), cursor.positionInBlock())
        if offset is not None:
            self.byte_clicked.emit(offset)

    def _cursor(self, line: int, start: int, stop: int) -> QTextCursor:
        position = self.document().findBlockByNumber(line).position()
        cursor = QTextCursor(self.document())
        cursor.setPosition(position + start)
        cursor.setPosition(position + stop, QTextCursor.MoveMode.KeepAnchor)
        return cursor

    def _dump(self) -> str:
        lines = []
        for start in range(0, len(self.data), BYTES_PER_LINE):
            chunk = self.data[start : start + BYTES_PER_LINE]
            line = [" "] * (self.text_column(BYTES_PER_LINE - 1) + 1)
            line[: self._prefix - 2] = f"{start:0{self._prefix - 2}x}"
            for index, byte in enumerate(chunk):
                column = self.hex_column(index)
                line[column : column + 2] = f"{byte:02x}"
                line[self.text_column(index)] = chr(byte) if 0x20 <= byte < 0x7F else "."
            lines.append("".join(line).rstrip())
        return "\n".join(lines)


class BytesPane(QTabWidget):
    """The frame's bytes, and a tab for each run of reassembled bytes.

    The tabs only show when there is more than one, as in Wireshark.
    """

    byte_clicked = Signal(object, int)
    """A byte clicked: the reassembled bytes it is in, or ``None`` for the
    frame's own, and its offset in them."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.setTabPosition(QTabWidget.TabPosition.South)
        self._sources: list[Source | None] = []

    def show_bytes(self, data: bytes, sources: list[Source]) -> None:
        """Show a packet's bytes and the reassembled bytes its tree points into."""
        self.clear()
        self._sources = [None, *sources]
        self._add(data, f"Frame ({len(data)} bytes)", None)
        for source in sources:
            self._add(source.data, f"{source.name} ({len(source.data)} bytes)", source)
        self.tabBar().setVisible(len(self._sources) > 1)

    def views(self) -> list[HexView]:
        found = [self.widget(tab) for tab in range(self.count())]
        return [view for view in found if isinstance(view, HexView)]

    def show_field(self, node: Node | None) -> None:
        """Light up the bytes a field came from, in whichever tab holds them."""
        for view in self.views():
            view.clear_highlight()
        if node is None or not node.length:
            return
        for tab, source in enumerate(self._sources):
            if source is node.source:
                self.setCurrentIndex(tab)
                view = self.views()[tab]
                view.highlight(node.offset, node.length)
                return

    @override
    def clear(self) -> None:
        while self.count():
            widget = self.widget(0)
            self.removeTab(0)
            if widget is not None:
                widget.deleteLater()
        self._sources = []

    def _add(self, data: bytes, title: str, source: Source | None) -> None:
        view = HexView(data)
        view.byte_clicked.connect(lambda offset: self.byte_clicked.emit(source, offset))
        self.addTab(view, title)
