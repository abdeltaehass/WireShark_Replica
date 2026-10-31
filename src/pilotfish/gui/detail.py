"""The protocol tree of the packet selected in the list.

Every row is a node of the packet's :class:`ProtocolTree`, worded as the
command line's ``-V`` words it. Each node knows the bytes it was read from,
which is all it takes to tie the tree to the bytes pane both ways: selecting
a field lights up its bytes, and clicking a byte selects the smallest field
that holds it.

Subtrees opened on one packet stay open on the next, by field name, so
looking at the same field across packets doesn't mean opening it every time.
"""

from typing import override

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QAbstractItemView, QTreeWidget, QTreeWidgetItem, QWidget

from pilotfish.core.dissect import Node, ProtocolTree, Source
from pilotfish.core.dissect.text import node_text

_NODE = Qt.ItemDataRole.UserRole


class ProtocolTreeView(QTreeWidget):
    """One packet's layers, each with its fields under it."""

    field_selected = Signal(object)
    """The :class:`Node` selected, or ``None`` when nothing with bytes is."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._items: list[tuple[Node, QTreeWidgetItem]] = []
        self._open: set[str] = set()
        self.currentItemChanged.connect(self._changed)
        self.itemExpanded.connect(lambda item: self._remember(item, True))
        self.itemCollapsed.connect(lambda item: self._remember(item, False))

    def show_tree(self, tree: ProtocolTree) -> None:
        self.clear()
        for layer in tree.layers:
            self.addTopLevelItem(self._item(layer))
        if tree.error is not None:
            self.addTopLevelItem(QTreeWidgetItem([f"[Malformed packet: {tree.error}]"]))
        # Opened only once they are in the tree, which is when Qt allows it.
        for node, item in self._items:
            if node.name in self._open and item.childCount():
                item.setExpanded(True)

    def show_waiting(self, message: str) -> None:
        """Say why there is no tree yet."""
        self.clear()
        self.addTopLevelItem(QTreeWidgetItem([message]))

    @override
    def clear(self) -> None:
        self._items = []
        super().clear()

    def node_of(self, item: QTreeWidgetItem | None) -> Node | None:
        if item is None:
            return None
        node = item.data(0, _NODE)
        return node if isinstance(node, Node) else None

    def item_for(self, name: str) -> QTreeWidgetItem | None:
        """The first row for a field name, such as ``ip.src``."""
        return next((item for node, item in self._items if node.name == name), None)

    def select_byte(self, source: Source | None, offset: int) -> None:
        """Select the smallest field that holds a byte, opening what's around it.

        ``source`` is the reassembled bytes the offset counts into, or
        ``None`` for the frame's own. Among fields of the same size, the
        outermost wins, so a byte of flags selects the flags rather than
        whichever bit happens to come first.
        """
        best: tuple[Node, QTreeWidgetItem] | None = None
        for node, item in self._items:
            if (
                node.source is source
                and node.length
                and node.offset <= offset < node.offset + node.length
                and (best is None or node.length < best[0].length)
            ):
                best = node, item
        if best is None:
            return
        item = best[1]
        parent = item.parent()
        while parent is not None:
            parent.setExpanded(True)
            parent = parent.parent()
        self.setCurrentItem(item)
        self.scrollToItem(item)

    def _item(self, node: Node) -> QTreeWidgetItem:
        item = QTreeWidgetItem([node_text(node)])
        item.setData(0, _NODE, node)
        self._items.append((node, item))
        for child in node.children:
            item.addChild(self._item(child))
        return item

    def _changed(self, current: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None) -> None:
        self.field_selected.emit(self.node_of(current))

    def _remember(self, item: QTreeWidgetItem, opened: bool) -> None:
        node = self.node_of(item)
        if node is not None:
            if opened:
                self._open.add(node.name)
            else:
                self._open.discard(node.name)
