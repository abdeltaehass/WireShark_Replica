"""Filter fields that check what is typed as it is typed, as Wireshark's do.

The field turns green while what it holds compiles and red when it doesn't,
with the reason in its tooltip and in the status bar, so a filter is known
to be right before it is applied. The display filter bar compiles with the
display filter compiler, and the capture filter field with libpcap's.
"""

from collections.abc import Callable
from enum import StrEnum

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget

from pilotfish.core.capture import MAX_SNAPLEN, compile_filter
from pilotfish.core.display import DisplayFilter, DisplayFilterError, compile_display_filter
from pilotfish.core.filters import FilterError

# Wireshark's colours for a filter that compiles and one that doesn't. They
# are pale, so the text on them is always dark, in dark mode too.
VALID_COLOUR = "#afffaf"
INVALID_COLOUR = "#ffafaf"

type Check = Callable[[str], str | None]
"""What is wrong with a filter, or ``None`` if nothing is."""


class Validity(StrEnum):
    EMPTY = "empty"
    VALID = "valid"
    INVALID = "invalid"


class FilterEdit(QLineEdit):
    """A line edit that says whether its filter compiles, as it is typed."""

    checked = Signal(str)
    """What is wrong with the filter, or an empty string if nothing is."""

    def __init__(self, check: Check, placeholder: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._check = check
        self.validity = Validity.EMPTY
        self.problem = ""
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self.textChanged.connect(self._recheck)

    def _recheck(self, text: str) -> None:
        if not text.strip():
            self.validity, self.problem = Validity.EMPTY, ""
            self.setStyleSheet("")
        else:
            problem = self._check(text)
            self.validity = Validity.INVALID if problem else Validity.VALID
            self.problem = problem or ""
            colour = INVALID_COLOUR if problem else VALID_COLOUR
            self.setStyleSheet(f"QLineEdit {{ background: {colour}; color: black; }}")
        self.setToolTip(self.problem)
        self.checked.emit(self.problem)


def display_filter_problem(text: str) -> str | None:
    try:
        compile_display_filter(text)
    except DisplayFilterError as error:
        return error.message
    return None


DLT_EN10MB = 1


def capture_filter_problem(text: str, dlt: int = DLT_EN10MB) -> str | None:
    """Checked against Ethernet unless told otherwise, since the interface,
    and so its link type, may not have been chosen yet. The helper compiles
    it again for the interface it opens, and says if it doesn't fit."""
    try:
        compile_filter(text, dlt, MAX_SNAPLEN)
    except FilterError as error:
        return str(error)
    return None


class DisplayFilterBar(QWidget):
    """The display filter above the packet list. Return or Apply applies it."""

    applied = Signal(object)
    """The :class:`DisplayFilter` to apply, or ``None`` to show every packet."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.edit = FilterEdit(display_filter_problem, "Apply a display filter … ⌘/")
        self.button = QPushButton("Apply")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 2)
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.button)
        self.edit.returnPressed.connect(self.apply)
        self.button.clicked.connect(self.apply)
        self.active: DisplayFilter | None = None
        """The filter applied last."""

    def apply(self) -> bool:
        """Apply the filter typed, unless it doesn't compile."""
        text = self.edit.text().strip()
        if not text:
            self.active = None
            self.applied.emit(None)
            return True
        try:
            display = compile_display_filter(text)
        except DisplayFilterError:
            return False
        self.active = display
        self.applied.emit(display)
        return True
