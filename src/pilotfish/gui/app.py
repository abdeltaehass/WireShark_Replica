"""Starting the desktop app: ``pilotfish-gui [FILE]``."""

import argparse
import sys
from collections.abc import Sequence

from pilotfish import __version__

INSTALL_HINT = (
    "pilotfish-gui: the desktop app needs PySide6, which comes with the gui extra: "
    "uv sync --extra gui"
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pilotfish-gui", description="Open the pilotfish desktop app."
    )
    parser.add_argument("file", nargs="?", help="a pcap or pcapng file to open")
    parser.add_argument("--version", action="version", version=f"pilotfish {__version__}")
    arguments = parser.parse_args(argv)
    try:
        from PySide6.QtWidgets import QApplication

        from pilotfish.gui.window import APP_NAME, MainWindow
    except ImportError:
        print(INSTALL_HINT, file=sys.stderr)
        return 1
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName(APP_NAME)
    window = MainWindow()
    window.show()
    if arguments.file is not None:
        window.try_to_open(arguments.file)
    return app.exec()
