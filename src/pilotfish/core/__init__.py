"""Capture, decoding, display filters and capture file formats.

The command line tool and the desktop app share this package, so it must never
import from ``pilotfish.cli``, ``pilotfish.gui`` or a GUI toolkit, and it uses
only the standard library plus ``cryptography``. ``tests/test_architecture.py``
enforces both rules.
"""
