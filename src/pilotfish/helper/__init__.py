"""The capture helper: a separate process that captures and writes pcapng.

Wireshark never captures in its own window's process. It runs a helper,
dumpcap, which opens the interface and writes what it captures as pcapng,
while the window reads that and decodes it. pilotfish does the same, with
``python -m pilotfish.helper``. Keeping capture in a process of its own
means the two never wait on each other: in Python, decoding in the window
would otherwise hold the GIL that the capture thread needs to keep up.

The helper writes the capture to standard output, and reports on standard
error, one JSON object a line, so the window can tell what happened::

    {"event": "started", "interface": "en0", "link_type": 1}
    {"event": "stats", "captured": 120, "dropped": 0, ...}
    {"event": "error", "kind": "permission", "message": "..."}
    {"event": "stopped", "captured": 4031, "dropped": 0, ...}

It captures until it is sent SIGTERM or SIGINT, or until whatever reads its
output goes away.
"""
