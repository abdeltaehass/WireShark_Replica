"""Capture filters: the BPF programs the kernel runs over every packet.

A filter is written as text, such as ``udp port 53``, and compiled to a short
BPF program by libpcap's parser, in :mod:`pilotfish.core.capture.libpcap`.
This package is what that program is made of: :mod:`program` holds the
instructions and prints them the way ``tcpdump -d`` does, and :mod:`machine`
runs them, which is how a filter written for the kernel can also be applied
to packets read from a file.

A capture filter decides what is captured at all. Display filters, which pick
from packets already captured, are a separate thing and come later.
"""

from pilotfish.core.filters.errors import FilterError
from pilotfish.core.filters.program import Instruction, Program

__all__ = ["FilterError", "Instruction", "Program"]
