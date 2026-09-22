"""Names for link-layer header types.

pcap and pcapng files both use the LINKTYPE values from the tcpdump.org
registry (https://www.tcpdump.org/linktypes.html). This table covers the
types pilotfish is likely to meet on macOS and in common sample captures.
"""

_NAMES: dict[int, str] = {
    0: "NULL",
    1: "ETHERNET",
    6: "IEEE802_5",
    9: "PPP",
    10: "FDDI",
    # Older BSD libpcap wrote its platform's DLT_RAW value into files instead
    # of LINKTYPE_RAW (101): 12 on most systems, 14 on OpenBSD.
    12: "RAW",
    14: "RAW",
    50: "PPP_HDLC",
    51: "PPP_ETHER",
    101: "RAW",
    104: "C_HDLC",
    105: "IEEE802_11",
    107: "FRELAY",
    108: "LOOP",
    113: "LINUX_SLL",
    117: "PFLOG",
    119: "IEEE802_11_PRISM",
    127: "IEEE802_11_RADIOTAP",
    144: "LINUX_IRDA",
    163: "IEEE802_11_AVS",
    187: "BLUETOOTH_HCI_H4",
    189: "USB_LINUX",
    192: "PPI",
    195: "IEEE802_15_4_WITHFCS",
    201: "BLUETOOTH_HCI_H4_WITH_PHDR",
    220: "USB_LINUX_MMAPPED",
    227: "CAN_SOCKETCAN",
    228: "IPV4",
    229: "IPV6",
    230: "IEEE802_15_4_NOFCS",
    231: "DBUS",
    239: "NFLOG",
    249: "USBPCAP",
    251: "BLUETOOTH_LE_LL",
    253: "NETLINK",
    254: "BLUETOOTH_LINUX_MONITOR",
    256: "BLUETOOTH_LE_LL_WITH_PHDR",
    258: "PKTAP",
    266: "USB_DARWIN",
    276: "LINUX_SLL2",
    283: "IEEE802_15_4_TAP",
}


def link_type_name(link_type: int) -> str:
    """The registry name without its ``LINKTYPE_`` prefix, such as ``ETHERNET``."""
    return _NAMES.get(link_type, f"LINKTYPE_{link_type}")
