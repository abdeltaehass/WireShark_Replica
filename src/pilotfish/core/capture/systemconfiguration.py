"""Interface names as System Settings shows them, such as "Wi-Fi" for en0.

The SystemConfiguration framework knows which hardware port each BSD
interface belongs to. Wireshark uses it for its interface list too.
"""

import ctypes
from ctypes import c_bool, c_char_p, c_long, c_uint32, c_void_p

_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_SYSTEM_CONFIGURATION = (
    "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"
)
_UTF8 = 0x08000100  # kCFStringEncodingUTF8
_NAME_BUFFER_SIZE = 256


def display_names() -> dict[str, str]:
    """Each known interface's display name, keyed by BSD name such as ``en0``.

    Empty where the frameworks can't be loaded, as on Linux.
    """
    try:
        cf = ctypes.CDLL(_CORE_FOUNDATION)
        sc = ctypes.CDLL(_SYSTEM_CONFIGURATION)
    except OSError:
        return {}
    # CFArrayRef SCNetworkInterfaceCopyAll(void);
    sc.SCNetworkInterfaceCopyAll.restype = c_void_p
    sc.SCNetworkInterfaceCopyAll.argtypes = []
    # CFStringRef SCNetworkInterfaceGetBSDName(SCNetworkInterfaceRef interface);
    # CFStringRef SCNetworkInterfaceGetLocalizedDisplayName(SCNetworkInterfaceRef interface);
    for getter in (sc.SCNetworkInterfaceGetBSDName, sc.SCNetworkInterfaceGetLocalizedDisplayName):
        getter.restype = c_void_p
        getter.argtypes = [c_void_p]
    # CFIndex CFArrayGetCount(CFArrayRef theArray);
    cf.CFArrayGetCount.restype = c_long
    cf.CFArrayGetCount.argtypes = [c_void_p]
    # const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
    cf.CFArrayGetValueAtIndex.restype = c_void_p
    cf.CFArrayGetValueAtIndex.argtypes = [c_void_p, c_long]
    # Boolean CFStringGetCString(CFStringRef theString, char *buffer,
    #                            CFIndex bufferSize, CFStringEncoding encoding);
    cf.CFStringGetCString.restype = c_bool
    cf.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
    # void CFRelease(CFTypeRef cf);
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [c_void_p]

    def string(ref: int | None) -> str | None:
        buffer = ctypes.create_string_buffer(_NAME_BUFFER_SIZE)
        if ref and cf.CFStringGetCString(ref, buffer, _NAME_BUFFER_SIZE, _UTF8):
            return buffer.value.decode()
        return None

    interfaces: int | None = sc.SCNetworkInterfaceCopyAll()
    if not interfaces:
        return {}
    # "Copy" functions hand over ownership and "Get" functions don't, so only
    # the array needs releasing.
    try:
        names: dict[str, str] = {}
        for index in range(cf.CFArrayGetCount(interfaces)):
            interface = cf.CFArrayGetValueAtIndex(interfaces, index)
            bsd_name = string(sc.SCNetworkInterfaceGetBSDName(interface))
            display_name = string(sc.SCNetworkInterfaceGetLocalizedDisplayName(interface))
            if bsd_name and display_name:
                names[bsd_name] = display_name
        return names
    finally:
        cf.CFRelease(interfaces)
