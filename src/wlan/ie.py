"""802.11 Information Element builders — normal and malformed."""

from dataclasses import dataclass
import struct


@dataclass
class IE:
    id: int
    body: bytes
    declared_length: int | None = None  # None = use actual len

    def pack(self) -> bytes:
        length = self.declared_length if self.declared_length is not None else len(self.body)
        return struct.pack("!BB", self.id, length) + self.body


def ssid_ie(ssid: str) -> IE:
    return IE(id=0, body=ssid.encode("utf-8"))

def supported_rates_ie(rates: list[int]) -> IE:
    return IE(id=1, body=bytes(rates))

def ht_capabilities_ie(caps: bytes) -> IE:
    return IE(id=45, body=caps)

def vht_capabilities_ie(caps: bytes) -> IE:
    return IE(id=191, body=caps)

def he_capabilities_ie(caps: bytes) -> IE:
    return IE(id=255, body=b"\x35" + caps)  # 255 for HE per 802.11ax

def rsn_ie(auth_type: int = 2, pairwise: bytes = b"\x00\x0f\xac\x04",
           group: bytes = b"\x00\x0f\xac\x04", psk: bool = True) -> IE:
    body = struct.pack("<H", 1)  # version
    body += group  # group cipher suite (4 bytes)
    body += struct.pack("<H", 1) + pairwise  # pairwise count + suite
    body += struct.pack("<H", 1)  # akm count
    if psk:
        body += b"\x00\x0f\xac\x02"  # WPA2-PSK
    else:
        body += b"\x00\x0f\xac\x01"  # WPA2-Enterprise
    body += struct.pack("<H", 0)  # RSN capabilities
    return IE(id=48, body=body)


# --- Malformed IE builders ---

def oversized_ie(ie_id: int, size: int, declared_length: int = 0) -> IE:
    """IE with body larger than declared length."""
    return IE(id=ie_id, body=b"\x00" * size, declared_length=declared_length)

def truncated_ie(ie_id: int, actual_len: int) -> IE:
    """IE truncated to actual_len bytes."""
    body = b"\x01\x02\x03\x04" * 10
    return IE(id=ie_id, body=body[:actual_len])

def vendor_malformed_ie(oui: bytes = b"\x00\x11\x22",
                        data: bytes = b"\xff" * 32) -> IE:
    return IE(id=221, body=oui + data)
