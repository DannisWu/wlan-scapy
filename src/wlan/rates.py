"""802.11 PHY rate sets — b/g/a Supported Rates and Extended Rates IEs.

Rate encoding: lower 7 bits = rate(Mbps) * 2, bit7 = BSS basic rate.

Scapy IE ID: 1=Supported Rates, 50=Extended Supported Rates (max 8 per IE).
"""

from typing import Dict, List, Optional, Tuple

from scapy.all import Dot11Elt

from src.wlan.ie import IE

# (supported_rates_bytes, extended_rates_bytes)
RATE_SETS: Dict[str, Tuple[bytes, bytes]] = {
    # 802.11b — 2.4GHz CCK only
    "b": (
        b"\x82\x84\x8b\x96",  # 1(B),2(B),5.5(B),11(B)
        b"",
    ),
    # 802.11g — 2.4GHz CCK + OFDM (12 rates, 8+4)
    "g": (
        b"\x82\x84\x8b\x96\x0c\x12\x18\x24",  # 1,2,5.5,11(B) + 6,9,12,18
        b"\x30\x48\x60\x6c",                   # 24,36,48,54 in Extended
    ),
    # 802.11a — 5GHz OFDM only
    "a": (
        b"\x8c\x12\x98\x24\xb0\x48\x60\x6c",  # 6(B),9,12(B),18,24(B),36,48,54
        b"",
    ),
}

# phy -> band description
PHY_BAND: Dict[str, str] = {
    "b": "2.4GHz (CCK)",
    "g": "2.4GHz (CCK+OFDM)",
    "a": "5GHz (OFDM)",
}

DEFAULT_PHY = "g"


def get_rate_ies(phy: str) -> Tuple[Dot11Elt, Optional[Dot11Elt]]:
    """Return Supported Rates and Extended Supported Rates Dot11Elt by PHY type.

    Args:
        phy: PHY type ("b", "g", "a")

    Returns:
        (supported_rates_ie, extended_rates_ie_or_None)
    """
    if phy not in RATE_SETS:
        raise ValueError(f"Unknown PHY type: {phy}, options: {list(RATE_SETS.keys())}")
    supp, ext = RATE_SETS[phy]
    supp_ie = Dot11Elt(ID="Rates", info=supp)
    ext_ie = Dot11Elt(ID=50, info=ext) if ext else None
    return supp_ie, ext_ie


def build_rate_ies_layers(phy: str) -> List[Dot11Elt]:
    """Return rate IE layers ready for ``/`` stacking.

    Args:
        phy: PHY type ("b", "g", "a")
    """
    supp, ext = get_rate_ies(phy)
    layers = [supp]
    if ext is not None:
        layers.append(ext)
    return layers


def get_rate_ies_as_ie(phy: str) -> Tuple[IE, Optional[IE]]:
    """Return Supported Rates and Extended Supported Rates as IE dataclasses.

    Args:
        phy: PHY type ("b", "g", "a")

    Returns:
        (supported_rates_ie, extended_rates_ie_or_None)
    """
    if phy not in RATE_SETS:
        raise ValueError(f"Unknown PHY type: {phy}, options: {list(RATE_SETS.keys())}")
    supp_bytes, ext_bytes = RATE_SETS[phy]
    supp_ie = IE(id=1, body=supp_bytes)
    ext_ie = IE(id=50, body=ext_bytes) if ext_bytes else None
    return supp_ie, ext_ie


def common_ies(ssid: str, phy: str = DEFAULT_PHY) -> List[Dot11Elt]:
    """Build basic IE set for request frames: SSID + Supported Rates [+ Extended].

    Args:
        ssid: SSID string, empty for broadcast probe
        phy: PHY type ("b", "g", "a")
    """
    layers = [Dot11Elt(ID="SSID", info=ssid.encode("utf-8"))]
    layers.extend(build_rate_ies_layers(phy))
    return layers


def _stack_ies(pkt, ies: List[Dot11Elt]):
    """Stack IE layers onto a packet using ``/``."""
    result = pkt
    for ie in ies:
        result = result / ie
    return result
