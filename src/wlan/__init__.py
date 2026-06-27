"""WLAN frame construction — 802.11 management frames and IEs.

Submodules:
- frames: frame builders (Auth, Assoc, Deauth, Disassoc, ProbeReq, ReassocReq, NullData)
- ie: Information Element dataclass and builder functions
- rates: PHY rate sets (b/g/a) and IE helpers
- anomalies: abnormal protocol interaction sequences
"""

from src.wlan.frames import (
    build_auth_frame,
    build_assoc_req_frame,
    build_deauth_frame,
    build_disassoc_frame,
    build_null_data_frame,
    build_probe_req_frame,
    build_reassoc_req_frame,
    # convenience wrappers (PHY-aware)
    build_probe_req,
    build_auth_req,
    build_assoc_req,
    build_reassoc_req,
    build_deauth,
    build_disassoc,
)

from src.wlan.ie import IE, rsn_ie, ssid_ie, supported_rates_ie

from src.wlan.rates import RATE_SETS, DEFAULT_PHY, PHY_BAND

__all__ = [
    "build_auth_frame", "build_assoc_req_frame", "build_deauth_frame",
    "build_disassoc_frame", "build_null_data_frame", "build_probe_req_frame",
    "build_reassoc_req_frame",
    "build_probe_req", "build_auth_req", "build_assoc_req",
    "build_reassoc_req", "build_deauth", "build_disassoc",
    "IE", "rsn_ie", "ssid_ie", "supported_rates_ie",
    "RATE_SETS", "DEFAULT_PHY", "PHY_BAND",
]
