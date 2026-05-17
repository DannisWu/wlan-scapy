from scapy.all import RadioTap, Dot11Auth, Dot11AssoReq

from src.wlan.frames import build_auth_frame, build_assoc_req_frame, build_deauth_frame


def test_build_auth_frame():
    frame = build_auth_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff",
                             "aa:bb:cc:dd:ee:ff")
    assert len(frame) > 0
    pkt = RadioTap(frame)
    assert pkt[Dot11Auth].algo == 0
    assert pkt[Dot11Auth].seqnum == 1


def test_build_assoc_req_frame():
    frame = build_assoc_req_frame(
        "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff", "TestNet",
    )
    assert len(frame) > 0
    pkt = RadioTap(frame)
    assert b"TestNet" in bytes(pkt)


def test_build_deauth_frame():
    frame = build_deauth_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55",
                               "aa:bb:cc:dd:ee:ff")
    assert len(frame) > 0
