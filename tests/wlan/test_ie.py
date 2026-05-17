from src.wlan.ie import ssid_ie, oversized_ie, truncated_ie


def test_ssid_ie():
    ie = ssid_ie("MyWiFi")
    assert ie.id == 0
    assert ie.body == b"MyWiFi"
    packed = ie.pack()
    assert packed[0] == 0
    assert packed[1] == 6
    assert packed[2:] == b"MyWiFi"


def test_oversized_ie():
    ie = oversized_ie(1, 256, declared_length=5)
    assert ie.id == 1
    assert len(ie.body) == 256
    packed = ie.pack()
    assert packed[1] == 5  # declared length
    assert len(packed) == 2 + 256  # actual body


def test_truncated_ie():
    ie = truncated_ie(1, 3)
    assert len(ie.body) == 3
