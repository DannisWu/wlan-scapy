"""STA association scenario fixtures."""

import pytest


@pytest.fixture
def ap_profile_11ax():
    return {"channel": 36, "mode": "11ax", "bandwidth": 80, "ssid": "test-ax"}


@pytest.fixture
def ap_profile_11ac():
    return {"channel": 36, "mode": "11ac", "bandwidth": 80, "ssid": "test-ac"}


@pytest.fixture
def ap_profile_11n():
    return {"channel": 6, "mode": "11n", "bandwidth": 40, "ssid": "test-n"}


@pytest.fixture
async def ap_configured(ap, ap_profile_11ax):
    await ap.set_radio(
        ap_profile_11ax["channel"],
        ap_profile_11ax["mode"],
        ap_profile_11ax["bandwidth"],
    )
    await ap.set_ssid(ap_profile_11ax["ssid"])
    yield ap
    await ap.factory_reset()
