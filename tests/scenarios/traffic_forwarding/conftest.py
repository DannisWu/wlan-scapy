"""Traffic forwarding scenario fixtures."""

import pytest
from src.devices.sta import SecurityParams


@pytest.fixture
async def ap_with_sta(ap, sta):
    """AP configured with one associated STA ready for traffic tests."""
    await ap.set_radio(36, "11ax", 80)
    await ap.set_ssid("traffic-test")
    stas = await sta.create_stas(1)
    await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "traffic-test",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    yield ap, sta, stas[0]
    await sta.destroy_stas()
    await ap.factory_reset()
