"""Multi-STA concurrency scenario fixtures."""

import pytest


@pytest.fixture
async def ap_multi_sta(ap):
    await ap.set_radio(36, "11ax", 80)
    await ap.set_ssid("multi-test")
    yield ap
    await ap.factory_reset()
