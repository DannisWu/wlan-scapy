"""Multi-STA concurrency test -- 32 STAs simultaneous association."""

import asyncio

import pytest

from src.devices.sta import SecurityParams


@pytest.mark.scenario("multi_sta")
async def test_32sta_associate(ap_multi_sta, sta, test_log_dir):
    STACOUNT = 32
    stas = await sta.create_stas(STACOUNT, base_mac="00:11:22:33:00:00")
    pcap_path = test_log_dir / "air.pcap"
    await sta.start_capture(pcap_path)

    tasks = []
    for s in stas:
        tasks.append(
            sta.associate(
                s, "ff:ff:ff:ff:ff:ff", "multi-test",
                SecurityParams(auth="WPA2", psk="test1234"),
            )
        )
    results = await asyncio.gather(*tasks, return_exceptions=True)

    await sta.stop_capture()

    success = sum(
        1 for r in results
        if not isinstance(r, Exception) and r.status == 0
    )
    assert success >= STACOUNT * 0.9, (
        f"Expected >= {STACOUNT * 0.9} successful associations, "
        f"got {success}"
    )
