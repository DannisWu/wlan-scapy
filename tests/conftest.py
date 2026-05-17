"""Top-level pytest fixtures — connection pool, device instances."""

from datetime import datetime
from pathlib import Path

import pytest

from src.utils.config import load_config
from src.connections.pool import ConnectionPool
from src.transport.radio import RadioTransport
from src.devices.ap import APController
from src.devices.sta import StaInjector
from src.devices.wired_pc import TrafficGenerator
from src.devices.sniffer import SnifferDevice


@pytest.fixture(scope="session")
def config():
    return load_config("config/topology.yaml")


@pytest.fixture(scope="session")
async def conn_pool(config):
    pool = ConnectionPool(config)
    await pool.connect_all()
    yield pool
    await pool.disconnect_all()


@pytest.fixture(scope="function")
def test_log_dir(request):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    d = Path("reports") / f"{request.node.name}_{timestamp}"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="function")
async def ap(conn_pool, test_log_dir):
    ap_ctrl = APController(conn_pool.telnet, conn_pool.serial)
    await ap_ctrl.clear_logs()
    dmesg_before = await ap_ctrl.get_dmesg()
    await ap_ctrl.start_monitoring(test_log_dir)
    yield ap_ctrl
    _, serial_errors = await ap_ctrl.stop_monitoring()
    dmesg_after = await ap_ctrl.get_dmesg()
    dmesg_errors = await ap_ctrl.check_dmesg(dmesg_before, dmesg_after)
    (test_log_dir / "dmesg_before.txt").write_text(dmesg_before)
    (test_log_dir / "dmesg_after.txt").write_text(dmesg_after)
    assert not serial_errors, f"AP serial errors: {serial_errors}"
    assert not dmesg_errors, f"AP dmesg errors: {dmesg_errors}"


@pytest.fixture(scope="function")
async def sta(conn_pool, config):
    transport = RadioTransport(
        config.sta.transport.interface,
        conn_pool.ssh["sta"],
    )
    await transport.setup()
    sta_inj = StaInjector(transport, conn_pool.ssh["sta"])
    yield sta_inj
    await sta_inj.destroy_stas()
    await transport.teardown()


@pytest.fixture(scope="function")
async def wired_pc(conn_pool, config):
    tg = TrafficGenerator(
        conn_pool.ssh["wired_pc"],
        config.wired_pc.interface,
    )
    yield tg


@pytest.fixture(scope="function")
async def sniffer(conn_pool, config):
    if "sniffer" not in conn_pool.ssh:
        yield None
        return
    device = SnifferDevice(
        conn_pool.ssh["sniffer"],
        config.sniffer.interface,
    )
    yield device
    await device.teardown()
