"""Connection pool managing all remote device connections."""

from src.connections.base import SerialMode
from src.connections.ssh import SSHConnection
from src.connections.telnet import TelnetConnection
from src.connections.serial import SerialConnection
from src.utils.config import TopologyConfig


class ConnectionPool:
    def __init__(self, config: TopologyConfig):
        self.config = config
        self._ssh: dict[str, SSHConnection] = {}
        self._telnet: TelnetConnection | None = None
        self._serial: SerialConnection | None = None

    async def connect_all(self) -> None:
        if self._ssh:
            raise RuntimeError("Connections already established")

        try:
            # SSH to Wired PC
            wired = SSHConnection(
                self.config.wired_pc.host,
                self.config.wired_pc.ssh_port,
                self.config.wired_pc.user,
                self.config.wired_pc.password,
            )
            await wired.connect()
            self._ssh["wired_pc"] = wired

            # SSH to WLAN STA
            sta = SSHConnection(
                self.config.sta.host,
                self.config.sta.ssh_port,
                self.config.sta.user,
                self.config.sta.password,
            )
            await sta.connect()
            self._ssh["sta"] = sta

            # Telnet to DUT AP
            self._telnet = TelnetConnection(
                self.config.ap.telnet.host,
                self.config.ap.telnet.port,
            )
            await self._telnet.connect()

            # Serial to DUT AP (optional)
            if self.config.ap.serial.enable:
                self._serial = SerialConnection()
                mode = SerialMode.LOCAL if self.config.ap.serial.mode == "local" else SerialMode.COMHUB
                if mode == SerialMode.LOCAL:
                    await self._serial.open(
                        mode,
                        port=self.config.ap.serial.port,
                        baudrate=self.config.ap.serial.baudrate,
                    )
                else:
                    await self._serial.open(
                        mode,
                        host=self.config.ap.serial.host,
                        port=self.config.ap.serial.com_port,
                    )
        except Exception:
            await self.disconnect_all()
            raise

    async def disconnect_all(self) -> None:
        for conn in self._ssh.values():
            await conn.disconnect()
        if self._telnet:
            await self._telnet.disconnect()
        if self._serial:
            await self._serial.close()

    @property
    def ssh(self) -> dict[str, SSHConnection]:
        return dict(self._ssh)

    @property
    def telnet(self) -> TelnetConnection:
        if not self._telnet:
            raise RuntimeError("Telnet not connected")
        return self._telnet

    @property
    def serial(self) -> SerialConnection | None:
        return self._serial
