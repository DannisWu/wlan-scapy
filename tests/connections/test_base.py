"""Tests for connection base types."""
from src.connections.base import SSHResult, SerialMode


class TestSerialMode:
    def test_modes(self):
        assert SerialMode.LOCAL.value == "local"
        assert SerialMode.COMHUB.value == "comhub"
