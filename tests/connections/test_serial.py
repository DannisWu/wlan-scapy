"""Tests for SerialConnection."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.connections.serial import SerialConnection, SerialMode


class TestSerialConnectionErrors:
    @pytest.mark.asyncio
    async def test_check_errors_no_buffer(self):
        conn = SerialConnection()
        errors = await conn.check_errors()
        assert errors == []

    @pytest.mark.asyncio
    async def test_check_errors_no_match(self):
        conn = SerialConnection()
        conn._buffer = ["normal line", "another normal line"]
        errors = await conn.check_errors()
        assert errors == []

    @pytest.mark.asyncio
    async def test_check_errors_match_oops(self):
        conn = SerialConnection()
        conn._buffer = ["some oops happened", "normal line"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "some oops happened" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_panic(self):
        conn = SerialConnection()
        conn._buffer = ["kernel panic: not syncing"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "kernel panic: not syncing" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_bug(self):
        conn = SerialConnection()
        conn._buffer = ["BUG: unable to handle"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "BUG: unable to handle" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_call_trace(self):
        conn = SerialConnection()
        conn._buffer = ["Call Trace:"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "Call Trace:" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_warning(self):
        conn = SerialConnection()
        conn._buffer = ["WARNING: at kernel/sched"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "WARNING: at kernel/sched" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_error(self):
        conn = SerialConnection()
        conn._buffer = ["ERROR: something broke"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "ERROR: something broke" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_firmware_error(self):
        conn = SerialConnection()
        conn._buffer = ["Firmware error detected"]
        errors = await conn.check_errors()
        assert len(errors) == 1
        assert "Firmware error detected" in errors[0]

    @pytest.mark.asyncio
    async def test_check_errors_match_iwlwifi_regex(self):
        conn = SerialConnection()
        conn._buffer = ["iwlwifi: Microcode SW error"]
        errors = await conn.check_errors()
        assert len(errors) == 1

    @pytest.mark.asyncio
    async def test_check_errors_match_unable_to_handle(self):
        conn = SerialConnection()
        conn._buffer = ["Unable to handle kernel NULL pointer"]
        errors = await conn.check_errors()
        assert len(errors) == 1

    @pytest.mark.asyncio
    async def test_check_errors_multiple_matches(self):
        conn = SerialConnection()
        conn._buffer = [
            "normal line",
            "kernel panic: not syncing",
            "another normal",
            "Call Trace:",
            "ERROR: wlan0 failed",
        ]
        errors = await conn.check_errors()
        assert len(errors) == 3

    @pytest.mark.asyncio
    async def test_check_errors_with_custom_patterns(self):
        conn = SerialConnection()
        conn._buffer = ["custom error happened"]
        errors = await conn.check_errors(patterns=["custom"])
        assert len(errors) == 1

    @pytest.mark.asyncio
    async def test_check_errors_with_empty_custom_patterns(self):
        conn = SerialConnection()
        conn._buffer = ["oops something"]
        # Passing an empty list is falsy, so defaults are used
        errors = await conn.check_errors(patterns=[])
        assert len(errors) == 1

    @pytest.mark.asyncio
    async def test_check_errors_ignores_non_error_lines(self):
        conn = SerialConnection()
        conn._buffer = ["info: link is up", "notice: interface ready"]
        errors = await conn.check_errors()
        assert errors == []


class TestSerialConnectionDefaultPatterns:
    def test_default_patterns_contains_oops(self):
        assert "oops" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_panic(self):
        assert "panic" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_bug(self):
        assert "BUG:" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_call_trace(self):
        assert "Call Trace" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_warning(self):
        assert "WARNING:" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_error(self):
        assert "ERROR:" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_firmware_error(self):
        assert "Firmware error" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_iwlwifi_regex(self):
        pats = SerialConnection.DEFAULT_ERROR_PATTERNS
        has_iwl_regex = any("iwlw" in p for p in pats)
        assert has_iwl_regex

    def test_default_patterns_contains_kernel_panic(self):
        assert "Kernel panic" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_contains_unable_to_handle(self):
        assert "Unable to handle" in SerialConnection.DEFAULT_ERROR_PATTERNS

    def test_default_patterns_count(self):
        assert len(SerialConnection.DEFAULT_ERROR_PATTERNS) == 11


class TestSerialConnectionInit:
    def test_default_state(self):
        conn = SerialConnection()
        assert conn._reader is None
        assert conn._active is False
        assert conn._buffer == []
        assert conn._mode is None
        assert conn._drain_task is None
        assert conn._log_file is None


class TestSerialConnectionOpenLocal:
    @pytest.mark.asyncio
    async def test_open_local_creates_serial(self):
        with patch("serial.Serial") as mock_serial_cls:
            conn = SerialConnection()
            await conn.open(SerialMode.LOCAL, port="/dev/ttyUSB0", baudrate=115200)
            mock_serial_cls.assert_called_once_with(
                "/dev/ttyUSB0", 115200, timeout=0.1
            )
            assert conn._reader is mock_serial_cls.return_value

    @pytest.mark.asyncio
    async def test_open_local_default_baudrate(self):
        with patch("serial.Serial") as mock_serial_cls:
            conn = SerialConnection()
            await conn.open(SerialMode.LOCAL, port="/dev/ttyUSB0")
            mock_serial_cls.assert_called_once_with(
                "/dev/ttyUSB0", 115200, timeout=0.1
            )


class TestSerialConnectionClose:
    @pytest.mark.asyncio
    async def test_close_local_closes_reader(self):
        with patch("serial.Serial") as mock_serial_cls:
            conn = SerialConnection()
            await conn.open(SerialMode.LOCAL, port="/dev/ttyUSB0")
            mock_instance = mock_serial_cls.return_value
            await conn.close()
            mock_instance.close.assert_called_once()
            assert conn._reader is None

    @pytest.mark.asyncio
    async def test_close_without_open_does_not_raise(self):
        conn = SerialConnection()
        await conn.close()


class TestSerialConnectionReadLineLocal:
    @pytest.mark.asyncio
    async def test_read_line_local_with_data(self):
        conn = SerialConnection()
        conn._mode = SerialMode.LOCAL
        conn._reader = MagicMock()
        conn._reader.in_waiting = 10
        conn._reader.readline.return_value = b"test line\n"

        loop_mock = MagicMock()
        loop_mock.run_in_executor = AsyncMock(
            side_effect=lambda executor, func: func(),
        )

        with patch("asyncio.get_event_loop", return_value=loop_mock):
            result = await conn._read_line()

        assert result == "test line\n"
        conn._reader.readline.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_line_local_no_data(self):
        conn = SerialConnection()
        conn._mode = SerialMode.LOCAL
        conn._reader = MagicMock()
        conn._reader.in_waiting = 0

        result = await conn._read_line()
        assert result is None
        conn._reader.readline.assert_not_called()
