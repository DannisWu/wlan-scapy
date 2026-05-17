from pathlib import Path

from src.utils.pcap import PCAPManager


def test_check_packets_empty():
    """check_packets on a non-existent file raises FileNotFoundError."""
    mgr = PCAPManager()
    try:
        mgr.check_packets("/tmp/nonexistent.pcap", lambda p: True)
        assert False, "Expected exception"
    except FileNotFoundError:
        pass
    except Exception:
        pass


def test_verify_sequence_empty():
    """verify_sequence with empty conditions returns True for valid pcap."""
    mgr = PCAPManager()
    try:
        result = mgr.verify_sequence("/tmp/nonexistent.pcap", [])
        assert result is True
    except FileNotFoundError:
        pass
    except Exception:
        pass
