from src.cli.parser import CLIParser


def test_parse_table():
    text = "00:11:22:33:44:55 1 -45 associated\n00:11:22:33:44:66 2 -50 associated"
    result = CLIParser.parse_table(text, ["mac", "aid", "rssi", "state"])
    assert len(result) == 2
    assert result[0]["mac"] == "00:11:22:33:44:55"


def test_extract_value():
    assert CLIParser.extract_value("channel=36 bw=80", "channel") == "36"


def test_wait_for_pattern():
    assert CLIParser.wait_for_pattern("Error: timeout", r"Error")
    assert not CLIParser.wait_for_pattern("OK", r"Error")
