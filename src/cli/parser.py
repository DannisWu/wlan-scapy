"""DUT AP CLI output parser."""

import re
from typing import Any


class CLIParser:
    @staticmethod
    def parse_table(text: str, columns: list[str]) -> list[dict[str, str]]:
        rows = [line.split() for line in text.strip().split("\n") if line.strip()]
        results = []
        for row in rows:
            if len(row) >= len(columns):
                results.append(dict(zip(columns, row)))
        return results

    @staticmethod
    def parse_sta_list(text: str) -> list[dict[str, str]]:
        return CLIParser.parse_table(text, ["mac", "aid", "rssi", "state"])

    @staticmethod
    def extract_value(text: str, key: str) -> str | None:
        m = re.search(rf"{key}[:\s=]+(\S+)", text)
        return m.group(1) if m else None

    @staticmethod
    def wait_for_pattern(text: str, pattern: str) -> bool:
        return bool(re.search(pattern, text))

    @staticmethod
    def parse_stats(text: str, counter_type: str) -> dict[str, int]:
        result: dict[str, int] = {}
        for line in text.strip().split("\n"):
            m = re.match(r"(\S+)\s*[:=]\s*(\d+)", line.strip())
            if m:
                result[m.group(1)] = int(m.group(2))
        return result
