"""Connection layer base types."""

from dataclasses import dataclass, field
from enum import Enum


@dataclass
class SSHResult:
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class TelnetResult:
    output: str
    prompt: str = ""


class SerialMode(Enum):
    LOCAL = "local"
    COMHUB = "comhub"
