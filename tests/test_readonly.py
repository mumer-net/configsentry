"""ConfigSentry must never change a device. These tests enforce that in code, not just in the README."""

import re
from pathlib import Path

import pytest

from configsentry.collect import _show

SRC = Path(__file__).resolve().parents[1] / "src" / "configsentry"
WRITE_CALLS = re.compile(r"send_config|config_mode|save_config|commit\(|write memory|copy run")


def test_no_code_path_enters_configuration_mode():
    offenders = [p.name for p in SRC.rglob("*.py") if WRITE_CALLS.search(p.read_text())]
    assert offenders == []


class FakeConnection:
    def __init__(self):
        self.sent = []

    def send_command(self, command, **kwargs):
        self.sent.append(command)
        return ""


def test_only_allowlisted_show_commands_can_be_sent():
    conn = FakeConnection()
    _show(conn, "show running-config")
    with pytest.raises(ValueError):
        _show(conn, "configure terminal")
    assert conn.sent == ["show running-config"]
