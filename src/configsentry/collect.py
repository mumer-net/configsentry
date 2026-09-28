"""Pull the running config and version facts from IOS-XE devices over SSH.

Read-only: every command goes through _show(), which refuses anything that isn't
on the allowlist, and nothing in ConfigSentry enters configuration mode.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from netmiko import ConnectHandler

READ_ONLY_COMMANDS = ("show running-config", "show version")


@dataclass
class Device:
    name: str
    host: str
    port: int = 22
    device_type: str = "cisco_xe"
    username_env: str = "SANDBOX_USERNAME"
    password_env: str = "SANDBOX_PASSWORD"  # noqa: S105 (the name of an env var, not a password)


def load_inventory(path: Path) -> list[Device]:
    data = yaml.safe_load(path.read_text())
    return [Device(**item) for item in data["devices"]]


def _show(conn, command: str, structured: bool = False):
    if command not in READ_ONLY_COMMANDS:
        raise ValueError(f"{command!r} is not on the read-only allowlist")
    return conn.send_command(command, use_textfsm=structured, read_timeout=90)


def collect(device: Device) -> tuple[str, dict[str, str]]:
    """Return (running-config text, facts) for one device."""
    username, password = os.environ.get(device.username_env), os.environ.get(device.password_env)
    if not username or not password:
        raise RuntimeError(f"{device.name}: set {device.username_env} and {device.password_env} in .env")
    params = {
        "device_type": device.device_type,
        "host": device.host,
        "port": device.port,
        "username": username,
        "password": password,
        "conn_timeout": 20,
    }
    with ConnectHandler(**params) as conn:
        running = _show(conn, "show running-config")
        version = _show(conn, "show version", structured=True)
    facts: dict[str, str] = {}
    if isinstance(version, list) and version:  # TextFSM parsed it (ntc-templates)
        v = version[0]
        facts = {
            "hostname": v.get("hostname", ""),
            "version": v.get("version", ""),
            "model": (v.get("hardware") or [""])[0],
            "uptime": v.get("uptime", ""),
        }
    return running, facts
