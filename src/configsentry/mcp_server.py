"""A read-only MCP server over audit history. A client can ask about audits but can't touch a device.

- This module never imports the SSH layer (collect.py), so no tool call can reach a device.
  tests/test_mcp.py checks that Netmiko isn't even loaded.
- Saved configs are read from one folder only, and paths that escape it are refused.
- Bad input raises ToolError, so the client gets the reason instead of a stack trace.
- History comes from SQLite, and configs saved by `audit` are already redacted.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from configsentry import store
from configsentry.engine import audit_text
from configsentry.rules import RULES

server = MCPServer(
    "configsentry",
    instructions="Read-only compliance data for Cisco IOS-XE and Meraki networks. No tool changes a device.",
)


def _db():
    return store.connect(Path(os.environ.get("CONFIGSENTRY_DB", "configsentry.db")))


def _config_dir() -> Path:
    return Path(os.environ.get("CONFIGSENTRY_CONFIG_DIR", "configs")).resolve()


@server.tool()
def list_devices() -> list[dict]:
    """Every audited device with its latest score, source, and audit time."""
    return store.devices(_db())


@server.tool()
def latest_findings(device: str) -> dict:
    """Failing rules for a device's most recent audit, with evidence, the fix, and how long each has failed."""
    db = _db()
    audit = store.latest(db, device)
    if audit is None:
        raise ToolError(f"no audits recorded for {device!r}")
    fixes = {r.id: r.fix for r in RULES}
    failing = [
        {**f, "fix": fixes.get(f["rule"], ""), "failing_since": store.failing_since(db, device, f["rule"])}
        for f in audit["findings"]
        if not f["passed"]
    ]
    return {"device": device, "audited_at": audit["started_at"], "passed": audit["passed"], "failing": failing}


@server.tool()
def explain_rule(rule_id: str) -> dict:
    """What a ConfigSentry rule checks, its severity, its CIS benchmark reference, and the fix."""
    for r in RULES:
        if r.id == rule_id.upper():
            return {"rule": r.id, "title": r.title, "severity": r.severity, "cis": r.cis, "fix": r.fix}
    raise ToolError(f"unknown rule {rule_id!r}; rules are CS-01 to CS-{len(RULES):02d}")


@server.tool()
def audit_saved_config(filename: str) -> dict:
    """Audit a saved config file from the configs folder. Never connects to a device."""
    root = _config_dir()
    path = (root / filename).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ToolError("filename must name a file inside the configs folder")
    result = audit_text(path.read_text(), path.stem)
    return {
        "device": result.device,
        "passed": result.passed_count,
        "failing": [{"rule": r.rule, "title": r.title, "problems": r.problems, "fix": r.fix} for r in result.failed],
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
