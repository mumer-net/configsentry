import asyncio
import subprocess
import sys
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from configsentry import mcp_server, store
from configsentry.engine import audit_text

GOLDEN = (Path(__file__).parent / "fixtures" / "golden.cfg").read_text()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "c8k.cfg").write_text(GOLDEN.replace("ip ssh version 2\n", ""))
    (tmp_path / "secret.txt").write_text("outside the allowed folder")
    db = store.connect(tmp_path / "cs.db")
    store.save(db, audit_text(GOLDEN.replace("ip ssh version 2\n", ""), "c8k", "ssh"))
    monkeypatch.setenv("CONFIGSENTRY_DB", str(tmp_path / "cs.db"))
    monkeypatch.setenv("CONFIGSENTRY_CONFIG_DIR", str(configs))
    return tmp_path


def test_tools_are_listed():
    tools = asyncio.run(mcp_server.server.list_tools())
    assert {t.name for t in tools} == {"list_devices", "latest_findings", "explain_rule", "audit_saved_config"}


def test_tools_answer_from_history_and_saved_configs(workspace):
    assert mcp_server.list_devices()[0]["device"] == "c8k"
    findings = mcp_server.latest_findings("c8k")
    assert [f["rule"] for f in findings["failing"]] == ["CS-01"]
    assert mcp_server.explain_rule("cs-12")["fix"] == "ip ssh time-out 60"
    assert [f["rule"] for f in mcp_server.audit_saved_config("c8k.cfg")["failing"]] == ["CS-01"]


def test_paths_outside_the_configs_folder_are_refused(workspace):
    with pytest.raises(ToolError):
        mcp_server.audit_saved_config("../secret.txt")


def test_the_mcp_server_cannot_reach_devices():
    code = "import sys, configsentry.mcp_server; print('netmiko' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "False"
