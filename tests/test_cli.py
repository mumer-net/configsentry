import json
from pathlib import Path

from configsentry.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def audit(tmp_path, *files, fail_on="high"):
    return main(
        [
            "audit",
            "--file",
            *map(str, files),
            "--fail-on",
            fail_on,
            "--reports",
            str(tmp_path / "reports"),
            "--db",
            str(tmp_path / "cs.db"),
            "--no-alerts",
            "--baselines",
            str(tmp_path / "baselines"),
        ]
    )


def test_clean_config_exits_zero_and_writes_reports(tmp_path):
    assert audit(tmp_path, FIXTURES / "golden.cfg") == 0
    report = json.loads((tmp_path / "reports" / "latest.json").read_text())
    assert report[0]["device"] == "golden"
    assert all(r["passed"] for r in report[0]["results"])
    assert "ConfigSentry compliance report" in (tmp_path / "reports" / "latest.html").read_text()


def test_high_severity_failure_trips_the_gate(tmp_path):
    bad = tmp_path / "bad.cfg"
    bad.write_text((FIXTURES / "golden.cfg").read_text().replace("ip ssh version 2\n", ""))
    assert audit(tmp_path, bad) == 2
    assert audit(tmp_path, bad, fail_on="none") == 0


def test_selftest_passes_on_the_committed_corpus(capsys):
    assert main(["selftest", "--golden", str(FIXTURES / "golden.cfg"), "--faults", str(FIXTURES / "faults.yaml")]) == 0
    assert "false positives" in capsys.readouterr().out


def test_drift_is_reported_against_a_saved_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIGSENTRY_FINGERPRINT_KEY", "test-key")
    golden = FIXTURES / "golden.cfg"
    assert main(["baseline", "--file", str(golden), "--baselines", str(tmp_path / "baselines")]) == 0
    changed = tmp_path / "golden.cfg"
    changed.write_text(golden.read_text().replace("logging host 192.0.2.50", "logging host 203.0.113.9"))
    audit(tmp_path, changed, fail_on="none")
    report = json.loads((tmp_path / "reports" / "latest.json").read_text())
    assert report[0]["drift"]["added"] == ["logging host 203.0.113.9"]
