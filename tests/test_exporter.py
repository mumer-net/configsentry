from pathlib import Path

from prometheus_client import generate_latest

from configsentry import exporter
from configsentry.engine import audit_text

GOLDEN = (Path(__file__).parent / "fixtures" / "golden.cfg").read_text()


def test_metrics_reflect_the_latest_audit():
    exporter.update(audit_text(GOLDEN.replace("ip ssh version 2\n", ""), "c8k"))
    text = generate_latest(exporter.REGISTRY).decode()
    assert 'configsentry_rule_passed{device="c8k",rule="CS-01",severity="high"} 0.0' in text
    assert 'configsentry_rule_passed{device="c8k",rule="CS-02",severity="high"} 1.0' in text
    assert 'configsentry_compliance_ratio{device="c8k"} 0.9333333333333333' in text
