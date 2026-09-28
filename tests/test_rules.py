from pathlib import Path

import pytest

from configsentry.engine import run_rules
from configsentry.parser import parse
from configsentry.redact import redact_text
from configsentry.rules import RULES

GOLDEN = (Path(__file__).parent / "fixtures" / "golden.cfg").read_text()
BY_ID = {r.id: r for r in RULES}


def check(rule_id: str, config: str) -> list[str]:
    return BY_ID[rule_id].check(parse(config))


def test_fifteen_rules_with_unique_ids_and_cis_mapping():
    assert len(RULES) == 15
    assert len(BY_ID) == 15
    assert all(r.cis and r.fix and r.severity in {"low", "medium", "high"} for r in RULES)


@pytest.mark.parametrize("rule_id", sorted(BY_ID))
def test_golden_config_passes_every_rule(rule_id):
    assert check(rule_id, GOLDEN) == []


def test_missing_exec_timeout_means_the_compliant_default():
    assert check("CS-03", "line vty 0 4\n transport input ssh\n") == []


def test_exec_timeout_zero_fails():
    problems = check("CS-03", "line vty 0 4\n exec-timeout 0 0\n")
    assert problems and "never disconnects" in problems[0]


def test_missing_ssh_timeout_means_the_noncompliant_default():
    assert "120-second default" in check("CS-12", "hostname r1\n")[0]


def test_transport_input_none_counts_as_ssh_only():
    assert check("CS-02", "line vty 0 4\n transport input none\n") == []


def test_evidence_never_contains_secrets():
    config = GOLDEN + "\nenable password 7 0822455D0A16\nusername bob password 0 Hunter2\n"
    evidence = " ".join(p for r in run_rules(config) for p in r.problems)
    assert "0822455D0A16" not in evidence and "Hunter2" not in evidence
    assert "<redacted>" in evidence


def test_rules_give_the_same_verdict_on_redacted_configs():
    faulty = GOLDEN + "\nsnmp-server community Ops-Write RW\nusername bob password 0 Hunter2\n"
    before = {r.rule: r.passed for r in run_rules(faulty)}
    after = {r.rule: r.passed for r in run_rules(redact_text(faulty))}
    assert before == after
