from pathlib import Path

import pytest

from configsentry.faults import Fault, FaultError, apply, load_faults, selftest
from configsentry.rules import RULES

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = (FIXTURES / "golden.cfg").read_text()
FAULTS = load_faults(FIXTURES / "faults.yaml")


def test_every_rule_has_at_least_one_seeded_fault():
    assert {r.id for r in RULES} <= {f.rule for f in FAULTS}


@pytest.mark.parametrize("fault", FAULTS, ids=lambda f: f"{f.rule}-{f.why}")
def test_each_fault_trips_its_rule_and_nothing_else(fault):
    golden_failures, (row,) = selftest(GOLDEN, [fault])
    assert golden_failures == []
    assert row.detected, f"{fault.rule} missed: {fault.why}"
    assert row.false_positives == [], f"{fault.why} also tripped {row.false_positives}"


def test_a_fault_that_matches_nothing_is_an_error_not_a_silent_pass():
    with pytest.raises(FaultError):
        apply(GOLDEN, Fault(rule="CS-01", why="typo", remove="ip ssh versoin 2"))


def test_faults_never_edit_banner_text():
    # golden.cfg has "line vty 0 4" inside a banner; the fault must land in the real block
    faulty = apply(
        GOLDEN,
        Fault(rule="CS-02", why="x", replace="transport input ssh", with_="transport input all", under="line vty 0 4"),
    )
    assert " transport input telnet\n" in faulty  # banner text untouched
    assert faulty.count("transport input all") == 1
