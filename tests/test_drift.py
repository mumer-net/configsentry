from configsentry.drift import compare, normalize

KEY = b"test-key"
BASE = """\
Building configuration...

Current configuration : 1200 bytes
!
! Last configuration change at 09:00:00 UTC Mon Sep 28 2026
!
hostname r1
username admin privilege 15 secret 9 $9$salt$hashA
logging host 192.0.2.50
!
end
"""


def test_volatile_lines_are_not_drift():
    later = BASE.replace("1200 bytes", "1210 bytes").replace("09:00:00", "17:45:12")
    assert compare(BASE, later, KEY).changed == 0


def test_added_and_removed_lines_are_reported():
    later = BASE.replace("logging host 192.0.2.50", "logging host 203.0.113.9")
    drift = compare(BASE, later, KEY, "r1")
    assert drift.added == ["logging host 203.0.113.9"]
    assert drift.removed == ["logging host 192.0.2.50"]
    assert drift.diff.startswith("--- baselines/r1.cfg")


def test_a_changed_secret_is_drift_but_never_appears_in_the_diff():
    later = BASE.replace("hashA", "hashB")
    drift = compare(BASE, later, KEY)
    assert drift.changed == 2
    assert "hashA" not in drift.diff and "hashB" not in drift.diff


def test_normalized_baseline_is_safe_to_commit():
    saved = "\n".join(normalize(BASE, KEY))
    assert "$9$salt$hashA" not in saved and "<hmac:" in saved
    assert compare(saved, BASE, KEY).changed == 0  # a saved baseline compares cleanly with the raw config
