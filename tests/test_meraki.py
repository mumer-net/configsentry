"""Meraki checks against the healthy fixtures, then one seeded fault per check."""

import copy
from pathlib import Path

import pytest

from configsentry.meraki_checks import audit, check_network, load_intent
from configsentry.meraki_source import FixtureSource, LiveSource

ROOT = Path(__file__).resolve().parents[1]
INTENT = load_intent(ROOT / "tests" / "fixtures" / "meraki" / "intent.yaml")
NET = INTENT["networks"][0]


class Seeded(FixtureSource):
    """A fixture source whose data can be broken one field at a time."""

    def __init__(self):
        super().__init__(ROOT / "tests" / "fixtures" / "meraki" / "healthy")
        self.data = {
            "devices": copy.deepcopy(super().devices("")),
            "availabilities": copy.deepcopy(super().availabilities("")),
            "stacks": copy.deepcopy(super().stacks(NET["id"])),
            "ports": {s: copy.deepcopy(super().port_statuses(s)) for s in ("Q3AA-AAAA-0001", "Q3AA-AAAA-0002")},
        }

    def devices(self, org_id):
        return self.data["devices"]

    def availabilities(self, org_id):
        return self.data["availabilities"]

    def stacks(self, network_id):
        return self.data["stacks"]

    def port_statuses(self, serial):
        return self.data["ports"].get(serial, [])


def drop_member(d):
    d["stacks"][0]["serials"].remove("Q3AA-AAAA-0003")


def swap_active(d):
    d["stacks"][0]["members"][0]["role"], d["stacks"][0]["members"][1]["role"] = "standby", "active"


def unplug_uplink(d):
    next(p for p in d["ports"]["Q3AA-AAAA-0001"] if p["portId"] == "50")["status"] = "Disconnected"


def remove_ap(d):
    d["devices"] = [x for x in d["devices"] if x["serial"] != "Q3AB-BBBB-0004"]


def take_switch_offline(d):
    next(a for a in d["availabilities"] if a["serial"] == "Q3AA-AAAA-0002")["status"] = "offline"


def test_healthy_network_passes_every_check():
    (result,) = audit(INTENT, Seeded())
    assert result.failed == []
    assert result.device == "Building A" and len(result.results) == 5


@pytest.mark.parametrize(
    "break_it,check",
    [
        (drop_member, "MK-01"),
        (swap_active, "MK-02"),
        (unplug_uplink, "MK-03"),
        (remove_ap, "MK-04"),
        (take_switch_offline, "MK-05"),
    ],
)
def test_each_seeded_fault_trips_exactly_its_check(break_it, check):
    source = Seeded()
    break_it(source.data)
    problems = check_network(NET, source, INTENT["organization_id"])
    assert [c for c, p in problems.items() if p] == [check]


def test_live_source_passes_the_sdk_caller_check():
    LiveSource(api_key="0" * 40)  # the SDK validates its caller string here, before any network call
