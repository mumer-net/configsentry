"""Meraki checks: compare what the Dashboard API reports with what the network is meant to be.

These automate post-deployment verification done by hand in the Dashboard: right switches in
each stack, the intended switch active, uplinks connected, enough access points, every device
online. Intent lives in intent/meraki.yaml, so "what should be true" is reviewed in Git like code.
"""

from __future__ import annotations

import time
from pathlib import Path

import yaml

from configsentry.engine import AuditResult, RuleResult, now_iso

CHECKS = {
    "MK-01": ("Stack members match intent", "high", "Add or remove stack members in Dashboard to match intent"),
    "MK-02": ("Intended switch is the active stack member", "medium", "Check stack cabling and switch priority"),
    "MK-03": ("Uplink ports connected", "high", "Check cabling, SFPs, and the upstream port for each listed uplink"),
    "MK-04": ("Access point count meets intent", "medium", "Claim and add the missing APs, or update the intent"),
    "MK-05": ("Every device online", "high", "Check power, uplink, and cloud connectivity for each device"),
}


def load_intent(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def check_network(net: dict, source, org_id: str) -> dict[str, list[str]]:
    """Problems per check ID for one network. An empty list means the check passed."""
    problems: dict[str, list[str]] = {check: [] for check in CHECKS}
    devices = [d for d in source.devices(org_id) if d.get("networkId") == net["id"]]
    stacks = {s["name"]: s for s in source.stacks(net["id"])} if net.get("stacks") else {}

    for want in net.get("stacks", []):
        got = stacks.get(want["name"])
        if got is None:
            problems["MK-01"].append(f"stack {want['name']!r} not found")
            continue
        missing = [s for s in want["members"] if s not in got.get("serials", [])]
        extra = [s for s in got.get("serials", []) if s not in want["members"]]
        problems["MK-01"] += [f"{want['name']}: {s} missing" for s in missing]
        problems["MK-01"] += [f"{want['name']}: {s} not in intent" for s in extra]
        if want.get("active"):
            active = [m["serial"] for m in got.get("members", []) if m.get("role") == "active"]
            if active != [want["active"]]:
                actual = ", ".join(active) or "none"
                problems["MK-02"].append(f"{want['name']}: active is {actual}, expected {want['active']}")

    for serial, ports in net.get("uplinks", {}).items():
        statuses = {p["portId"]: p.get("status") for p in source.port_statuses(serial)}
        for port in ports:
            status = statuses.get(str(port), "missing")
            if status != "Connected":
                problems["MK-03"].append(f"{serial} port {port}: {status}")

    access_points = [d for d in devices if d.get("productType") == "wireless"]
    if len(access_points) < net.get("min_access_points", 0):
        expected = net["min_access_points"]
        problems["MK-04"].append(f"{len(access_points)} access points found, intent expects at least {expected}")

    if net.get("all_devices_online", True):
        serials = {d["serial"] for d in devices}
        for a in source.availabilities(org_id):
            if a.get("serial") in serials and a.get("status") != "online":
                problems["MK-05"].append(f"{a['serial']} ({a.get('productType', '?')}): {a.get('status')}")
    return problems


def audit(intent: dict, source) -> list[AuditResult]:
    results = []
    for net in intent["networks"]:
        started, started_at = time.perf_counter(), now_iso()
        problems = check_network(net, source, intent["organization_id"])
        rule_results = [
            RuleResult(check, title, severity, not problems[check], problems[check], fix, "Meraki intent")
            for check, (title, severity, fix) in CHECKS.items()
        ]
        results.append(
            AuditResult(
                device=net.get("name", net["id"]),
                source="meraki",
                started_at=started_at,
                duration_s=round(time.perf_counter() - started, 3),
                results=rule_results,
            )
        )
    return results
