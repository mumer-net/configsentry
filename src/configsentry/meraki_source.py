"""Where Meraki data comes from: the live Dashboard API, or JSON recorded from it.

Both sources answer the same four questions, so the checks never know which one they're reading.
Recorded fixtures make the checks testable offline, and seeded copies of them prove each check
catches its fault.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from rich.console import Console

from configsentry import __version__


class FixtureSource:
    """Reads responses saved by `configsentry meraki --record` (or written by hand for tests)."""

    def __init__(self, root: Path):
        self.root = root

    def _load(self, relative: str, default=None):
        path = self.root / relative
        return json.loads(path.read_text()) if path.exists() else default

    def devices(self, org_id: str) -> list[dict]:
        return self._load("devices.json", [])

    def availabilities(self, org_id: str) -> list[dict]:
        return self._load("availabilities.json", [])

    def stacks(self, network_id: str) -> list[dict]:
        return self._load(f"stacks/{network_id}.json", [])

    def port_statuses(self, serial: str) -> list[dict]:
        return self._load(f"ports/{serial}.json", [])


class LiveSource:
    """Calls the Meraki Dashboard API with a read-only key from MERAKI_DASHBOARD_API_KEY."""

    def __init__(self, api_key: str | None = None):
        import meraki  # imported here so offline use doesn't need the SDK configured

        key = api_key or os.environ.get("MERAKI_DASHBOARD_API_KEY")
        if not key:
            raise RuntimeError("set MERAKI_DASHBOARD_API_KEY in .env")
        # The SDK rejects a caller that isn't "AppName/version VendorName", before any request is sent
        caller = f"ConfigSentry/{__version__} ConfigSentry"
        self.api = meraki.DashboardAPI(key, output_log=False, print_console=False, suppress_logging=True, caller=caller)

    def organizations(self) -> list[dict]:
        return self.api.organizations.getOrganizations()

    def networks(self, org_id: str) -> list[dict]:
        return self.api.organizations.getOrganizationNetworks(org_id, total_pages="all")

    def devices(self, org_id: str) -> list[dict]:
        return self.api.organizations.getOrganizationDevices(org_id, total_pages="all")

    def availabilities(self, org_id: str) -> list[dict]:
        return self.api.organizations.getOrganizationDevicesAvailabilities(org_id, total_pages="all")

    def stacks(self, network_id: str) -> list[dict]:
        return self.api.switch.getNetworkSwitchStacks(network_id)

    def port_statuses(self, serial: str) -> list[dict]:
        return self.api.switch.getDeviceSwitchPortsStatuses(serial)


def discover(live: LiveSource) -> None:
    """Print what the API key can see, to help write intent/meraki.yaml."""
    console = Console()
    for org in live.organizations():
        console.print(f"[bold]Org {org['id']}[/] {org['name']}")
        devices = live.devices(org["id"])
        for net in live.networks(org["id"]):
            console.print(f"  Network {net['id']} {net['name']}")
            for d in (d for d in devices if d.get("networkId") == net["id"]):
                console.print(f"    {d.get('serial')} {d.get('model')} {d.get('productType')} {d.get('name') or ''}")
            if "switch" in net.get("productTypes", []):
                for stack in live.stacks(net["id"]):
                    console.print(f"    stack {stack['name']}: {', '.join(stack.get('serials', []))}")


def record(live: LiveSource, org_id: str, network_ids: list[str], out: Path) -> None:
    """Save real API responses in the FixtureSource layout."""
    (out / "stacks").mkdir(parents=True, exist_ok=True)
    (out / "ports").mkdir(parents=True, exist_ok=True)
    devices = [d for d in live.devices(org_id) if not network_ids or d.get("networkId") in network_ids]
    (out / "devices.json").write_text(json.dumps(devices, indent=2))
    availabilities = [a for a in live.availabilities(org_id) if a.get("serial") in {d["serial"] for d in devices}]
    (out / "availabilities.json").write_text(json.dumps(availabilities, indent=2))
    switch_networks = {d.get("networkId") for d in devices if d.get("productType") == "switch"}
    for network_id in network_ids:  # the stacks endpoint only answers for networks with switches
        stacks = live.stacks(network_id) if network_id in switch_networks else []
        (out / "stacks" / f"{network_id}.json").write_text(json.dumps(stacks, indent=2))
    for d in devices:
        if d.get("productType") == "switch":
            (out / "ports" / f"{d['serial']}.json").write_text(json.dumps(live.port_statuses(d["serial"]), indent=2))
