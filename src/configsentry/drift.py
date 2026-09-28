"""Compare a device's running config with its approved baseline, which lives in Git.

Both sides are normalized first, so the diff shows real changes only: timestamps and byte counts
that change on every read are dropped, and secrets become keyed fingerprints. That makes the
baseline safe to commit while a changed password still shows up as drift.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from configsentry.redact import fingerprint

_VOLATILE = re.compile(
    r"^(Building configuration|Current configuration :|! Last configuration change|"
    r"! NVRAM config last updated|! No configuration change since last restart|"
    r"ntp clock-period|Load for five secs|Time source is)"
)


def normalize(text: str, key: bytes) -> list[str]:
    lines = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped == "!" or _VOLATILE.match(stripped):
            continue
        lines.append(fingerprint(line, key))
    return lines


@dataclass
class Drift:
    added: list[str]
    removed: list[str]
    diff: str

    @property
    def changed(self) -> int:
        return len(self.added) + len(self.removed)


def compare(baseline: str, current: str, key: bytes, device: str = "device") -> Drift:
    before, after = normalize(baseline, key), normalize(current, key)
    diff = list(difflib.unified_diff(before, after, f"baselines/{device}.cfg", f"{device} (running)", lineterm=""))
    added = [d[1:] for d in diff if d.startswith("+") and not d.startswith("+++")]
    removed = [d[1:] for d in diff if d.startswith("-") and not d.startswith("---")]
    return Drift(added=added, removed=removed, diff="\n".join(diff))
