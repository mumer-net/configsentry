"""Seeded faults: break a compliant config one rule at a time and prove each rule catches it.

Each fault is one edit to the golden config (remove, add, or replace a line, optionally inside a
block). The self-test applies every fault and checks two things: the targeted rule fails, and no
other rule does. That gives the detection rate and the false-positive count.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from configsentry.engine import run_rules
from configsentry.parser import Line, parse


class FaultError(ValueError):
    """The fault's target line or block wasn't found, so the fault would silently do nothing."""


@dataclass
class Fault:
    rule: str
    why: str
    remove: str | None = None
    add: str | None = None
    replace: str | None = None
    with_: str | None = None
    under: str | None = None


def load_faults(path: Path) -> list[Fault]:
    items = yaml.safe_load(path.read_text())
    return [Fault(**{("with_" if k == "with" else k): v for k, v in item.items()}) for item in items]


def _last_number(line: Line) -> int:
    return _last_number(line.children[-1]) if line.children else line.number


def apply(text: str, fault: Fault) -> str:
    """Return a copy of the config with the fault applied.

    Uses the parser to find lines, so text inside a banner can never be mistaken for config.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    cfg = parse(text)
    if fault.under:
        parent = next((line for line in cfg.lines if line.text == fault.under), None)
        if parent is None:
            raise FaultError(f"{fault.rule}: block {fault.under!r} not found")
        candidates, indent = parent.children, " "
        insert_at = _last_number(parent)  # after the block's last line
    else:
        candidates, indent = cfg.lines, ""
        end = next((line for line in cfg.lines if line.text == "end"), None)
        insert_at = end.number - 1 if end else len(lines)  # before "end"

    if fault.add:
        lines.insert(insert_at, indent + fault.add.strip())
        return "\n".join(lines)

    wanted = (fault.remove or fault.replace or "").strip()
    target = next((line for line in candidates if line.text == wanted), None)
    if target is None:
        where = f" under {fault.under!r}" if fault.under else ""
        raise FaultError(f"{fault.rule}: line {wanted!r} not found{where}")
    index = target.number - 1
    if fault.remove:
        del lines[index]
    else:
        leading = lines[index][: len(lines[index]) - len(lines[index].lstrip(" "))]
        lines[index] = leading + (fault.with_ or "").strip()
    return "\n".join(lines)


@dataclass
class SelfTestRow:
    rule: str
    why: str
    detected: bool
    false_positives: list[str]


def selftest(golden: str, faults: list[Fault]) -> tuple[list[str], list[SelfTestRow]]:
    """Returns (rules failing on the golden config, one row per fault)."""
    golden_failures = [r.rule for r in run_rules(golden) if not r.passed]
    rows = []
    for fault in faults:
        failed = {r.rule for r in run_rules(apply(golden, fault)) if not r.passed}
        rows.append(SelfTestRow(fault.rule, fault.why, fault.rule in failed, sorted(failed - {fault.rule})))
    return golden_failures, rows
