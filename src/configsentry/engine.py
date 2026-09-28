"""Run every rule against a config and package the results."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from configsentry.parser import parse
from configsentry.rules import RULES

if TYPE_CHECKING:
    from configsentry.drift import Drift

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class RuleResult:
    rule: str
    title: str
    severity: str
    passed: bool
    problems: list[str]
    fix: str
    cis: str = ""


@dataclass
class AuditResult:
    device: str
    source: str  # ssh | file | meraki
    started_at: str  # ISO 8601, UTC
    duration_s: float
    results: list[RuleResult]
    facts: dict[str, str] = field(default_factory=dict)
    drift: Drift | None = None

    @property
    def failed(self) -> list[RuleResult]:
        return [r for r in self.results if not r.passed]

    @property
    def passed_count(self) -> int:
        return sum(r.passed for r in self.results)

    def worst_failure(self) -> int:
        """Highest severity rank among failed rules (0 if everything passed)."""
        return max((SEVERITY_RANK[r.severity] for r in self.failed), default=0)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def run_rules(text: str) -> list[RuleResult]:
    cfg = parse(text)
    results = []
    for r in RULES:
        problems = r.check(cfg)
        results.append(RuleResult(r.id, r.title, r.severity, not problems, problems, r.fix, r.cis))
    return results


def audit_text(
    text: str, device: str, source: str = "file", facts: dict | None = None, started: float | None = None
) -> AuditResult:
    """Audit config text. Pass `started` (time.perf_counter()) to include collection time."""
    started = time.perf_counter() if started is None else started
    started_at = now_iso()
    results = run_rules(text)
    return AuditResult(
        device=device,
        source=source,
        started_at=started_at,
        duration_s=round(time.perf_counter() - started, 3),
        results=results,
        facts=facts or {},
    )
