"""Prometheus metrics for compliance, so Grafana can graph it and Alertmanager can page on it."""

from __future__ import annotations

import time
from collections.abc import Callable

from prometheus_client import CollectorRegistry, Gauge, start_http_server

from configsentry.engine import AuditResult

REGISTRY = CollectorRegistry()
RULE_PASSED = Gauge(
    "configsentry_rule_passed",
    "1 if the rule passed on the latest audit, else 0",
    ["device", "rule", "severity"],
    registry=REGISTRY,
)
COMPLIANCE = Gauge(
    "configsentry_compliance_ratio", "Share of rules passing on the latest audit", ["device"], registry=REGISTRY
)
DRIFT = Gauge(
    "configsentry_drift_lines", "Lines added or removed versus the Git baseline", ["device"], registry=REGISTRY
)
LAST_AUDIT = Gauge(
    "configsentry_last_audit_timestamp_seconds", "Unix time of the latest audit", ["device"], registry=REGISTRY
)
DURATION = Gauge(
    "configsentry_audit_duration_seconds",
    "Collection plus audit time of the latest audit",
    ["device"],
    registry=REGISTRY,
)


def update(result: AuditResult) -> None:
    for r in result.results:
        RULE_PASSED.labels(result.device, r.rule, r.severity).set(int(r.passed))
    COMPLIANCE.labels(result.device).set(result.passed_count / len(result.results))
    if result.drift is not None:
        DRIFT.labels(result.device).set(result.drift.changed)
    LAST_AUDIT.labels(result.device).set(time.time())
    DURATION.labels(result.device).set(result.duration_s)


def serve(audit_all: Callable[[], list[AuditResult]], interval: int, port: int) -> None:
    start_http_server(port, registry=REGISTRY)
    while True:
        for result in audit_all():
            update(result)
        time.sleep(interval)
