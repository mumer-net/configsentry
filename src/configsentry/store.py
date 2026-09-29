"""Audit history in SQLite: one row per audit and one row per rule result.

The audit and meraki commands save every run here. Alerts compare each run with the previous
one, and the history command and the MCP server read from it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from configsentry.engine import AuditResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id            INTEGER PRIMARY KEY,
    device        TEXT    NOT NULL,
    source        TEXT    NOT NULL,          -- ssh | file | meraki
    started_at    TEXT    NOT NULL,          -- ISO 8601, UTC
    duration_s    REAL    NOT NULL,
    passed        INTEGER NOT NULL,
    failed        INTEGER NOT NULL,
    drift_added   INTEGER,                   -- NULL when there is no baseline
    drift_removed INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    rule     TEXT    NOT NULL,
    passed   INTEGER NOT NULL,
    evidence TEXT    NOT NULL,               -- already redacted
    PRIMARY KEY (audit_id, rule)
);
CREATE INDEX IF NOT EXISTS audits_by_device_time ON audits (device, started_at);
"""


def connect(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    return db


def save(db: sqlite3.Connection, result: AuditResult) -> int:
    drift = result.drift
    with db:  # one transaction: the audit and its findings land together or not at all
        cursor = db.execute(
            "INSERT INTO audits (device, source, started_at, duration_s, passed, failed, drift_added, drift_removed)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.device,
                result.source,
                result.started_at,
                result.duration_s,
                result.passed_count,
                len(result.failed),
                len(drift.added) if drift else None,
                len(drift.removed) if drift else None,
            ),
        )
        audit_id = cursor.lastrowid
        db.executemany(
            "INSERT INTO findings (audit_id, rule, passed, evidence) VALUES (?, ?, ?, ?)",
            [(audit_id, r.rule, int(r.passed), "; ".join(r.problems)) for r in result.results],
        )
    return audit_id


def last_audit(db: sqlite3.Connection, device: str) -> dict | None:
    """The device's most recent audit: its failing rules and drift size, or None if never audited."""
    row = db.execute(
        "SELECT id, drift_added, drift_removed FROM audits WHERE device = ? ORDER BY started_at DESC, id DESC LIMIT 1",
        (device,),
    ).fetchone()
    if row is None:
        return None
    rows = db.execute("SELECT rule FROM findings WHERE audit_id = ? AND passed = 0", (row["id"],))
    failing = {r["rule"] for r in rows}
    drift = None if row["drift_added"] is None else row["drift_added"] + row["drift_removed"]
    return {"failing": failing, "drift": drift}


def history(db: sqlite3.Connection, device: str | None = None, days: int = 7) -> list[sqlite3.Row]:
    # strftime gives the same "YYYY-MM-DDTHH:MM:SS" shape as started_at, so the strings compare correctly
    query = "SELECT * FROM audits WHERE started_at >= strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)"
    params: list = [f"-{days} days"]
    if device:
        query += " AND device = ?"
        params.append(device)
    return db.execute(query + " ORDER BY started_at DESC, id DESC", params).fetchall()


def failing_since(db: sqlite3.Connection, device: str, rule: str) -> str | None:
    """When the rule's current failing streak began (ISO time), or None if it passes now."""
    rows = db.execute(
        "SELECT a.started_at, f.passed FROM findings f JOIN audits a ON a.id = f.audit_id"
        " WHERE a.device = ? AND f.rule = ? ORDER BY a.started_at DESC, a.id DESC",
        (device, rule),
    ).fetchall()
    since = None
    for row in rows:
        if row["passed"]:
            break
        since = row["started_at"]
    return since


def latest(db: sqlite3.Connection, device: str) -> dict | None:
    """The latest audit for a device with every finding (used by the MCP server)."""
    audit = db.execute(
        "SELECT * FROM audits WHERE device = ? ORDER BY started_at DESC, id DESC LIMIT 1", (device,)
    ).fetchone()
    if audit is None:
        return None
    findings = db.execute(
        "SELECT rule, passed, evidence FROM findings WHERE audit_id = ? ORDER BY rule", (audit["id"],)
    )
    return {**dict(audit), "findings": [dict(f) for f in findings]}


def devices(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        "SELECT device, source, started_at, passed, failed FROM audits a"
        " WHERE id = (SELECT id FROM audits b WHERE b.device = a.device ORDER BY started_at DESC, id DESC LIMIT 1)"
        " ORDER BY device"
    ).fetchall()
    return [dict(r) for r in rows]
