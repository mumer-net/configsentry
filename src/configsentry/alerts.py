"""Webex alerts that fire on change, not on every run.

A rule that fails every five minutes should page someone once, not 288 times a day. So an alert
goes out only when something changed since the device's last audit: a rule newly failing, a rule
fixed, or the amount of drift moving.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import httpx

from configsentry.engine import AuditResult

WEBEX_MESSAGES_URL = "https://webexapis.com/v1/messages"
MAX_BYTES = 7000  # Webex rejects messages over 7,439 bytes, so cut by bytes, not characters


def build_message(result: AuditResult, previous: dict | None) -> str | None:
    """Markdown for Webex, or None when nothing changed since the previous audit."""
    failing = {r.rule for r in result.failed}
    before = previous["failing"] if previous else set()
    new = sorted(failing - before)
    fixed = sorted(before - failing)
    drift_now = result.drift.changed if result.drift else None
    drift_moved = previous is not None and drift_now is not None and drift_now != previous["drift"]
    first_drift = previous is None and bool(drift_now)
    if not (new or fixed or drift_moved or first_drift):
        return None

    by_id = {r.rule: r for r in result.results}
    lines = [f"**ConfigSentry: {result.device}** ({result.passed_count}/{len(result.results)} rules passing)"]
    if new:
        lines.append("**New failures**")
        lines += [f"- {rid} {by_id[rid].title}: {'; '.join(by_id[rid].problems[:2])}" for rid in new]
    if fixed:
        lines.append("**Fixed since last audit**")
        lines += [f"- {rid} {by_id[rid].title}" for rid in fixed if rid in by_id]
    if result.drift and (drift_moved or first_drift):
        lines.append(f"**Drift vs Git baseline:** +{len(result.drift.added)} / -{len(result.drift.removed)} lines")
    return "\n".join(lines).encode()[:MAX_BYTES].decode(errors="ignore")


def send(markdown: str, token: str, room_id: str, client: httpx.Client | None = None) -> None:
    client = client or httpx.Client(timeout=10)
    response = client.post(
        WEBEX_MESSAGES_URL,
        headers={"Authorization": f"Bearer {token}"},
        json={"roomId": room_id, "markdown": markdown},
    )
    response.raise_for_status()


def send_if_configured(markdown: str, log: Callable[[str], None] = print) -> None:
    token, room = os.environ.get("WEBEX_BOT_TOKEN"), os.environ.get("WEBEX_ROOM_ID")
    if not token or not room:
        log("Webex not configured (WEBEX_BOT_TOKEN, WEBEX_ROOM_ID); alert printed instead:\n" + markdown)
        return
    try:
        send(markdown, token, room)
        log("Webex alert sent")
    except httpx.HTTPError as exc:  # a failed alert must not fail the audit
        log(f"Webex alert failed: {exc}")
