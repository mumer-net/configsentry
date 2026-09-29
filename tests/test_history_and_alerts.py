from pathlib import Path

import httpx

from configsentry import alerts, store
from configsentry.engine import audit_text

GOLDEN = (Path(__file__).parent / "fixtures" / "golden.cfg").read_text()


def audit(text):
    return audit_text(text, "c8k", "ssh")


def test_history_round_trip_and_new_failures_only(tmp_path):
    db = store.connect(tmp_path / "cs.db")
    assert store.last_audit(db, "c8k") is None

    first = audit(GOLDEN.replace("ip ssh version 2\n", ""))  # CS-01 fails
    assert "New failures" in alerts.build_message(first, store.last_audit(db, "c8k"))
    store.save(db, first)

    same_again = audit(GOLDEN.replace("ip ssh version 2\n", ""))
    assert alerts.build_message(same_again, store.last_audit(db, "c8k")) is None  # nothing changed: no alert
    store.save(db, same_again)

    fixed = audit(GOLDEN)
    message = alerts.build_message(fixed, store.last_audit(db, "c8k"))
    assert "Fixed since last audit" in message and "CS-01" in message
    store.save(db, fixed)

    assert len(store.history(db, "c8k")) == 3
    assert store.failing_since(db, "c8k", "CS-01") is None
    assert store.latest(db, "c8k")["passed"] == 15


def test_webex_post_shape():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "msg1"})

    alerts.send("hello", "TOKEN", "ROOM", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen["url"] == "https://webexapis.com/v1/messages"
    assert seen["auth"] == "Bearer TOKEN"
    assert b'"roomId":"ROOM"' in seen["body"].replace(b" ", b"")
