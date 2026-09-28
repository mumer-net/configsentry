"""Keep secrets out of reports, alerts, baselines, and Git.

Two modes share one list of patterns:
- redact(): replaces each secret with <redacted>. Used for anything a person reads.
- fingerprint(): replaces each secret with a keyed HMAC fingerprint. Used for baselines, so a
  changed secret still shows up as drift, but neither the secret nor its hash is ever stored.
  The key lives in .env; without it, a fingerprint can't be brute-forced from a public repo.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable

_PATTERNS = [
    # enable secret 9 ..., username x secret 9 ..., line " password 7 ...", "password 0 cisco"
    re.compile(r"(?P<head>\b(?:secret|password)\s+(?!encryption\b)(?:[0-9]\s+)?)(?P<value>\S+)"),
    # key chain " key-string 7 ...", RADIUS/TACACS server " key 7 ..."
    re.compile(r"(?P<head>^\s*key-string\s+(?:[0-9]\s+)?)(?P<value>\S+)"),
    re.compile(r"(?P<head>^\s*key\s+(?!chain\b|config-key\b|\d+\s*$)(?:[0-9]\s+)?)(?P<value>\S+)"),
    # OSPF, NTP, and IKE keys
    re.compile(r"(?P<head>\bip ospf authentication-key\s+(?:[07]\s+)?)(?P<value>\S+)"),
    re.compile(r"(?P<head>\bmessage-digest-key\s+\d+\s+md5\s+(?:[07]\s+)?)(?P<value>\S+)"),
    re.compile(r"(?P<head>\bntp authentication-key\s+\d+\s+\S+\s+)(?P<value>\S+)"),
    re.compile(r"(?P<head>\bcrypto isakmp key\s+(?:[06]\s+)?)(?P<value>\S+)"),
    # SNMP community names are passwords too; the well-known defaults stay visible on purpose
    re.compile(r"(?P<head>^\s*snmp-server community\s+)(?P<value>(?!(?:public|private)(?:\s|$))\S+)", re.I),
]
_ALREADY_HIDDEN = re.compile(r"^<(redacted|hmac:[0-9a-f]+)>$")


def _replace(line: str, make: Callable[[str], str]) -> str:
    def swap(match: re.Match[str]) -> str:
        value = match.group("value")
        if _ALREADY_HIDDEN.match(value):  # keeps both functions idempotent
            return match.group(0)
        return match.group("head") + make(value)

    for pattern in _PATTERNS:
        line = pattern.sub(swap, line)
    return line


def redact(line: str) -> str:
    """Hide every secret on the line."""
    return _replace(line, lambda _value: "<redacted>")


def fingerprint(line: str, key: bytes) -> str:
    """Swap every secret for a short keyed fingerprint (same secret + same key = same text)."""
    if not key:
        raise ValueError("a fingerprint key is required; set CONFIGSENTRY_FINGERPRINT_KEY in .env")
    return _replace(line, lambda value: f"<hmac:{hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:12]}>")


def redact_text(text: str) -> str:
    return "\n".join(redact(line) for line in text.split("\n"))
