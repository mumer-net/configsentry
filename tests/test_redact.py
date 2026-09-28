import pytest

from configsentry.redact import fingerprint, redact

KEY = b"test-key"


@pytest.mark.parametrize(
    "line,secret",
    [
        ("enable secret 9 $9$abcDEF$xyz", "$9$abcDEF$xyz"),
        ("enable password 7 0822455D0A16", "0822455D0A16"),
        ("username admin privilege 15 secret 9 $9$salt$hash", "$9$salt$hash"),
        ("username bob password 0 Hunter2", "Hunter2"),
        (" password 7 104D000A0618", "104D000A0618"),
        (" key-string 7 070C285F4D06", "070C285F4D06"),
        (" key 7 13061E010803", "13061E010803"),
        (" ip ospf message-digest-key 1 md5 7 011057175804", "011057175804"),
        ("ntp authentication-key 1 md5 104D000A0618 7", "104D000A0618"),
        ("crypto isakmp key Sup3rSecret address 0.0.0.0", "Sup3rSecret"),
        ("snmp-server community N3tM0n-RO RO", "N3tM0n-RO"),
    ],
)
def test_secrets_are_hidden(line, secret):
    assert secret not in redact(line)
    assert secret not in fingerprint(line, KEY)


@pytest.mark.parametrize(
    "line",
    [
        "service password-encryption",
        "password encryption aes",
        "key chain OSPF-KEYS",
        " key 1",
        "snmp-server community public RO",
        "security passwords min-length 12",
    ],
)
def test_lines_without_secrets_are_unchanged(line):
    assert redact(line) == line


def test_fingerprints_are_stable_keyed_and_idempotent():
    line = "username admin privilege 15 secret 9 $9$salt$hash"
    once = fingerprint(line, KEY)
    assert once == fingerprint(line, KEY)
    assert once != fingerprint(line, b"another-key")
    assert fingerprint(once, KEY) == once
    assert fingerprint(line.replace("hash", "changed"), KEY) != once


def test_fingerprint_needs_a_key():
    with pytest.raises(ValueError):
        fingerprint("enable secret 9 x", b"")
