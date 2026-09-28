"""The 15 ConfigSentry rules, each mapped to a CIS Cisco IOS XE 17.x Benchmark recommendation.

A rule is a function that takes a parsed Config and returns a list of problems. An empty list
means the rule passed. Problems are short evidence strings with line numbers, and they never
contain secrets.

`show running-config` hides settings left at their default, so every rule has to decide what a
missing line means. That decision is written next to each rule.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from configsentry.parser import Config, Line
from configsentry.redact import redact

Check = Callable[[Config], list[str]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str  # high | medium | low
    cis: str  # CIS Cisco IOS XE 17.x Benchmark v2.1.0 recommendation
    fix: str  # config that makes the rule pass
    check: Check


RULES: list[Rule] = []


def rule(id: str, title: str, severity: str, cis: str, fix: str) -> Callable[[Check], Check]:
    """Register a check function as a rule."""

    def register(check: Check) -> Check:
        RULES.append(Rule(id, title, severity, cis, fix, check))
        return check

    return register


def _vtys(cfg: Config) -> list[Line]:
    return cfg.find(r"^line vty\s")


def _idle_timeout_problems(block: Line, limit_s: int = 600) -> list[str]:
    # Missing line = the default of 10 minutes, which is compliant.
    line = block.child(r"^exec-timeout\s")
    if line is None:
        return []
    parts = line.text.split()[1:]
    seconds = int(parts[0]) * 60 + (int(parts[1]) if len(parts) > 1 else 0)
    if seconds == 0:
        return [f"{block.where()}: 'exec-timeout 0 0' never disconnects idle sessions"]
    if seconds > limit_s:
        return [f"{block.where()}: idle timeout is {seconds // 60} min {seconds % 60} s (limit 10 min)"]
    return []


# Management access: CS-01 to CS-05


@rule("CS-01", "SSH version 2 only", "high", "2.1.1.2 Set version 2 for 'ip ssh version'", "ip ssh version 2")
def ssh_version_2(cfg: Config) -> list[str]:
    return [] if cfg.has(r"^ip ssh version 2$") else ["'ip ssh version 2' is not set"]


@rule(
    "CS-02",
    "VTY lines accept SSH only",
    "high",
    "1.2.2 Set 'transport input ssh' for 'line vty' connections",
    "line vty 0 15\n transport input ssh",
)
def vty_ssh_only(cfg: Config) -> list[str]:
    # Missing line = fail: the default differs across releases, so only an explicit setting counts.
    vtys = _vtys(cfg)
    if not vtys:
        return ["no 'line vty' blocks found"]
    problems = []
    for vty in vtys:
        transport = vty.child(r"^transport input\s")
        if transport is None:
            problems.append(f"{vty.where()}: no explicit 'transport input ssh'")
        elif transport.text.split()[2:] not in (["ssh"], ["none"]):
            problems.append(f"{vty.where()}: '{transport.text}'")
    return problems


@rule(
    "CS-03",
    "VTY idle timeout of 10 minutes or less",
    "medium",
    "1.2.8 Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'",
    "line vty 0 15\n exec-timeout 10 0",
)
def vty_idle_timeout(cfg: Config) -> list[str]:
    return [problem for vty in _vtys(cfg) for problem in _idle_timeout_problems(vty)]


@rule(
    "CS-04",
    "Console idle timeout of 10 minutes or less",
    "medium",
    "1.2.7 Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'",
    "line con 0\n exec-timeout 10 0",
)
def console_idle_timeout(cfg: Config) -> list[str]:
    return [problem for con in cfg.find(r"^line con(sole)? 0$") for problem in _idle_timeout_problems(con)]


@rule(
    "CS-05",
    "VTY access limited by an ACL",
    "high",
    "1.2.5 Set 'access-class' for 'line vty'",
    "line vty 0 15\n access-class MGMT-SSH in",
)
def vty_access_class(cfg: Config) -> list[str]:
    return [
        f"{vty.where()}: no 'access-class <acl> in'"
        for vty in _vtys(cfg)
        if vty.child(r"^access-class \S+ in\b") is None
    ]


# Credentials: CS-06 to CS-08


@rule(
    "CS-06",
    "Enable secret set, no enable password",
    "high",
    "1.4.1 Set 'password' for 'enable secret'",
    "enable secret <strong-password>\nno enable password",
)
def enable_secret(cfg: Config) -> list[str]:
    problems = [] if cfg.has(r"^enable secret\s") else ["'enable secret' is not set"]
    problems += [f"'{redact(line.text)}' (line {line.number})" for line in cfg.find(r"^enable password\s")]
    return problems


@rule(
    "CS-07",
    "Password encryption service on",
    "medium",
    "1.4.2 Enable 'service password-encryption'",
    "service password-encryption",
)
def password_encryption(cfg: Config) -> list[str]:
    return [] if cfg.has(r"^service password-encryption$") else ["'service password-encryption' is not set"]


@rule(
    "CS-08",
    "Local users stored as secrets",
    "high",
    "1.4.3 Set 'username secret' for all local users",
    "username <name> secret <strong-password>",
)
def username_secret(cfg: Config) -> list[str]:
    return [
        f"'{redact(line.text)}' (line {line.number}): uses 'password', not 'secret'"
        for line in cfg.find(r"^username\s")
        if re.search(r"\spassword\s", line.text)
    ]


# SNMP: CS-09 and CS-10


@rule(
    "CS-09",
    "No default SNMP community names",
    "high",
    "1.5.2 and 1.5.3 Unset 'private' and 'public' for 'snmp-server community'",
    "no snmp-server community public\nno snmp-server community private",
)
def snmp_default_communities(cfg: Config) -> list[str]:
    return [line.where() for line in cfg.find(r"(?i)^snmp-server community (public|private)(\s|$)")]


@rule(
    "CS-10",
    "No read-write SNMP communities",
    "high",
    "1.5.4 Do not set 'RW' for any 'snmp-server community'",
    "no snmp-server community <name> RW",
)
def snmp_read_write(cfg: Config) -> list[str]:
    return [
        f"'{redact(line.text)}' (line {line.number})" for line in cfg.find(r"(?i)^snmp-server community \S+ rw(\s|$)")
    ]


# Services and logging: CS-11 to CS-15


@rule("CS-11", "AAA new-model enabled", "high", "1.1.1 Enable 'aaa new-model'", "aaa new-model")
def aaa_new_model(cfg: Config) -> list[str]:
    return [] if cfg.has(r"^aaa new-model$") else ["'aaa new-model' is not set, so AAA is off"]


@rule(
    "CS-12",
    "SSH login timeout of 60 seconds or less",
    "medium",
    "2.1.1.1.4 Set 'seconds' for 'ip ssh timeout' for 60 seconds or less",
    "ip ssh time-out 60",
)
def ssh_login_timeout(cfg: Config) -> list[str]:
    # Missing line = the default of 120 seconds, which is NOT compliant (the opposite of CS-03).
    lines = cfg.find(r"^ip ssh time-out\s")
    if not lines:
        return ["'ip ssh time-out' is not set, so the 120-second default applies"]
    seconds = int(lines[0].text.split()[-1])
    return [] if seconds <= 60 else [f"{lines[0].where()}: {seconds} s is over 60 s"]


@rule(
    "CS-13",
    "Logs sent to a remote syslog server",
    "medium",
    "2.2.4 Set IP address for 'logging host'",
    "logging host <syslog-server-ip>",
)
def remote_logging(cfg: Config) -> list[str]:
    ok = cfg.has(r"^logging (host \S+|\d{1,3}(\.\d{1,3}){3})")
    return [] if ok else ["no 'logging host' is configured"]


@rule(
    "CS-14",
    "Debug messages carry timestamps",
    "low",
    "2.2.6 Set 'service timestamps debug datetime'",
    "service timestamps debug datetime msec show-timezone",
)
def debug_timestamps(cfg: Config) -> list[str]:
    ok = cfg.has(r"^service timestamps debug datetime")
    return [] if ok else ["'service timestamps debug datetime' is not set"]


@rule(
    "CS-15",
    "Login warning banner set",
    "low",
    "1.3.2 and 1.3.3 Set the 'banner-text' for 'banner login' and 'banner motd'",
    "banner login ^CAuthorized access only. Activity is logged.^C",
)
def login_banner(cfg: Config) -> list[str]:
    has_text = any(cfg.banners.get(kind, "").strip() for kind in ("login", "motd"))
    return [] if has_text else ["no 'banner login' or 'banner motd' text"]
