"""Turn IOS-XE running-config text into a tree that rules can query.

`show running-config` is indentation-based: a line with no leading space starts a block, and the
indented lines below it are its children. Banners are the exception. Their text is free-form and
can look exactly like commands, so the parser reads everything up to the closing delimiter as
banner text instead of config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# "banner login ^C", "banner motd #Welcome#". Running-config always shows the delimiter as ^C.
_BANNER = re.compile(r"^banner\s+(\S+)\s+(\^C|\S)(.*)$")


@dataclass
class Line:
    """One config line and the lines indented beneath it."""

    text: str  # the line without leading spaces
    number: int  # 1-based line number in the original text, used as evidence
    children: list[Line] = field(default_factory=list)

    def child(self, pattern: str) -> Line | None:
        """First direct child whose text matches the regex, or None."""
        rx = re.compile(pattern)
        return next((c for c in self.children if rx.search(c.text)), None)

    def where(self) -> str:
        return f"'{self.text}' (line {self.number})"


@dataclass
class Config:
    """A parsed running-config: the top-level lines, plus banner text by banner type."""

    lines: list[Line]
    banners: dict[str, str]

    def find(self, pattern: str) -> list[Line]:
        """Top-level lines matching the regex. Anchor with ^ to match whole commands."""
        rx = re.compile(pattern)
        return [line for line in self.lines if rx.search(line.text)]

    def has(self, pattern: str) -> bool:
        return bool(self.find(pattern))


def parse(text: str) -> Config:
    root = Line("", 0)
    stack: list[tuple[int, Line]] = [(-1, root)]  # (indent, line) for the current branch
    banners: dict[str, str] = {}
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        number = i + 1
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))

        banner = _BANNER.match(stripped) if indent == 0 else None
        if banner:
            kind, delim, rest = banner.groups()
            if delim in rest:  # opens and closes on one line
                body = [rest.split(delim, 1)[0]]
            else:  # read until the line holding the closing delimiter
                body = [rest]
                while i < len(lines) and delim not in lines[i]:
                    body.append(lines[i].rstrip())
                    i += 1
                if i < len(lines):
                    body.append(lines[i].split(delim, 1)[0].rstrip())
                    i += 1
            banners[kind] = "\n".join(body).strip()
            root.children.append(Line(f"banner {kind}", number))
            stack = [(-1, root)]
            continue

        while stack[-1][0] >= indent:
            stack.pop()
        node = Line(stripped, number)
        stack[-1][1].children.append(node)
        stack.append((indent, node))
    return Config(lines=root.children, banners=banners)
