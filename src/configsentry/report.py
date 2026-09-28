"""Show results three ways: a terminal table, JSON for machines, and an HTML report for people."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape
from rich.console import Console
from rich.table import Table

from configsentry.engine import AuditResult

console = Console()


def print_result(result: AuditResult) -> None:
    title = f"{result.device}: {result.passed_count}/{len(result.results)} rules passing ({result.duration_s} s)"
    table = Table(title=title, title_justify="left", show_lines=False)
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Check")
    table.add_column("Result", no_wrap=True)
    table.add_column("Evidence")
    for r in result.results:
        verdict = "[green]PASS[/]" if r.passed else f"[red]FAIL[/] ({r.severity})"
        table.add_row(r.rule, r.title, verdict, "; ".join(r.problems[:2]))
    console.print(table)
    if result.drift is not None:
        console.print(f"Drift vs baseline: +{len(result.drift.added)} / -{len(result.drift.removed)} lines")


def write_json(results: list[AuditResult], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "latest.json"
    path.write_text(json.dumps([asdict(r) for r in results], indent=2))
    return path


def write_html(results: list[AuditResult], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(autoescape=select_autoescape(default=True))
    template = env.from_string((files("configsentry") / "templates" / "report.html.j2").read_text())
    path = out_dir / "latest.html"
    audited = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    path.write_text(template.render(results=results, audited=audited))
    return path
