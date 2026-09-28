"""ConfigSentry command line: audit, baseline, selftest, timing, rules."""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from configsentry.drift import compare, normalize
from configsentry.engine import SEVERITY_RANK, audit_text
from configsentry.faults import load_faults, selftest
from configsentry.redact import redact_text
from configsentry.report import print_result, write_html, write_json
from configsentry.rules import RULES

console = Console()
Target = tuple[str, str, str, dict, float]  # name, config text, source, facts, perf_counter at start


def _key() -> bytes:
    return os.environ.get("CONFIGSENTRY_FINGERPRINT_KEY", "").encode()


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[max(math.ceil(pct / 100 * len(ordered)), 1) - 1]


def _collect_targets(args) -> tuple[list[Target], list[str]]:
    if args.file:
        return [(Path(p).stem, Path(p).read_text(), "file", {}, time.perf_counter()) for p in args.file], []

    from configsentry.collect import collect, load_inventory  # only live audits need SSH

    devices = load_inventory(Path(args.inventory))
    if args.device:
        devices = [d for d in devices if d.name in args.device]

    def one(device) -> Target:
        started = time.perf_counter()
        running, facts = collect(device)
        return device.name, running, "ssh", facts, started

    targets, errors = [], []
    with ThreadPoolExecutor(max_workers=min(8, len(devices) or 1)) as pool:
        futures = {pool.submit(one, d): d for d in devices}
        for future, device in futures.items():
            try:
                targets.append(future.result())
            except Exception as exc:  # one unreachable device shouldn't stop the others
                errors.append(f"{device.name}: {exc}")
                console.print(f"[red]{device.name}: {exc}[/]")
    return targets, errors


def run_audit(args) -> int:
    targets, errors = _collect_targets(args)
    results = []
    for name, text, source, facts, started in targets:
        result = audit_text(text, name, source, facts, started)
        baseline = Path(args.baselines) / f"{name}.cfg"
        if baseline.exists():
            if _key():
                result.drift = compare(baseline.read_text(), text, _key(), name)
            else:
                console.print("[yellow]Skipping drift: set CONFIGSENTRY_FINGERPRINT_KEY in .env[/]")
        if source == "ssh":  # keep a redacted copy for offline audits and the MCP server
            Path(args.configs).mkdir(parents=True, exist_ok=True)
            (Path(args.configs) / f"{name}.cfg").write_text(redact_text(text))
        results.append(result)
        print_result(result)
    if results:
        paths = write_json(results, Path(args.reports)), write_html(results, Path(args.reports))
        console.print(f"Reports: {paths[0]} and {paths[1]}")
    if errors:
        return 1
    threshold = SEVERITY_RANK.get(args.fail_on, 0)
    if threshold and any(r.worst_failure() >= threshold for r in results):
        return 2
    return 0


def _add_audit(sub) -> None:
    p = sub.add_parser("audit", help="audit devices over SSH, or saved config files")
    p.add_argument("--inventory", default="inventory.yaml")
    p.add_argument("--device", nargs="*", help="only these inventory devices")
    p.add_argument("--file", nargs="*", help="audit saved config files instead of devices")
    p.add_argument("--baselines", default="baselines")
    p.add_argument("--configs", default="configs", help="where redacted copies of live configs go")
    p.add_argument("--reports", default="reports")
    p.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high"],
        default="none",
        help="exit 2 if any failed rule is at least this severe (for CI gates)",
    )
    p.set_defaults(func=run_audit)


def run_baseline(args) -> int:
    if not _key():
        console.print("[red]Set CONFIGSENTRY_FINGERPRINT_KEY in .env first (see .env.example).[/]")
        return 1
    if args.file:
        name, text = args.name or Path(args.file).stem, Path(args.file).read_text()
    else:
        from configsentry.collect import collect, load_inventory

        device = next(d for d in load_inventory(Path(args.inventory)) if d.name == args.device)
        name, (text, _facts) = device.name, collect(device)
    path = Path(args.baselines) / f"{name}.cfg"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(normalize(text, _key())) + "\n")
    console.print(f"Saved {path}. Review it, then: git add {path} && git commit -m 'baseline: {name}'")
    return 0


def _add_baseline(sub) -> None:
    p = sub.add_parser("baseline", help="save the approved config for a device (commit it to Git)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--device")
    group.add_argument("--file")
    p.add_argument("--name", help="baseline name when using --file")
    p.add_argument("--inventory", default="inventory.yaml")
    p.add_argument("--baselines", default="baselines")
    p.set_defaults(func=run_baseline)


def run_selftest(args) -> int:
    golden_failures, rows = selftest(Path(args.golden).read_text(), load_faults(Path(args.faults)))
    detected = sum(r.detected for r in rows)
    noisy = sum(bool(r.false_positives) for r in rows)
    uncovered = sorted({r.id for r in RULES} - {r.rule for r in rows})
    if args.markdown:
        print("| Rule | Seeded fault | Caught | Other rules that fired |\n| --- | --- | --- | --- |")
        for r in rows:
            print(f"| {r.rule} | {r.why} | {'yes' if r.detected else 'NO'} | {', '.join(r.false_positives) or '-'} |")
        print()
    else:
        table = Table(title="Seeded-fault self-test", title_justify="left")
        for column in ("Rule", "Seeded fault", "Caught", "Other rules that fired"):
            table.add_column(column)
        for r in rows:
            table.add_row(
                r.rule, r.why, "[green]yes[/]" if r.detected else "[red]NO[/]", ", ".join(r.false_positives) or "-"
            )
        console.print(table)
    summary = (
        f"Caught {detected}/{len(rows)} seeded faults, {noisy} with false positives, "
        f"golden config failures: {len(golden_failures)}, rules with no fault: {', '.join(uncovered) or 'none'}"
    )
    print(f"**{summary}**" if args.markdown else summary)
    ok = detected == len(rows) and not noisy and not golden_failures and not uncovered
    return 0 if ok else 1


def _add_selftest(sub) -> None:
    p = sub.add_parser("selftest", help="prove every rule catches its seeded faults")
    p.add_argument("--golden", default="tests/fixtures/golden.cfg")
    p.add_argument("--faults", default="tests/fixtures/faults.yaml")
    p.add_argument("--markdown", action="store_true", help="Markdown output (GitHub job summary)")
    p.set_defaults(func=run_selftest)


def run_timing(args) -> int:
    from configsentry.collect import collect, load_inventory

    device = next(d for d in load_inventory(Path(args.inventory)) if d.name == args.device)
    durations = []
    for i in range(args.runs):
        started = time.perf_counter()
        running, facts = collect(device)
        audit_text(running, device.name, "ssh", facts, started)
        durations.append(round(time.perf_counter() - started, 3))
        console.print(f"run {i + 1}/{args.runs}: {durations[-1]:.2f} s")
    stats = {
        "device": device.name,
        "runs": len(durations),
        "median_s": round(statistics.median(durations), 2),
        "p95_s": round(_percentile(durations, 95), 2),
        "max_s": round(max(durations), 2),
        "durations_s": durations,
    }
    Path("results").mkdir(exist_ok=True)
    Path(f"results/timing-{device.name}.json").write_text(json.dumps(stats, indent=2))
    console.print(
        f"{device.name}: median {stats['median_s']} s, p95 {stats['p95_s']} s over {len(durations)} runs "
        "(SSH login + show commands + 15 rules)"
    )
    return 0


def _add_timing(sub) -> None:
    p = sub.add_parser("timing", help="time N full audits of one device")
    p.add_argument("--device", required=True)
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--inventory", default="inventory.yaml")
    p.set_defaults(func=run_timing)


def run_rules(args) -> int:
    if args.checklist:
        print("# Manual audit checklist\n")
        print("Timed from `show running-config` until every box is ticked.\n")
        for r in RULES:
            looks_like = " / ".join(line.strip() for line in r.fix.splitlines())
            print(f"- [ ] {r.id} {r.title}. Compliant looks like: `{looks_like}`")
        return 0
    table = Table(title="ConfigSentry rules", title_justify="left")
    for column in ("Rule", "Check", "Severity", "CIS Cisco IOS XE 17.x v2.1.0"):
        table.add_column(column)
    for r in RULES:
        table.add_row(r.id, r.title, r.severity, r.cis)
    console.print(table)
    return 0


def _add_rules(sub) -> None:
    p = sub.add_parser("rules", help="list the rules and their CIS mapping")
    p.add_argument("--checklist", action="store_true", help="Markdown checklist for timing a manual audit")
    p.set_defaults(func=run_rules)


COMMANDS = [_add_audit, _add_baseline, _add_selftest, _add_timing, _add_rules]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configsentry", description="Compliance and drift auditing for IOS-XE and Meraki"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for add in COMMANDS:
        add(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
