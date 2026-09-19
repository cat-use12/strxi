"""``strix retest`` — remediation lifecycle management CLI.

Commands
--------
strix retest status <run-name>
    Show remediation status for every finding in a run.

strix retest set <run-name> <finding-id> <status> [--note "..."] [--by "name"]
    Transition a finding to a new remediation status.
    Valid statuses: open, in_progress, pending_retest, verified_fixed, wont_fix

strix retest summary <run-name>
    Print a one-line summary: totals by status and remediation rate.

Examples
--------
    strix retest status my-scan-run
    strix retest set my-scan-run vuln-0003 in_progress --note "Dev assigned to Alice"
    strix retest set my-scan-run vuln-0003 pending_retest --by "alice@example.com"
    strix retest set my-scan-run vuln-0003 verified_fixed --note "PR #42 merged, re-tested manually"
    strix retest summary my-scan-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text


_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}

_STATUS_STYLES: dict[str, str] = {
    "open": "red",
    "in_progress": "yellow",
    "pending_retest": "cyan",
    "verified_fixed": "bold green",
    "wont_fix": "dim",
}


def _load_vulnerabilities(run_name: str) -> list[dict]:
    """Load vulnerabilities.json from a strix run directory."""
    run_dir = Path("strix_runs") / run_name
    vuln_path = run_dir / "vulnerabilities.json"
    if not vuln_path.exists():
        raise FileNotFoundError(f"Run not found: {run_dir} (missing vulnerabilities.json)")
    data = json.loads(vuln_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"vulnerabilities.json in {run_dir} is not a list")
    return data


def _save_vulnerabilities(run_name: str, vulns: list[dict]) -> None:
    run_dir = Path("strix_runs") / run_name
    vuln_path = run_dir / "vulnerabilities.json"
    vuln_path.write_text(
        json.dumps(vulns, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def _cmd_status(args: argparse.Namespace, console: Console) -> int:
    try:
        vulns = _load_vulnerabilities(args.run_name)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/] {e}")
        return 1

    if not vulns:
        console.print("[dim]No findings in this run.[/dim]")
        return 0

    table = Table(title=f"Findings — {args.run_name}", show_lines=False, expand=True)
    table.add_column("ID", style="dim", no_wrap=True, width=12)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=6)
    table.add_column("Title", ratio=4)
    table.add_column("Remediation Status", width=18)
    table.add_column("Updated", width=22)

    for v in sorted(vulns, key=lambda x: (x.get("cvss") or 0), reverse=True):
        vid = str(v.get("id") or "—")
        sev = str(v.get("severity") or "info").lower()
        cvss = f"{v.get('cvss', 0):.1f}" if v.get("cvss") is not None else "—"
        title = str(v.get("title") or "Untitled")[:80]
        rem_status = str(v.get("remediation_status") or "open").lower()
        updated = str(v.get("remediation_updated_at") or v.get("timestamp") or "—")

        table.add_row(
            vid,
            Text(sev, style=_SEVERITY_STYLES.get(sev, "")),
            cvss,
            title,
            Text(rem_status.replace("_", " "), style=_STATUS_STYLES.get(rem_status, "")),
            updated,
        )

    console.print(table)
    return 0


def _cmd_set(args: argparse.Namespace, console: Console) -> int:
    try:
        vulns = _load_vulnerabilities(args.run_name)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/] {e}")
        return 1

    from strix.report.state import ReportState

    target = next((v for v in vulns if v.get("id") == args.finding_id), None)
    if target is None:
        console.print(f"[bold red]Error:[/] Finding '{args.finding_id}' not found in run '{args.run_name}'")
        available = [v.get("id") for v in vulns]
        console.print(f"Available IDs: {available}")
        return 1

    new_status = args.status.strip().lower()
    current = str(target.get("remediation_status") or "open").lower()
    allowed = ReportState._REMEDIATION_TRANSITIONS.get(current, [])

    if new_status not in allowed:
        console.print(
            f"[bold red]Invalid transition:[/] '{current}' → '{new_status}'\n"
            f"Allowed from '{current}': {allowed}"
        )
        return 1

    from datetime import UTC, datetime

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    event: dict = {"from": current, "to": new_status, "timestamp": timestamp}
    if getattr(args, "note", None):
        event["note"] = args.note.strip()
    if getattr(args, "by", None):
        event["updated_by"] = args.by.strip()

    history = list(target.get("remediation_history") or [])
    history.append(event)
    target["remediation_status"] = new_status
    target["remediation_history"] = history
    target["remediation_updated_at"] = timestamp

    _save_vulnerabilities(args.run_name, vulns)

    status_style = _STATUS_STYLES.get(new_status, "")
    console.print(
        f"[bold]{args.finding_id}[/] "
        f"[dim]{current}[/dim] → "
        f"[{status_style}]{new_status.replace('_', ' ')}[/{status_style}]  "
        f"[dim]{timestamp}[/dim]"
    )
    if getattr(args, "note", None):
        console.print(f"  Note: {args.note}")
    return 0


def _cmd_summary(args: argparse.Namespace, console: Console) -> int:
    try:
        vulns = _load_vulnerabilities(args.run_name)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/] {e}")
        return 1

    counts: dict[str, int] = {
        "open": 0, "in_progress": 0, "pending_retest": 0, "verified_fixed": 0, "wont_fix": 0
    }
    for v in vulns:
        s = str(v.get("remediation_status") or "open").lower()
        counts[s] = counts.get(s, 0) + 1

    total = len(vulns)
    fixed = counts.get("verified_fixed", 0)
    rate = round(fixed / total * 100, 1) if total else 0.0

    console.print(f"\n[bold]Remediation summary — {args.run_name}[/bold]")
    console.print(f"  Total findings   : {total}")
    for status, count in counts.items():
        style = _STATUS_STYLES.get(status, "")
        label = status.replace("_", " ").ljust(16)
        bar = "█" * count
        console.print(f"  [{style}]{label}[/{style}]: {count:3d}  {bar}")
    console.print(f"\n  Remediation rate : [bold green]{rate}%[/bold green] ({fixed}/{total} fixed)")
    return 0


def run_retest(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix retest",
        description="Manage remediation lifecycle for Strix findings.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = sub.add_parser("status", help="Show remediation status for all findings in a run")
    p_status.add_argument("run_name", help="Run name (directory under ./strix_runs/)")

    # set
    p_set = sub.add_parser("set", help="Transition a finding to a new remediation status")
    p_set.add_argument("run_name", help="Run name")
    p_set.add_argument("finding_id", help="Finding ID, e.g. vuln-0001")
    p_set.add_argument(
        "status",
        choices=["open", "in_progress", "pending_retest", "verified_fixed", "wont_fix"],
        help="New status",
    )
    p_set.add_argument("--note", default=None, help="Optional note about the transition")
    p_set.add_argument("--by", default=None, help="Person making the transition (name or email)")

    # summary
    p_sum = sub.add_parser("summary", help="Print a remediation rate summary for a run")
    p_sum.add_argument("run_name", help="Run name")

    args = parser.parse_args(argv)
    console = Console()

    dispatch = {
        "status": _cmd_status,
        "set": _cmd_set,
        "summary": _cmd_summary,
    }
    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        return 2
    return fn(args, console)
