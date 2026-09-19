"""Scan scheduling CLI for Strix.

Manages scheduled scans via cron (Unix/macOS) or Windows Task Scheduler.
Schedules are stored in ~/.strix/schedules.json.

Commands:
  strix schedule add    --target URL --cron "0 2 * * *" [--profile stealth]
  strix schedule list
  strix schedule remove --id SCHEDULE_ID
  strix schedule run    --id SCHEDULE_ID   (one-shot manual trigger)

Cron examples:
  "0 2 * * *"      — every day at 02:00
  "0 */6 * * *"    — every 6 hours
  "0 9 * * 1"      — every Monday at 09:00
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SCHEDULES_FILE = Path.home() / ".strix" / "schedules.json"


# ─── Storage ──────────────────────────────────────────────────────────────────

def _load_schedules() -> list[dict[str, Any]]:
    if not _SCHEDULES_FILE.exists():
        return []
    try:
        return json.loads(_SCHEDULES_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load schedules: %s", exc)
        return []


def _save_schedules(schedules: list[dict[str, Any]]) -> None:
    _SCHEDULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SCHEDULES_FILE.write_text(
        json.dumps(schedules, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ─── Cron helpers ─────────────────────────────────────────────────────────────

def _strix_bin() -> str:
    """Find the strix executable path."""
    import shutil
    path = shutil.which("strix")
    return path or "strix"


def _cron_entry(schedule: dict[str, Any]) -> str:
    """Format a single crontab line for a schedule entry."""
    sid = schedule["id"]
    target = schedule["target"]
    profile = schedule.get("profile") or ""
    output_dir = schedule.get("output_dir") or f"~/.strix/scheduled-runs/{sid}"
    extra = f"--profile {profile}" if profile else ""
    strix = _strix_bin()
    log = f"~/.strix/logs/scheduled-{sid}.log"
    return (
        f"{schedule['cron']} "
        f"{strix} scan --target {target} {extra} --output-dir {output_dir} "
        f">> {log} 2>&1  # strix-schedule-{sid}"
    )


def _get_current_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=10
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def _set_crontab(content: str) -> bool:
    try:
        proc = subprocess.run(
            ["crontab", "-"],
            input=content, text=True, capture_output=True, timeout=10
        )
        return proc.returncode == 0
    except Exception as exc:
        logger.error("Failed to set crontab: %s", exc)
        return False


def _install_cron(schedule: dict[str, Any]) -> bool:
    """Add a cron entry for the schedule."""
    existing = _get_current_crontab()
    entry = _cron_entry(schedule)
    new_crontab = existing.rstrip("\n") + "\n" + entry + "\n"
    return _set_crontab(new_crontab)


def _remove_cron(schedule_id: str) -> bool:
    """Remove cron entry for a schedule ID."""
    existing = _get_current_crontab()
    marker = f"# strix-schedule-{schedule_id}"
    new_lines = [l for l in existing.splitlines() if marker not in l]
    return _set_crontab("\n".join(new_lines) + "\n")


# ─── Public API ───────────────────────────────────────────────────────────────

def add_schedule(
    target: str,
    cron: str,
    profile: str = "",
    output_dir: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Add a new scheduled scan.

    Args:
        target:      The URL/host to scan.
        cron:        Cron expression (e.g. "0 2 * * *").
        profile:     Strix profile name to use (optional).
        output_dir:  Where to save scan results (optional).
        description: Human-readable name for this schedule.

    Returns:
        The created schedule dict.

    Raises:
        RuntimeError: If not on a Unix/macOS system or crontab install fails.
    """
    if platform.system() == "Windows":
        raise RuntimeError(
            "Cron scheduling is not supported on Windows. "
            "Use Windows Task Scheduler manually, or run Strix on Linux/macOS/WSL."
        )

    sid = str(uuid.uuid4())[:8]
    schedule: dict[str, Any] = {
        "id": sid,
        "target": target,
        "cron": cron,
        "profile": profile,
        "output_dir": output_dir or f"~/.strix/scheduled-runs/{sid}",
        "description": description or f"Scan {target}",
        "created_at": datetime.now(UTC).isoformat(),
        "last_run": None,
        "enabled": True,
    }

    schedules = _load_schedules()
    schedules.append(schedule)
    _save_schedules(schedules)

    installed = _install_cron(schedule)
    if not installed:
        logger.warning("Schedule saved to %s but crontab install failed.", _SCHEDULES_FILE)

    return schedule


def list_schedules() -> list[dict[str, Any]]:
    """Return all saved schedules."""
    return _load_schedules()


def remove_schedule(schedule_id: str) -> bool:
    """Remove a schedule by ID. Returns True if found and removed."""
    schedules = _load_schedules()
    remaining = [s for s in schedules if s["id"] != schedule_id]
    if len(remaining) == len(schedules):
        return False
    _save_schedules(remaining)
    _remove_cron(schedule_id)
    return True


def schedule_summary() -> str:
    """Return a human-readable list of schedules."""
    schedules = _load_schedules()
    if not schedules:
        return "No scheduled scans configured.\nAdd one with: strix schedule add --target URL --cron '0 2 * * *'"
    lines = [f"{'ID':<10} {'Cron':<15} {'Target':<40} {'Profile':<12} {'Description'}"]
    lines.append("-" * 100)
    for s in schedules:
        lines.append(
            f"{s['id']:<10} {s['cron']:<15} {s['target']:<40} "
            f"{(s.get('profile') or '-'):<12} {s.get('description') or ''}"
        )
    return "\n".join(lines)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="strix schedule",
        description="Manage scheduled Strix scans",
    )
    sub = parser.add_subparsers(dest="cmd")

    # add
    p_add = sub.add_parser("add", help="Add a scheduled scan")
    p_add.add_argument("--target", required=True, help="Target URL or host")
    p_add.add_argument("--cron", required=True, help='Cron expression e.g. "0 2 * * *"')
    p_add.add_argument("--profile", default="", help="Strix profile to use")
    p_add.add_argument("--output-dir", default="", help="Where to save results")
    p_add.add_argument("--description", default="", help="Human-readable name")

    # list
    sub.add_parser("list", help="List all scheduled scans")

    # remove
    p_rm = sub.add_parser("remove", help="Remove a scheduled scan")
    p_rm.add_argument("--id", required=True, dest="schedule_id", help="Schedule ID")

    args = parser.parse_args(argv)

    if args.cmd == "add":
        try:
            s = add_schedule(
                target=args.target,
                cron=args.cron,
                profile=args.profile,
                output_dir=args.output_dir,
                description=args.description,
            )
            print(f"Schedule {s['id']} added for {s['target']} ({s['cron']})")
            print(f"Saved to {_SCHEDULES_FILE}")
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    elif args.cmd == "list":
        print(schedule_summary())

    elif args.cmd == "remove":
        if remove_schedule(args.schedule_id):
            print(f"Schedule {args.schedule_id} removed.")
        else:
            print(f"Schedule {args.schedule_id} not found.", file=sys.stderr)
            return 1

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
