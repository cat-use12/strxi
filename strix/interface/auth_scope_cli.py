"""``strix auth-scope`` — manage the authorized-scopes.yaml file.

Commands
--------
strix auth-scope init --target <url> [--target ...] --authorized-by "Name <email>"
    Create (or append to) the authorized-scopes file.

strix auth-scope list
    Show all entries in the current scope file.

strix auth-scope verify --target <url>
    Check whether a target would be authorized under the current scope file.

strix auth-scope sign
    (Re-)sign all entries in the scope file using STRIX_AUTH_SCOPE_KEY.

Examples
--------
    export STRIX_AUTH_SCOPE_KEY="mysecretkey32chars"
    strix auth-scope init --target https://staging.example.com --authorized-by "Alice <alice@co.com>"
    strix auth-scope list
    strix auth-scope verify --target https://staging.example.com
    strix auth-scope sign
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table


def _default_scope_path() -> Path:
    return Path.home() / ".strix" / "authorized-scopes.yaml"


def _scope_file_path() -> Path:
    env = os.environ.get("STRIX_AUTH_SCOPE_FILE", "").strip()
    return Path(env).expanduser() if env else _default_scope_path()


def _cmd_init(args: argparse.Namespace, console: Console) -> int:
    from strix.core.authorization import create_scope_file

    targets = args.target
    if not targets:
        console.print("[bold red]Error:[/] At least one --target is required")
        return 1

    authorized_by = (args.authorized_by or "").strip()
    if not authorized_by:
        console.print("[bold red]Error:[/] --authorized-by is required")
        return 1

    scope_file = _scope_file_path()
    secret_key = os.environ.get("STRIX_AUTH_SCOPE_KEY", "").strip() or None

    if scope_file.exists() and not getattr(args, "force", False):
        # Append to existing file instead of overwriting
        import yaml

        existing = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
        existing_scopes: list[dict] = existing.get("scopes") or []
        existing_targets = {str(s.get("target") or "") for s in existing_scopes}

        from datetime import UTC, datetime

        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        added = 0
        for t in targets:
            if t in existing_targets:
                console.print(f"[dim]Already authorized: {t}[/dim]")
                continue
            entry = {
                "target": t,
                "authorized_by": authorized_by,
                "issued_at": now,
                "expires_at": None,
                "scope_notes": "Authorized for security testing",
                "signature": "",
            }
            if secret_key:
                from strix.core.authorization import AuthorizedScope, sign_scope_entry
                scope = AuthorizedScope(
                    target=t,
                    authorized_by=authorized_by,
                    issued_at=now,
                )
                entry["signature"] = sign_scope_entry(scope, secret_key=secret_key)
            existing_scopes.append(entry)
            added += 1

        existing["scopes"] = existing_scopes
        scope_file.write_text(
            yaml.dump(existing, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        console.print(f"[green]Added {added} new scope(s) to {scope_file}[/green]")
    else:
        new_path = create_scope_file(targets, authorized_by, scope_file, secret_key=secret_key)
        console.print(f"[green]Created authorization scope file: {new_path}[/green]")

    if not secret_key:
        console.print(
            "[yellow]Tip:[/yellow] Set STRIX_AUTH_SCOPE_KEY to a strong secret and run "
            "'strix auth-scope sign' to HMAC-sign the entries."
        )
    return 0


def _cmd_list(args: argparse.Namespace, console: Console) -> int:
    scope_file = _scope_file_path()
    if not scope_file.exists():
        console.print(f"[dim]No scope file at {scope_file}[/dim]")
        return 0

    import yaml

    data = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
    scopes = data.get("scopes") or []

    if not scopes:
        console.print("[dim]Scope file exists but contains no entries.[/dim]")
        return 0

    table = Table(title=f"Authorized scopes — {scope_file}", show_lines=True)
    table.add_column("Target", ratio=3)
    table.add_column("Authorized By", ratio=2)
    table.add_column("Issued At", width=22)
    table.add_column("Expires", width=22)
    table.add_column("Signed", width=7)
    table.add_column("Notes", ratio=2)

    for s in scopes:
        signed = "[green]yes[/green]" if s.get("signature") else "[dim]no[/dim]"
        expires = str(s.get("expires_at") or "never")
        table.add_row(
            str(s.get("target") or "—"),
            str(s.get("authorized_by") or "—"),
            str(s.get("issued_at") or "—"),
            expires,
            signed,
            str(s.get("scope_notes") or "—"),
        )

    console.print(table)
    return 0


def _cmd_verify(args: argparse.Namespace, console: Console) -> int:
    from strix.core.authorization import _load_scope_file, check_target_authorization

    scope_file = _scope_file_path()
    if not scope_file.exists():
        console.print(f"[yellow]No scope file at {scope_file} — target would be warn-only[/yellow]")
        return 0

    scopes = _load_scope_file(scope_file)
    secret_key = os.environ.get("STRIX_AUTH_SCOPE_KEY", "").strip() or None

    for target in args.target:
        result = check_target_authorization(
            target, scopes, secret_key=secret_key, verify_signatures=bool(secret_key)
        )
        if result.authorized:
            scope = result.matched_scope
            auth_by = scope.authorized_by if scope else "—"
            console.print(f"[green]AUTHORIZED[/green]  {target}  (authorized by {auth_by})")
        else:
            console.print(f"[red]NOT AUTHORIZED[/red]  {target}  — {result.reason}")
        for w in result.warnings:
            console.print(f"  [yellow]Warning:[/yellow] {w}")

    return 0


def _cmd_sign(args: argparse.Namespace, console: Console) -> int:
    secret_key = os.environ.get("STRIX_AUTH_SCOPE_KEY", "").strip()
    if not secret_key:
        console.print("[bold red]Error:[/] STRIX_AUTH_SCOPE_KEY is not set")
        return 1

    scope_file = _scope_file_path()
    if not scope_file.exists():
        console.print(f"[bold red]Error:[/] No scope file at {scope_file}")
        return 1

    import yaml

    from strix.core.authorization import AuthorizedScope, sign_scope_entry

    data = yaml.safe_load(scope_file.read_text(encoding="utf-8")) or {}
    scopes = data.get("scopes") or []
    signed = 0
    for s in scopes:
        entry = AuthorizedScope(
            target=str(s.get("target") or ""),
            authorized_by=str(s.get("authorized_by") or ""),
            issued_at=str(s.get("issued_at") or ""),
            expires_at=str(s.get("expires_at") or "") or None,
        )
        s["signature"] = sign_scope_entry(entry, secret_key=secret_key)
        signed += 1

    scope_file.write_text(
        yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8"
    )
    console.print(f"[green]Signed {signed} scope entry(s) in {scope_file}[/green]")
    return 0


def run_auth_scope(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix auth-scope",
        description="Manage the authorized-scopes.yaml file for target authorization.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Add authorized targets to the scope file")
    p_init.add_argument("--target", action="append", required=True, metavar="URL",
                        help="Target URL/domain/IP to authorize (repeatable)")
    p_init.add_argument("--authorized-by", default="", help="Name and email of authorizer")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing file")

    sub.add_parser("list", help="List all entries in the scope file")

    p_verify = sub.add_parser("verify", help="Check if a target is authorized")
    p_verify.add_argument("--target", action="append", required=True, metavar="URL")

    sub.add_parser("sign", help="HMAC-sign all entries using STRIX_AUTH_SCOPE_KEY")

    args = parser.parse_args(argv)
    console = Console()

    dispatch = {
        "init": _cmd_init,
        "list": _cmd_list,
        "verify": _cmd_verify,
        "sign": _cmd_sign,
    }
    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        return 2
    return fn(args, console)
