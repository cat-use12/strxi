"""Target authorization gate for Strix scans.

Every URL, domain, IP, or local path that Strix tests must either:
  1. Match an entry in an authorized-scopes file (when one is configured), OR
  2. Be a local path when no scope file is configured (warn-only mode).

Scope file format (YAML):
  version: 1
  scopes:
    - target: "https://example.com"
      authorized_by: "Alice <alice@example.com>"
      issued_at: "2026-09-17T00:00:00Z"
      expires_at: null        # optional ISO-8601 or null
      scope_notes: "Full black-box pentest, no DoS"
      signature: "<hmac-sha256-hex>"  # computed with sign_scope_entry()

Generate a signature for a scope entry:
  from strix.core.authorization import sign_scope_entry
  sig = sign_scope_entry(entry, secret_key="your-secret")

The HMAC covers: target + authorized_by + issued_at + (expires_at or "") — in that
order, joined by newlines. This binds every identity-carrying field together so
tampering any field invalidates the signature.

Set STRIX_AUTH_SCOPE_KEY to your HMAC secret (32+ chars recommended).
Set STRIX_AUTH_SCOPE_FILE to the path of your scope file (default: ~/.strix/authorized-scopes.yaml).
Set STRIX_AUTH_ENFORCE=1 to treat missing/unmatched authorization as a hard error;
without it the gate emits a warning and continues (warn-only mode, safe for dev).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

_SCOPE_FILE_ENV = "STRIX_AUTH_SCOPE_FILE"
_SCOPE_KEY_ENV = "STRIX_AUTH_SCOPE_KEY"
_ENFORCE_ENV = "STRIX_AUTH_ENFORCE"

_DEFAULT_SCOPE_PATH = Path.home() / ".strix" / "authorized-scopes.yaml"

_SCOPE_HMAC_SEP = "\n"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AuthorizedScope:
    """One entry in the authorized-scopes file."""

    target: str
    authorized_by: str
    issued_at: str
    expires_at: str | None = None
    scope_notes: str = ""
    signature: str = ""

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(UTC) > exp
        except ValueError:
            logger.warning("Could not parse expires_at %r; treating as not expired", self.expires_at)
            return False

    def hmac_payload(self) -> str:
        return _SCOPE_HMAC_SEP.join([
            self.target,
            self.authorized_by,
            self.issued_at,
            self.expires_at or "",
        ])


@dataclass
class AuthorizationResult:
    authorized: bool
    target: str
    matched_scope: AuthorizedScope | None = None
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------


def sign_scope_entry(entry: AuthorizedScope, *, secret_key: str) -> str:
    """Compute the HMAC-SHA256 hex signature for a scope entry."""
    payload = entry.hmac_payload().encode("utf-8")
    key = secret_key.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_scope_signature(entry: AuthorizedScope, *, secret_key: str) -> bool:
    """Return True when the stored signature matches the computed one."""
    if not entry.signature:
        return False
    expected = sign_scope_entry(entry, secret_key=secret_key)
    return hmac.compare_digest(expected, entry.signature.lower())


# ---------------------------------------------------------------------------
# Scope file loading
# ---------------------------------------------------------------------------


def _scope_file_path() -> Path | None:
    env_path = os.environ.get(_SCOPE_FILE_ENV, "").strip()
    if env_path:
        return Path(env_path).expanduser()
    if _DEFAULT_SCOPE_PATH.exists():
        return _DEFAULT_SCOPE_PATH
    return None


def _load_scope_file(path: Path) -> list[AuthorizedScope]:
    """Parse a YAML scope file. Returns empty list on parse failure."""
    try:
        import yaml  # pyyaml is a Strix dependency
    except ImportError:
        logger.error("pyyaml not installed; cannot load scope file %s", path)
        return []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Failed to parse scope file %s: %s", path, exc)
        return []

    if not isinstance(raw, dict):
        logger.error("Scope file %s must be a YAML mapping; got %s", path, type(raw).__name__)
        return []

    if raw.get("version") != 1:
        logger.warning("Scope file %s: unknown version %r", path, raw.get("version"))

    entries: list[AuthorizedScope] = []
    for i, item in enumerate(raw.get("scopes", []) or []):
        if not isinstance(item, dict):
            logger.warning("Scope file entry #%d is not a mapping; skipping", i)
            continue
        target = str(item.get("target") or "").strip()
        authorized_by = str(item.get("authorized_by") or "").strip()
        issued_at = str(item.get("issued_at") or "").strip()
        if not target or not authorized_by or not issued_at:
            logger.warning(
                "Scope entry #%d missing required fields (target/authorized_by/issued_at); skipping",
                i,
            )
            continue
        entries.append(AuthorizedScope(
            target=target,
            authorized_by=authorized_by,
            issued_at=issued_at,
            expires_at=str(item.get("expires_at") or "") or None,
            scope_notes=str(item.get("scope_notes") or ""),
            signature=str(item.get("signature") or ""),
        ))

    logger.debug("Loaded %d scope entries from %s", len(entries), path)
    return entries


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str:
    """Normalize a target string for comparison."""
    return target.strip().rstrip("/")


def _extract_host(target: str) -> str | None:
    """Return the hostname/IP of a URL or bare domain/IP target."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname or None
    # bare domain or IP
    parts = t.split("/")
    return parts[0].split(":")[0] if parts else None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_matches(host: str, pattern: str) -> bool:
    """True when *host* matches *pattern*.

    Supports:
    - Exact match: example.com
    - Wildcard subdomain: *.example.com → any subdomain of example.com
    - CIDR for IPs: 192.168.1.0/24
    - fnmatch glob: *.staging.example.*
    """
    host = host.lower().lstrip("www.")
    pattern_h = pattern.lower().lstrip("www.")

    # CIDR check for IPs
    if _is_ip(host):
        try:
            net = ipaddress.ip_network(pattern_h, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            pass

    # Exact match
    if host == pattern_h:
        return True

    # fnmatch glob (e.g. *.example.com)
    return fnmatch(host, pattern_h)


def _target_matches_scope(target: str, scope: AuthorizedScope) -> bool:
    """Return True when *target* is covered by *scope*.

    Matching rules (evaluated in order, first match wins):
    1. Normalized exact string match.
    2. Scope target is a URL prefix and the tested target starts with it.
    3. Host-level match (supports wildcards, CIDR for IPs).
    4. Local path: tested target is under the scope target directory.
    5. fnmatch glob on the full target string.
    """
    t = _normalize_target(target)
    s = _normalize_target(scope.target)

    # 1. Exact
    if t == s:
        return True

    # 4. Local path containment
    try:
        tp = Path(t).resolve()
        sp = Path(s).resolve()
        if tp == sp or str(tp).startswith(str(sp) + os.sep):
            return True
    except Exception:
        pass

    # 2. URL prefix
    if "://" in s and t.startswith(s):
        return True

    # 3. Host-level match
    t_host = _extract_host(t)
    s_host = _extract_host(s)
    if t_host and s_host and _domain_matches(t_host, s_host):
        # Also check that the URL scheme matches when both are URLs
        if "://" in t and "://" in s:
            if urlparse(t).scheme != urlparse(s).scheme:
                return False
        return True

    # 5. fnmatch on full target
    return fnmatch(t, s)


# ---------------------------------------------------------------------------
# Authorization checker
# ---------------------------------------------------------------------------


def check_target_authorization(
    target: str,
    scopes: list[AuthorizedScope],
    *,
    secret_key: str | None = None,
    verify_signatures: bool = True,
) -> AuthorizationResult:
    """Check whether *target* is covered by any scope entry.

    When *verify_signatures* is True and *secret_key* is provided, every
    matching scope's signature must also verify. Expired scopes are rejected.
    """
    warnings: list[str] = []

    matching: list[AuthorizedScope] = [
        s for s in scopes if _target_matches_scope(target, s)
    ]

    if not matching:
        return AuthorizationResult(
            authorized=False,
            target=target,
            reason=(
                f"No authorized scope covers target '{target}'. "
                "Add an entry to your authorized-scopes.yaml file."
            ),
        )

    for scope in matching:
        if scope.is_expired():
            warnings.append(
                f"Scope for '{scope.target}' authorized by {scope.authorized_by} "
                f"expired at {scope.expires_at}; skipping."
            )
            continue

        if verify_signatures and secret_key:
            if not scope.signature:
                warnings.append(
                    f"Scope for '{scope.target}' has no signature; "
                    "set STRIX_AUTH_SCOPE_KEY and re-sign it with sign_scope_entry()."
                )
            elif not verify_scope_signature(scope, secret_key=secret_key):
                warnings.append(
                    f"Scope signature mismatch for '{scope.target}'; "
                    "the entry may have been tampered with. Skipping."
                )
                continue

        return AuthorizationResult(
            authorized=True,
            target=target,
            matched_scope=scope,
            warnings=warnings,
        )

    return AuthorizationResult(
        authorized=False,
        target=target,
        reason=(
            f"All matching scopes for '{target}' are expired or have invalid signatures. "
            "Check your authorized-scopes.yaml and STRIX_AUTH_SCOPE_KEY."
        ),
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Public gate — called by the runner
# ---------------------------------------------------------------------------


class AuthorizationError(Exception):
    """Raised when a target is not authorized and enforcement is enabled."""


def enforce_authorization(
    targets: list[str],
    *,
    scope_file: Path | None = None,
    enforce: bool | None = None,
) -> list[AuthorizationResult]:
    """Check authorization for every target and enforce or warn.

    Returns the list of AuthorizationResult objects for all targets.

    Enforcement behavior:
    - enforce=True or STRIX_AUTH_ENFORCE=1: raise AuthorizationError on first
      unauthorized target.
    - enforce=False/None (default): emit a warning and continue.

    When no scope file is configured:
    - Local paths are implicitly allowed (developer convenience).
    - URLs/domains/IPs emit a warning reminding the user to add a scope file.
    """
    if enforce is None:
        enforce = os.environ.get(_ENFORCE_ENV, "").strip() in ("1", "true", "yes")

    # Resolve scope file
    resolved_scope_file = scope_file or _scope_file_path()
    secret_key = os.environ.get(_SCOPE_KEY_ENV, "").strip() or None

    scopes: list[AuthorizedScope] = []
    if resolved_scope_file is not None:
        if not resolved_scope_file.exists():
            msg = f"Authorization scope file not found: {resolved_scope_file}"
            if enforce:
                raise AuthorizationError(msg)
            logger.warning("%s — running without scope validation", msg)
        else:
            scopes = _load_scope_file(resolved_scope_file)
            if not scopes:
                msg = f"Authorization scope file {resolved_scope_file} loaded but contains no entries"
                if enforce:
                    raise AuthorizationError(msg)
                logger.warning(msg)

    results: list[AuthorizationResult] = []

    for target in targets:
        # When no scope file is configured, local paths get an implicit pass
        if not scopes:
            is_local = not target.startswith(("http://", "https://")) and not re.match(
                r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$", target.split("/")[0]
            )
            if is_local:
                results.append(AuthorizationResult(
                    authorized=True,
                    target=target,
                    reason="Local path — no scope file configured",
                ))
                continue
            else:
                msg = (
                    f"No authorization scope file configured. Testing '{target}' without "
                    "explicit authorization record. Set STRIX_AUTH_SCOPE_FILE or create "
                    f"{_DEFAULT_SCOPE_PATH} with an entry covering this target."
                )
                if enforce:
                    raise AuthorizationError(msg)
                logger.warning(msg)
                results.append(AuthorizationResult(
                    authorized=True,
                    target=target,
                    reason="No scope file — warn-only mode",
                    warnings=[msg],
                ))
                continue

        result = check_target_authorization(
            target,
            scopes,
            secret_key=secret_key,
            verify_signatures=bool(secret_key),
        )
        for w in result.warnings:
            logger.warning(w)

        results.append(result)

        if not result.authorized:
            msg = f"[AUTHORIZATION] {result.reason}"
            if enforce:
                raise AuthorizationError(msg)
            logger.warning(msg)

    return results


# ---------------------------------------------------------------------------
# Scope file scaffolding helper
# ---------------------------------------------------------------------------


def _scope_template(targets: list[str], authorized_by: str) -> dict[str, Any]:
    """Return a starter scope dict for the given targets."""
    import yaml  # pyyaml

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    scopes = [
        {
            "target": t,
            "authorized_by": authorized_by,
            "issued_at": now,
            "expires_at": None,
            "scope_notes": "Authorized for security testing",
            "signature": "",
        }
        for t in targets
    ]
    return {"version": 1, "scopes": scopes}


def create_scope_file(
    targets: list[str],
    authorized_by: str,
    path: Path | None = None,
    *,
    secret_key: str | None = None,
) -> Path:
    """Write a new authorized-scopes.yaml with entries for *targets*.

    When *secret_key* is provided each entry is HMAC-signed.
    Returns the path of the written file.
    """
    import yaml

    out_path = path or _DEFAULT_SCOPE_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = _scope_template(targets, authorized_by)

    if secret_key:
        for entry_dict in data["scopes"]:
            scope = AuthorizedScope(
                target=entry_dict["target"],
                authorized_by=entry_dict["authorized_by"],
                issued_at=entry_dict["issued_at"],
                expires_at=entry_dict.get("expires_at"),
            )
            entry_dict["signature"] = sign_scope_entry(scope, secret_key=secret_key)

    out_path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")
    logger.info("Wrote authorization scope file: %s (%d entries)", out_path, len(data["scopes"]))
    return out_path
