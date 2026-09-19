"""Dependency vulnerability checker using the Google OSV.dev public API.

Adapted from NousResearch/hermes-agent tools/osv_check.py (MIT).
Hermes version only blocked MAL-* malware advisories for MCP packages.
Strix version checks ALL CVEs/GHSA for dependency files found on target servers —
useful when the target exposes a requirements.txt, package.json, composer.json, etc.

Zero external dependencies — stdlib only (urllib.request, json, re, threading).
Fail-open: network/parse errors return empty results so scans continue uninterrupted.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
_TIMEOUT = 15

# In-process result cache: (ecosystem, package, version_or_empty) → (expiry_monotonic, vulns)
_CACHE_TTL_S = 3600.0
_CACHE_MAX = 512
_cache: dict[tuple[str, str, str], tuple[float, list[dict[str, Any]]]] = {}
_cache_lock = threading.Lock()


# ─── Cache helpers ───────────────────────────────────────────────────────────

def _cache_get(key: tuple[str, str, str]) -> list[dict[str, Any]] | None:
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.monotonic() < entry[0]:
            return entry[1]
        _cache.pop(key, None)
        return None


def _cache_put(key: tuple[str, str, str], vulns: list[dict[str, Any]]) -> None:
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            now = time.monotonic()
            expired = [k for k, (exp, _) in _cache.items() if exp <= now]
            for k in expired:
                del _cache[k]
            if len(_cache) >= _CACHE_MAX:
                _cache.clear()
        _cache[key] = (time.monotonic() + _CACHE_TTL_S, vulns)


# ─── OSV API ─────────────────────────────────────────────────────────────────

def _query_osv(package: str, ecosystem: str, version: str | None = None) -> list[dict[str, Any]]:
    """Query OSV.dev for all known vulnerabilities for a package. Fail-open on errors."""
    key = (ecosystem, package, version or "")
    cached = _cache_get(key)
    if cached is not None:
        return cached

    payload: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    req = urllib.request.Request(
        _OSV_ENDPOINT,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "strix-osv-checker/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            result: dict[str, Any] = json.loads(resp.read())
        vulns: list[dict[str, Any]] = result.get("vulns") or []
        _cache_put(key, vulns)
        logger.debug("osv_checker: %d vuln(s) for %s/%s", len(vulns), ecosystem, package)
        return vulns
    except Exception as exc:
        logger.debug("OSV query failed for %s/%s (fail-open): %s", ecosystem, package, exc)
        return []


# ─── Package parsers ─────────────────────────────────────────────────────────

def _parse_pypi_line(line: str) -> tuple[str, str | None] | None:
    """Parse one requirements.txt line → (name, version_or_None) or None to skip."""
    line = line.strip()
    if not line or line.startswith(("#", "-", "http://", "https://", "git+")):
        return None
    # Drop environment markers and extras: requests[security]==2.28; python_version>='3.8'
    line = line.split(";")[0].strip()
    m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:==([^\s,;]+))?", line)
    if not m:
        return None
    return m.group(1), m.group(2)


def _parse_npm_dep(name: str, version_spec: str) -> tuple[str, str | None]:
    """Parse npm dependency version spec → (name, version_or_None)."""
    # Strip range operators (^, ~, >=, >, etc.) to get a usable version.
    v = re.sub(r"^[^0-9]*", "", version_spec.strip()).split("-")[0] or None
    if v and not re.match(r"^\d+(\.\d+)*$", v):
        v = None  # discard non-semver like "latest", "*", "x.x"
    return name, v


# ─── Finding normaliser ───────────────────────────────────────────────────────

def _severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Try to extract a CVSS base score from an OSV vuln dict."""
    for sev in vuln.get("severity") or []:
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score_str = str(sev.get("score") or "")
            # Some OSV records embed the base score as a plain float string.
            try:
                return float(score_str)
            except ValueError:
                pass
            # Try database_specific.cvss_score (GitHub Advisory format).
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict):
        for key in ("cvss_score", "base_score", "cvss"):
            val = db.get(key)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
    return None


def _vuln_to_finding(
    package: str, ecosystem: str, version: str | None, vuln: dict[str, Any]
) -> dict[str, Any]:
    vuln_id: str = vuln.get("id") or ""
    aliases: list[str] = [a for a in (vuln.get("aliases") or []) if a != vuln_id]
    # MAL-* advisories are confirmed malware — escalate to critical.
    cvss = _extract_cvss(vuln)
    if vuln_id.startswith("MAL-"):
        severity = "critical"
    else:
        severity = _severity_from_cvss(cvss)

    # Collect affected version ranges for context.
    ranges: list[str] = []
    for affected in vuln.get("affected") or []:
        for r in affected.get("ranges") or []:
            for event in r.get("events") or []:
                introduced = event.get("introduced")
                fixed = event.get("fixed")
                if introduced:
                    ranges.append(f">={introduced}" + (f",<{fixed}" if fixed else ""))

    return {
        "package": package,
        "ecosystem": ecosystem,
        "version_checked": version or "any",
        "vuln_id": vuln_id,
        "aliases": aliases,
        "summary": (vuln.get("summary") or "")[:200],
        "details": (vuln.get("details") or "")[:500],
        "cvss": cvss,
        "severity": severity,
        "affected_ranges": ranges[:5],
    }


# ─── Public API ───────────────────────────────────────────────────────────────

def check_requirements_txt(content: str) -> list[dict[str, Any]]:
    """Check a requirements.txt file for known CVE/GHSA vulnerabilities.

    Queries OSV.dev for each package. Returns a list of finding dicts sorted
    by severity (critical first).
    """
    findings: list[dict[str, Any]] = []
    for line in content.splitlines():
        parsed = _parse_pypi_line(line)
        if parsed is None:
            continue
        name, version = parsed
        for vuln in _query_osv(name, "PyPI", version):
            findings.append(_vuln_to_finding(name, "PyPI", version, vuln))
    return _sort_findings(findings)


def check_package_json(content: str) -> list[dict[str, Any]]:
    """Check a package.json file for known npm CVE/GHSA vulnerabilities.

    Queries OSV.dev for each declared dependency and devDependency.
    """
    try:
        pkg: dict[str, Any] = json.loads(content)
    except json.JSONDecodeError:
        logger.debug("check_package_json: invalid JSON, skipping")
        return []
    findings: list[dict[str, Any]] = []
    deps: dict[str, str] = {}
    deps.update(pkg.get("dependencies") or {})
    deps.update(pkg.get("devDependencies") or {})
    for dep_name, version_spec in deps.items():
        name, version = _parse_npm_dep(dep_name, str(version_spec))
        for vuln in _query_osv(name, "npm", version):
            findings.append(_vuln_to_finding(name, "npm", version, vuln))
    return _sort_findings(findings)


def check_single_package(
    name: str, ecosystem: str, version: str | None = None
) -> list[dict[str, Any]]:
    """Check a single package for known vulnerabilities.

    Args:
        name: Package name (e.g. "requests", "lodash", "log4j").
        ecosystem: "PyPI" | "npm" | "Maven" | "Go" | "crates.io" | "RubyGems" etc.
        version: Exact version string, or None to check all versions.
    """
    vulns = _query_osv(name, ecosystem, version)
    findings = [_vuln_to_finding(name, ecosystem, version, v) for v in vulns]
    return _sort_findings(findings)


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    return sorted(findings, key=lambda f: _order.get(f.get("severity", "unknown"), 4))
