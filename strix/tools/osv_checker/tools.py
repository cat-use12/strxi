"""Agent-facing tools for OSV dependency vulnerability checking.

Adapted from NousResearch/hermes-agent tools/osv_check.py (MIT).
Lets the Strix AI agent check dependency files found on the target server
for known CVEs/GHSA advisories before starting manual exploitation attempts.
"""

from __future__ import annotations

import json
import logging

from agents import RunContextWrapper, function_tool

from strix.core.osv_checker import (
    check_package_json,
    check_requirements_txt,
    check_single_package,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


@function_tool
async def check_dependencies_for_cves(
    ctx: RunContextWrapper, file_content: str, file_type: str
) -> str:
    """Check a dependency file found on the target for known CVE/GHSA vulnerabilities.

    Queries the free OSV.dev API (no key needed) for every package in the file.
    Use this when you discover a requirements.txt, package.json, Pipfile, or similar
    file on the target server to identify exploitable libraries before manual testing.

    Args:
        file_content: Full text content of the dependency file.
        file_type: "requirements.txt" (Python/PyPI) or "package.json" (Node/npm).
    """
    ft = file_type.lower().strip()
    try:
        if "requirement" in ft or "pypi" in ft or ft.endswith(".txt"):
            findings = check_requirements_txt(file_content)
        elif "package.json" in ft or "npm" in ft:
            findings = check_package_json(file_content)
        else:
            return json.dumps({
                "success": False,
                "error": (
                    f"Unknown file_type: '{file_type}'. "
                    "Use 'requirements.txt' (PyPI) or 'package.json' (npm)."
                ),
            })
    except Exception as exc:
        logger.debug("check_dependencies_for_cves error: %s", exc)
        return json.dumps({"success": False, "error": str(exc)})

    if not findings:
        return json.dumps({
            "success": True,
            "file_type": file_type,
            "message": "No known CVEs found in this dependency file.",
            "findings": [],
        })

    counts = _severity_counts(findings)
    unique_packages = len({f["package"] for f in findings})
    return json.dumps({
        "success": True,
        "file_type": file_type,
        "total_findings": len(findings),
        "unique_vulnerable_packages": unique_packages,
        "severity_counts": counts,
        "message": (
            f"Found {len(findings)} CVE(s) in {unique_packages} package(s). "
            + ", ".join(f"{v} {k}" for k, v in counts.items() if v)
            + ". Investigate CRITICAL and HIGH first."
        ),
        "findings": findings,
    }, ensure_ascii=False, default=str)


@function_tool
async def lookup_package_cves(
    ctx: RunContextWrapper,
    package_name: str,
    ecosystem: str,
    version: str = "",
) -> str:
    """Look up CVE/GHSA vulnerabilities for one specific package via OSV.dev.

    Use this to check if a library version you spotted in the target's source code,
    error messages, or HTTP headers has known exploits.

    Supported ecosystems: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Hex, Pub.

    Args:
        package_name: Package name (e.g. "requests", "lodash", "spring-core").
        ecosystem: Ecosystem name: "PyPI", "npm", "Maven", "Go", "crates.io", etc.
        version: Exact version string (e.g. "2.28.0"). Leave empty to check all versions.
    """
    try:
        findings = check_single_package(package_name, ecosystem, version or None)
    except Exception as exc:
        logger.debug("lookup_package_cves error: %s", exc)
        return json.dumps({"success": False, "error": str(exc)})

    if not findings:
        return json.dumps({
            "success": True,
            "package": package_name,
            "ecosystem": ecosystem,
            "version": version or "any",
            "message": "No known CVEs found.",
            "findings": [],
        })

    counts = _severity_counts(findings)
    return json.dumps({
        "success": True,
        "package": package_name,
        "ecosystem": ecosystem,
        "version": version or "any",
        "total": len(findings),
        "severity_counts": counts,
        "findings": findings,
    }, ensure_ascii=False, default=str)
