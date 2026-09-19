"""Agent-facing tools for the cross-scan vulnerability knowledge base.

Inspired by NousResearch/hermes-agent session_search_tool.py — lets the Strix
agent query its own past scan history so it can say "I've seen XSS on this
domain before" and prioritize retesting those areas.
"""

from __future__ import annotations

import json
import logging

from agents import RunContextWrapper, function_tool

from strix.core.scan_memory import get_stats, query_domain, search_findings


logger = logging.getLogger(__name__)


@function_tool
async def recall_past_findings(ctx: RunContextWrapper, target: str) -> str:
    """Query the cross-scan knowledge base for past vulnerabilities on a target domain.

    Use this at the START of a scan to check whether this domain has been tested
    before and what was found. Knowing past findings helps you:
    - Prioritize retesting previously confirmed vulnerabilities (regression check)
    - Avoid re-discovering the same findings as new
    - Understand the target's security history

    Args:
        target: The target URL or domain to look up (e.g. https://example.com or example.com)
    """
    try:
        findings = query_domain(target, limit=15)
    except Exception as exc:
        logger.debug("recall_past_findings error: %s", exc)
        return json.dumps({"success": False, "error": str(exc)})

    if not findings:
        return json.dumps({
            "success": True,
            "target": target,
            "message": "No previous scan findings for this target.",
            "findings": [],
        })

    return json.dumps({
        "success": True,
        "target": target,
        "count": len(findings),
        "message": (
            f"Found {len(findings)} past finding(s) for this target. "
            "Consider retesting these areas for regressions."
        ),
        "findings": findings,
    }, ensure_ascii=False, default=str)


@function_tool
async def search_scan_history(ctx: RunContextWrapper, keyword: str) -> str:
    """Search all past scan findings by keyword (CVE, CWE, vulnerability type, etc).

    Use this to find patterns across all previously scanned targets, e.g.:
    - "SQL injection" to see all past SQLi findings
    - "CVE-2024-1234" to check if a specific CVE was found before
    - "XSS" or "SSRF" or "RCE" to find all instances of a vulnerability class

    Args:
        keyword: Search term — vulnerability type, CVE ID, CWE, technology name, etc.
    """
    try:
        findings = search_findings(keyword, limit=20)
    except Exception as exc:
        logger.debug("search_scan_history error: %s", exc)
        return json.dumps({"success": False, "error": str(exc)})

    if not findings:
        return json.dumps({
            "success": True,
            "keyword": keyword,
            "message": f"No past findings matching '{keyword}'.",
            "findings": [],
        })

    return json.dumps({
        "success": True,
        "keyword": keyword,
        "count": len(findings),
        "findings": findings,
    }, ensure_ascii=False, default=str)


@function_tool
async def scan_memory_stats(ctx: RunContextWrapper) -> str:
    """Return statistics about the cross-scan knowledge base.

    Shows total findings tracked, number of domains and runs, and breakdown
    by severity. Use this to understand the breadth of historical scan data.
    """
    try:
        stats = get_stats()
    except Exception as exc:
        logger.debug("scan_memory_stats error: %s", exc)
        return json.dumps({"success": False, "error": str(exc)})

    return json.dumps({"success": True, **stats}, ensure_ascii=False, default=str)
