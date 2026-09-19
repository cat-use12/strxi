"""Executive summary generator for Strix security reports.

Generates a concise, non-technical summary from structured findings.
The summary is aimed at management, product owners, or clients who
need to understand the security posture without reading full technical
reports.

Output is a Markdown document with:
- Overall risk rating (Critical/High/Medium/Low/Clean)
- Finding distribution chart (ASCII bar)
- Top-N critical/high findings with one-line impact
- Remediation progress (when tracked)
- Top remediation recommendations
- Scan metadata
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}

_RISK_THRESHOLD = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _overall_risk(vulns: list[dict[str, Any]]) -> str:
    """Derive overall risk from the highest-severity confirmed finding."""
    for sev in _SEVERITY_ORDER:
        if any(str(v.get("severity") or "").lower() == sev for v in vulns):
            return _RISK_THRESHOLD.get(sev, "INFO")
    return "CLEAN"


def _risk_style(risk: str) -> str:
    styles = {
        "CRITICAL": "**CRITICAL**",
        "HIGH": "**HIGH**",
        "MEDIUM": "**MEDIUM**",
        "LOW": "**LOW**",
        "CLEAN": "**CLEAN — No vulnerabilities found**",
    }
    return styles.get(risk, risk)


def _bar(count: int, total: int, width: int = 20) -> str:
    if total == 0:
        return ""
    filled = round(count / total * width)
    return "█" * filled + "░" * (width - filled)


def _top_findings(
    vulns: list[dict[str, Any]], severities: list[str], limit: int = 5
) -> list[dict[str, Any]]:
    """Return up to *limit* findings at the specified severity levels, sorted by CVSS."""
    filtered = [
        v for v in vulns
        if str(v.get("severity") or "").lower() in severities
    ]
    return sorted(filtered, key=lambda v: float(v.get("cvss") or 0), reverse=True)[:limit]


def _shorten(text: str | None, max_chars: int = 120) -> str:
    if not text:
        return "—"
    t = text.strip()
    return t if len(t) <= max_chars else t[:max_chars - 1] + "…"


def generate_executive_summary(
    vulnerabilities: list[dict[str, Any]],
    *,
    run_name: str | None = None,
    targets: list[str] | None = None,
    scan_start: str | None = None,
    scan_end: str | None = None,
    top_findings_limit: int = 5,
) -> str:
    """Generate a non-technical executive summary as a Markdown string."""

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    total = len(vulnerabilities)
    counts: Counter[str] = Counter(
        str(v.get("severity") or "info").lower() for v in vulnerabilities
    )
    overall_risk = _overall_risk(vulnerabilities)

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append("# Security Assessment — Executive Summary")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    if run_name:
        lines.append(f"**Run:** `{run_name}`")
    if targets:
        lines.append(f"**Target(s):** {', '.join(targets)}")
    if scan_start:
        lines.append(f"**Scan started:** {scan_start}")
    if scan_end:
        lines.append(f"**Scan completed:** {scan_end}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Overall risk ────────────────────────────────────────────────────────
    lines.append("## Overall Risk Rating")
    lines.append("")
    lines.append(f"> {_risk_style(overall_risk)}")
    lines.append("")

    if total == 0:
        lines.append(
            "No vulnerabilities were identified during this assessment. "
            "This does not guarantee the absence of security issues — "
            "it reflects the scope and depth of testing performed."
        )
        lines.append("")
    else:
        # Severity distribution
        lines.append("## Finding Distribution")
        lines.append("")
        lines.append(f"| Severity | Count | Distribution |")
        lines.append(f"|----------|------:|-------------|")
        for sev in _SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            emoji = _SEVERITY_EMOJI.get(sev, "")
            bar = _bar(n, total)
            lines.append(f"| {emoji} {sev.capitalize()} | {n} | `{bar}` |")
        lines.append(f"| **Total** | **{total}** | |")
        lines.append("")

        # Top critical/high findings
        top = _top_findings(vulnerabilities, ["critical", "high"], limit=top_findings_limit)
        if top:
            lines.append("## Critical & High Severity Findings")
            lines.append("")
            lines.append(
                "The following findings represent the highest-risk issues requiring "
                "immediate attention:"
            )
            lines.append("")
            for i, v in enumerate(top, 1):
                sev = str(v.get("severity") or "").lower()
                emoji = _SEVERITY_EMOJI.get(sev, "")
                title = str(v.get("title") or "Untitled")
                cvss = v.get("cvss")
                cvss_str = f" (CVSS {cvss:.1f})" if cvss is not None else ""
                impact = _shorten(v.get("impact") or v.get("description"))
                endpoint = v.get("endpoint") or v.get("target") or ""
                cve = v.get("cve") or ""
                cwe = v.get("cwe") or ""

                lines.append(f"### {i}. {emoji} {title}{cvss_str}")
                if endpoint:
                    lines.append(f"**Affected asset:** `{endpoint}`")
                if cve:
                    lines.append(f"**CVE:** {cve}")
                if cwe:
                    lines.append(f"**CWE:** {cwe}")
                lines.append(f"**Impact:** {impact}")

                fix_effort = str(v.get("fix_effort") or "").lower()
                if fix_effort:
                    lines.append(f"**Fix effort:** {fix_effort.capitalize()}")

                remediation = _shorten(v.get("remediation_steps"), max_chars=200)
                if remediation != "—":
                    lines.append(f"**Recommendation:** {remediation}")
                lines.append("")

        # Medium findings summary (no full detail)
        medium = [v for v in vulnerabilities if str(v.get("severity") or "").lower() == "medium"]
        if medium:
            lines.append("## Medium Severity Findings")
            lines.append("")
            lines.append(f"{len(medium)} medium-severity finding(s) were identified:")
            lines.append("")
            for v in sorted(medium, key=lambda x: float(x.get("cvss") or 0), reverse=True):
                title = str(v.get("title") or "Untitled")
                cvss = v.get("cvss")
                cvss_str = f" (CVSS {cvss:.1f})" if cvss is not None else ""
                lines.append(f"- **{title}**{cvss_str}")
            lines.append("")

    # ── Remediation progress ─────────────────────────────────────────────────
    tracked = [v for v in vulnerabilities if v.get("remediation_status")]
    if tracked:
        lines.append("## Remediation Progress")
        lines.append("")
        rem_counts: Counter[str] = Counter(
            str(v.get("remediation_status") or "open").lower() for v in vulnerabilities
        )
        fixed = rem_counts.get("verified_fixed", 0)
        rate = round(fixed / total * 100, 1) if total else 0.0
        lines.append(f"| Status | Count |")
        lines.append(f"|--------|------:|")
        status_labels = {
            "open": "Open",
            "in_progress": "In Progress",
            "pending_retest": "Pending Re-test",
            "verified_fixed": "Verified Fixed",
            "wont_fix": "Won't Fix",
        }
        for status, label in status_labels.items():
            n = rem_counts.get(status, 0)
            if n > 0:
                lines.append(f"| {label} | {n} |")
        lines.append("")
        lines.append(f"**Remediation rate:** {rate}% ({fixed}/{total} findings resolved)")
        lines.append("")

    # ── Recommendations ──────────────────────────────────────────────────────
    lines.append("## Recommendations")
    lines.append("")
    lines.append(
        "Based on this assessment, the following actions are recommended in priority order:"
    )
    lines.append("")

    crit_high = counts.get("critical", 0) + counts.get("high", 0)
    medium_count = counts.get("medium", 0)
    low_count = counts.get("low", 0)

    priority = 1
    if crit_high > 0:
        lines.append(
            f"{priority}. **Immediate action required** — Remediate all {crit_high} "
            "critical and high severity findings before the next production deployment."
        )
        priority += 1
    if medium_count > 0:
        lines.append(
            f"{priority}. **Short-term** — Address {medium_count} medium-severity findings "
            "within the next development sprint."
        )
        priority += 1
    if low_count > 0:
        lines.append(
            f"{priority}. **Planned** — Schedule remediation for {low_count} low-severity "
            "findings in the next maintenance window."
        )
        priority += 1

    lines.append(
        f"{priority}. **Re-test** — After remediation, run `strix retest set <run> <id> pending_retest` "
        "and conduct a focused re-test to verify each fix."
    )
    priority += 1
    lines.append(
        f"{priority}. **Continuous scanning** — Integrate Strix into your CI/CD pipeline "
        "to catch new vulnerabilities on every pull request."
    )
    lines.append("")

    # ── Disclaimer ────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append(
        "*This report was generated automatically by Strix AI Penetration Testing Agent. "
        "It reflects the findings discovered during the scope of this assessment and should "
        "be reviewed by a qualified security professional. The absence of a finding does not "
        "guarantee the absence of a vulnerability.*"
    )
    lines.append("")

    return "\n".join(lines)


def write_executive_summary(
    run_dir: Path,
    vulnerabilities: list[dict[str, Any]],
    *,
    run_name: str | None = None,
    targets: list[str] | None = None,
    scan_start: str | None = None,
    scan_end: str | None = None,
) -> Path:
    """Write the executive summary Markdown to *run_dir*/executive_summary.md."""
    summary = generate_executive_summary(
        vulnerabilities,
        run_name=run_name,
        targets=targets,
        scan_start=scan_start,
        scan_end=scan_end,
    )
    out_path = run_dir / "executive_summary.md"
    out_path.write_text(summary, encoding="utf-8")
    logger.info("Executive summary written: %s (%d findings)", out_path, len(vulnerabilities))
    return out_path
