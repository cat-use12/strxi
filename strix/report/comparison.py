"""Scan comparison / regression report for Strix.

Compare two scan runs to identify:
  - NEW findings   — appeared in the latest scan, not in the baseline
  - FIXED findings — present in baseline, gone in latest (patched!)
  - UNCHANGED      — same in both scans (still open)
  - IMPROVED       — severity lowered (e.g. Critical → High)

Usage::
    from strix.report.comparison import compare_runs, write_comparison_report
    result = compare_runs(baseline_dir, latest_dir)
    write_comparison_report(output_path, result)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵", "unknown": "⚪"}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class FindingKey:
    """Deduplication key for matching findings across scans."""
    title: str
    severity: str
    endpoint: str

    def __hash__(self) -> int:
        return hash((self.title.lower().strip(), self.severity.lower(), self.endpoint.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FindingKey):
            return NotImplemented
        return (
            self.title.lower().strip() == other.title.lower().strip()
            and self.severity.lower() == other.severity.lower()
            and self.endpoint.lower() == other.endpoint.lower()
        )


@dataclass
class ComparisonResult:
    baseline_run: str = ""
    latest_run: str = ""
    baseline_date: str = ""
    latest_date: str = ""

    new_findings: list[dict[str, Any]] = field(default_factory=list)
    fixed_findings: list[dict[str, Any]] = field(default_factory=list)
    unchanged_findings: list[dict[str, Any]] = field(default_factory=list)
    improved_findings: list[dict[str, Any]] = field(default_factory=list)  # severity lowered

    @property
    def total_new(self) -> int:
        return len(self.new_findings)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed_findings)

    @property
    def total_unchanged(self) -> int:
        return len(self.unchanged_findings)

    @property
    def regression(self) -> bool:
        """True if any new Critical or High findings appeared."""
        return any(
            f.get("severity", "").lower() in ("critical", "high")
            for f in self.new_findings
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_vulnerabilities(run_dir: Path) -> tuple[list[dict[str, Any]], str]:
    """Load vulnerability list from a run directory. Returns (vulns, run_name)."""
    # Try vulnerabilities.json first, then scan_report.json, then sarif
    for name in ("vulnerabilities.json", "scan_report.json"):
        p = run_dir / name
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data, run_dir.name
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities") or data.get("findings") or []
                    return vulns, data.get("run_name") or run_dir.name
            except Exception as exc:
                logger.debug("Could not load %s: %s", p, exc)
    logger.warning("No vulnerability file found in %s", run_dir)
    return [], run_dir.name


def _run_date(run_dir: Path) -> str:
    for name in ("vulnerabilities.json", "scan_report.json"):
        p = run_dir / name
        if p.exists():
            try:
                mtime = p.stat().st_mtime
                return datetime.fromtimestamp(mtime, UTC).strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                pass
    return run_dir.name


def _finding_key(f: dict[str, Any]) -> FindingKey:
    return FindingKey(
        title=str(f.get("title") or f.get("name") or ""),
        severity=str(f.get("severity") or "unknown").lower(),
        endpoint=str(f.get("endpoint") or f.get("url") or f.get("target") or ""),
    )


def _title_key(f: dict[str, Any]) -> str:
    """Looser match key — title + endpoint only, ignoring severity (for improved detection)."""
    title = str(f.get("title") or f.get("name") or "").lower().strip()
    endpoint = str(f.get("endpoint") or f.get("url") or f.get("target") or "").lower()
    return f"{title}||{endpoint}"


# ─── Core comparison ──────────────────────────────────────────────────────────

def compare_runs(
    baseline_dir: str | Path,
    latest_dir: str | Path,
) -> ComparisonResult:
    """Compare two Strix scan run directories.

    Args:
        baseline_dir: Directory of the older/reference scan run.
        latest_dir:   Directory of the newer scan run to compare against.

    Returns:
        ComparisonResult with new, fixed, unchanged, and improved findings.
    """
    baseline_dir = Path(baseline_dir)
    latest_dir = Path(latest_dir)

    baseline_vulns, baseline_name = _load_vulnerabilities(baseline_dir)
    latest_vulns, latest_name = _load_vulnerabilities(latest_dir)

    result = ComparisonResult(
        baseline_run=baseline_name,
        latest_run=latest_name,
        baseline_date=_run_date(baseline_dir),
        latest_date=_run_date(latest_dir),
    )

    # Build lookup maps
    baseline_exact: dict[FindingKey, dict[str, Any]] = {_finding_key(f): f for f in baseline_vulns}
    latest_exact: dict[FindingKey, dict[str, Any]] = {_finding_key(f): f for f in latest_vulns}

    # Title-only map for "improved severity" detection
    baseline_by_title: dict[str, dict[str, Any]] = {_title_key(f): f for f in baseline_vulns}
    latest_by_title: dict[str, dict[str, Any]] = {_title_key(f): f for f in latest_vulns}

    # New findings: in latest but NOT in baseline (exact match)
    for key, finding in latest_exact.items():
        if key not in baseline_exact:
            title_k = _title_key(finding)
            if title_k in baseline_by_title:
                # Same vuln, different severity — check if improved
                old_sev = _SEVERITY_ORDER.get(baseline_by_title[title_k].get("severity", "unknown").lower(), 5)
                new_sev = _SEVERITY_ORDER.get(finding.get("severity", "unknown").lower(), 5)
                if new_sev > old_sev:  # higher index = lower severity = improved
                    result.improved_findings.append({
                        **finding,
                        "_old_severity": baseline_by_title[title_k].get("severity"),
                    })
                    continue
            result.new_findings.append(finding)

    # Fixed findings: in baseline but NOT in latest (exact match)
    for key, finding in baseline_exact.items():
        if key not in latest_exact:
            title_k = _title_key(finding)
            if title_k not in latest_by_title:
                result.fixed_findings.append(finding)

    # Unchanged: in both
    for key, finding in latest_exact.items():
        if key in baseline_exact:
            result.unchanged_findings.append(finding)

    # Sort by severity
    def sev_sort(f: dict[str, Any]) -> int:
        return _SEVERITY_ORDER.get(str(f.get("severity") or "unknown").lower(), 5)

    result.new_findings.sort(key=sev_sort)
    result.fixed_findings.sort(key=sev_sort)
    result.unchanged_findings.sort(key=sev_sort)

    logger.info(
        "comparison: new=%d fixed=%d unchanged=%d improved=%d",
        result.total_new, result.total_fixed, result.total_unchanged, len(result.improved_findings),
    )
    return result


# ─── Report writer ────────────────────────────────────────────────────────────

def _sev_badge(sev: str) -> str:
    emoji = _SEV_EMOJI.get(sev.lower(), "⚪")
    return f"{emoji} {sev.upper()}"


def _finding_block(f: dict[str, Any], prefix: str = "") -> str:
    title = f.get("title") or f.get("name") or "Unknown"
    sev = str(f.get("severity") or "unknown")
    endpoint = f.get("endpoint") or f.get("url") or ""
    cve = f.get("cve") or ""
    cwe = f.get("cwe") or ""
    desc = str(f.get("description") or "")[:200]

    lines = [f"{prefix}**{title}** — {_sev_badge(sev)}"]
    if endpoint:
        lines.append(f"  - Endpoint: `{endpoint}`")
    if cve:
        lines.append(f"  - CVE: {cve}")
    if cwe:
        lines.append(f"  - CWE: {cwe}")
    if desc:
        lines.append(f"  - {desc}")
    return "\n".join(lines)


def generate_comparison_report(result: ComparisonResult) -> str:
    """Generate a Markdown comparison report from a ComparisonResult."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines += [
        "# Strix Scan Comparison Report",
        "",
        f"**Generated:** {now}",
        f"**Baseline:** {result.baseline_run} ({result.baseline_date})",
        f"**Latest:**   {result.latest_run} ({result.latest_date})",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Status | Count |",
        f"|--------|-------|",
        f"| 🆕 New findings | **{result.total_new}** |",
        f"| ✅ Fixed findings | **{result.total_fixed}** |",
        f"| ⚠️ Unchanged | **{result.total_unchanged}** |",
        f"| 📉 Severity improved | **{len(result.improved_findings)}** |",
        "",
    ]

    if result.regression:
        lines += [
            "## ⛔ REGRESSION DETECTED",
            "",
            "New Critical or High severity findings appeared since the baseline scan.",
            "Investigate immediately before marking this release as secure.",
            "",
        ]
    elif result.total_new == 0 and result.total_fixed > 0:
        lines += [
            "## ✅ Security Improved",
            "",
            f"No new findings. {result.total_fixed} finding(s) from the baseline have been fixed.",
            "",
        ]
    elif result.total_new == 0 and result.total_fixed == 0:
        lines += [
            "## ➡️ No Change",
            "",
            "No new or fixed findings compared to the baseline.",
            "",
        ]

    if result.new_findings:
        lines += ["## 🆕 New Findings", ""]
        for f in result.new_findings:
            lines.append(_finding_block(f, "- "))
            lines.append("")

    if result.fixed_findings:
        lines += ["## ✅ Fixed Since Baseline", ""]
        for f in result.fixed_findings:
            lines.append(_finding_block(f, "- "))
            lines.append("")

    if result.improved_findings:
        lines += ["## 📉 Severity Improved", ""]
        for f in result.improved_findings:
            old = f.get("_old_severity", "?")
            new = f.get("severity", "?")
            title = f.get("title") or "Unknown"
            lines.append(f"- **{title}** — {_sev_badge(old)} → {_sev_badge(new)}")
        lines.append("")

    if result.unchanged_findings:
        lines += [
            "## ⚠️ Still Open (Unchanged)",
            "",
            f"*{result.total_unchanged} finding(s) remain unresolved since the baseline scan.*",
            "",
        ]
        for f in result.unchanged_findings[:10]:  # cap to avoid huge reports
            lines.append(_finding_block(f, "- "))
            lines.append("")
        if result.total_unchanged > 10:
            lines.append(f"*... and {result.total_unchanged - 10} more. See full scan report for details.*")
            lines.append("")

    lines += ["---", "", "*Generated by Strix scan comparison engine.*", ""]
    return "\n".join(lines)


def write_comparison_report(
    output_path: str | Path,
    result: ComparisonResult,
) -> Path:
    """Write the Markdown comparison report to a file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_comparison_report(result)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Comparison report written to %s", output_path)
    return output_path
