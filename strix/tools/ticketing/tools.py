"""Auto Ticket Creator — create GitHub Issues from Strix findings.

Automatically creates GitHub Issues for scan findings so your team can
track and remediate vulnerabilities in your existing workflow.

Requires:
  GITHUB_TOKEN env var — a personal access token or fine-grained token
                         with repo:write or issues:write scope.
  GITHUB_REPO  env var — owner/repo (e.g. "myorg/myapp")

Usage::
    # As agent tools (registered via @function_tool)
    create_github_issue_for_finding(ctx, title=..., severity=..., description=...)
    create_github_issues_batch(ctx, findings_json=...)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)

_SEVERITY_LABELS = {
    "critical": "severity: critical",
    "high":     "severity: high",
    "medium":   "severity: medium",
    "low":      "severity: low",
    "info":     "severity: info",
}
_SEVERITY_PRIORITY = {
    "critical": "P0 - Immediate",
    "high":     "P1 - High",
    "medium":   "P2 - Medium",
    "low":      "P3 - Low",
    "info":     "P4 - Informational",
}


def _get_config() -> tuple[str, str]:
    """Return (token, repo) from environment, raising if missing."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPO", "").strip()
    if not token:
        raise ValueError(
            "GITHUB_TOKEN env var is not set. "
            "Create a token at https://github.com/settings/tokens with 'repo' scope."
        )
    if not repo:
        raise ValueError(
            "GITHUB_REPO env var is not set. "
            "Set it to 'owner/repo', e.g. GITHUB_REPO=myorg/myapp"
        )
    return token, repo


def _format_issue_body(
    severity: str,
    endpoint: str,
    description: str,
    remediation: str,
    cve: str,
    cwe: str,
    evidence: str,
    scan_id: str,
) -> str:
    sev_upper = severity.upper()
    lines = [
        f"## 🛡️ Security Finding — {sev_upper}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Severity** | {sev_upper} |",
        f"| **Priority** | {_SEVERITY_PRIORITY.get(severity.lower(), 'Unknown')} |",
    ]
    if endpoint:
        lines.append(f"| **Endpoint** | `{endpoint}` |")
    if cve:
        lines.append(f"| **CVE** | {cve} |")
    if cwe:
        lines.append(f"| **CWE** | {cwe} |")
    if scan_id:
        lines.append(f"| **Scan ID** | {scan_id} |")

    if description:
        lines += ["", "## Description", "", description]

    if evidence:
        lines += ["", "## Evidence", "", "```", evidence[:500], "```"]

    if remediation:
        lines += ["", "## Remediation", "", remediation]

    lines += [
        "",
        "---",
        "*Automatically created by [Strix](https://github.com/strix-security/strix) — AI Pentesting Agent*",
    ]
    return "\n".join(lines)


def _create_issue_http(
    token: str,
    repo: str,
    title: str,
    body: str,
    labels: list[str],
) -> dict[str, Any]:
    """Create a GitHub issue via REST API (no httpx dependency)."""
    url = f"https://api.github.com/repos/{repo}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(f"GitHub API error {exc.code}: {body_text}") from exc


# ─── Agent tools ──────────────────────────────────────────────────────────────

if _HAS_AGENTS:
    @function_tool
    async def create_github_issue_for_finding(
        ctx: RunContextWrapper,
        title: str,
        severity: str,
        description: str = "",
        endpoint: str = "",
        remediation: str = "",
        cve: str = "",
        cwe: str = "",
        evidence: str = "",
        scan_id: str = "",
    ) -> str:
        """Create a GitHub Issue for a single security finding.

        Requires GITHUB_TOKEN and GITHUB_REPO environment variables.

        Args:
            title:        Short issue title, e.g. "SQL Injection in /api/search".
            severity:     One of: critical, high, medium, low, info.
            description:  Full description of the vulnerability.
            endpoint:     Affected URL or endpoint.
            remediation:  How to fix it.
            cve:          CVE ID if applicable (e.g. CVE-2024-1234).
            cwe:          CWE ID if applicable (e.g. CWE-89).
            evidence:     Evidence / payload that triggered the finding.
            scan_id:      Strix scan ID for traceability.

        Returns:
            The GitHub issue URL, or an error message.
        """
        try:
            token, repo = _get_config()
        except ValueError as exc:
            return f"Configuration error: {exc}"

        sev_lower = severity.strip().lower()
        body = _format_issue_body(
            severity=sev_lower,
            endpoint=endpoint,
            description=description,
            remediation=remediation,
            cve=cve,
            cwe=cwe,
            evidence=evidence,
            scan_id=scan_id,
        )

        labels = ["security", "strix"]
        sev_label = _SEVERITY_LABELS.get(sev_lower)
        if sev_label:
            labels.append(sev_label)

        try:
            issue = _create_issue_http(token, repo, title=title, body=body, labels=labels)
            url = issue.get("html_url") or issue.get("url") or ""
            number = issue.get("number", "?")
            return f"Issue #{number} created: {url}"
        except Exception as exc:
            logger.error("Failed to create GitHub issue: %s", exc)
            return f"Error creating GitHub issue: {exc}"

    @function_tool
    async def create_github_issues_batch(
        ctx: RunContextWrapper,
        findings_json: str,
        min_severity: str = "medium",
        scan_id: str = "",
    ) -> str:
        """Create GitHub Issues for multiple findings at once.

        Args:
            findings_json:  JSON array of findings (each with title, severity,
                            description, endpoint, remediation, cve, cwe fields).
            min_severity:   Only create issues for this severity and above.
                            One of: critical, high, medium, low, info (default: medium).
            scan_id:        Strix scan ID for traceability.

        Returns:
            Summary of created issues.
        """
        try:
            token, repo = _get_config()
        except ValueError as exc:
            return f"Configuration error: {exc}"

        try:
            findings = json.loads(findings_json)
        except json.JSONDecodeError as exc:
            return f"Invalid findings JSON: {exc}"

        if not isinstance(findings, list):
            return "findings_json must be a JSON array."

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        min_sev_num = sev_order.get(min_severity.strip().lower(), 2)

        created: list[str] = []
        skipped = 0
        errors: list[str] = []

        for f in findings:
            sev = str(f.get("severity") or "unknown").lower()
            if sev_order.get(sev, 5) > min_sev_num:
                skipped += 1
                continue

            title = str(f.get("title") or f.get("name") or "Security Finding")
            body = _format_issue_body(
                severity=sev,
                endpoint=str(f.get("endpoint") or f.get("url") or ""),
                description=str(f.get("description") or ""),
                remediation=str(f.get("remediation") or ""),
                cve=str(f.get("cve") or ""),
                cwe=str(f.get("cwe") or ""),
                evidence=str(f.get("evidence") or ""),
                scan_id=scan_id,
            )
            labels = ["security", "strix", _SEVERITY_LABELS.get(sev, "severity: unknown")]
            try:
                issue = _create_issue_http(token, repo, title=title, body=body, labels=labels)
                url = issue.get("html_url") or str(issue.get("number", "?"))
                created.append(url)
            except Exception as exc:
                errors.append(f"{title}: {exc}")

        summary = [
            f"Created {len(created)} issue(s) in {repo}.",
            f"Skipped {skipped} finding(s) below {min_severity} severity.",
        ]
        if created:
            summary.append("Created:\n" + "\n".join(f"  - {u}" for u in created))
        if errors:
            summary.append("Errors:\n" + "\n".join(f"  - {e}" for e in errors))
        return "\n".join(summary)

else:
    async def create_github_issue_for_finding(**_: Any) -> str:  # type: ignore[misc]
        return "agents SDK not installed"

    async def create_github_issues_batch(**_: Any) -> str:  # type: ignore[misc]
        return "agents SDK not installed"
