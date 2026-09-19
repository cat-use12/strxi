"""Nuclei integration tools for Strix.

Wraps the Nuclei vulnerability scanner (https://github.com/projectdiscovery/nuclei)
to run template-based scans as part of Strix's agent workflow.

Requires nuclei to be installed: https://docs.projectdiscovery.io/tools/nuclei/install

The agent uses these tools to:
  1. Check if nuclei is available
  2. Run nuclei against a target with chosen templates/severity
  3. Parse and return structured findings
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)

# Maximum lines of nuclei output to keep in memory per run (avoids huge payloads).
_MAX_OUTPUT_LINES = 500
_DEFAULT_TIMEOUT = 300  # 5 minutes


def _nuclei_path() -> str | None:
    return shutil.which("nuclei")


def _parse_nuclei_jsonl(raw: str) -> list[dict[str, Any]]:
    """Parse nuclei -json output (one JSON object per line) into structured findings."""
    findings: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info") or {}
        sev_raw = str(info.get("severity") or "unknown").lower()
        sev_map = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "informational": "info",
        }
        severity = sev_map.get(sev_raw, "unknown")

        findings.append({
            "title": info.get("name") or obj.get("template-id") or "Nuclei Finding",
            "severity": severity,
            "endpoint": obj.get("host") or obj.get("matched-at") or "",
            "description": info.get("description") or "",
            "remediation": info.get("remediation") or "",
            "cve": (info.get("classification") or {}).get("cve-id") or "",
            "cwe": (info.get("classification") or {}).get("cwe-id") or "",
            "cvss": str((info.get("classification") or {}).get("cvss-score") or ""),
            "references": info.get("reference") or [],
            "template_id": obj.get("template-id") or "",
            "matcher_name": obj.get("matcher-name") or "",
            "evidence": obj.get("extracted-results") or obj.get("curl-command") or "",
            "source": "nuclei",
        })
    return findings


async def _run_nuclei_async(
    target: str,
    templates: str = "",
    severity: str = "",
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Core async nuclei runner. Returns {findings, stdout_snippet, error}."""
    nuclei_bin = _nuclei_path()
    if not nuclei_bin:
        return {
            "findings": [],
            "error": (
                "nuclei binary not found. Install it: "
                "https://docs.projectdiscovery.io/tools/nuclei/install"
            ),
        }

    cmd = [nuclei_bin, "-target", target, "-json", "-silent", "-no-color"]
    if templates:
        for t in templates.split(","):
            t = t.strip()
            if t:
                cmd += ["-t", t]
    if severity:
        cmd += ["-severity", severity.lower()]

    logger.info("Running nuclei: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {"findings": [], "error": f"Nuclei scan timed out after {timeout}s"}

        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")

        findings = _parse_nuclei_jsonl(stdout_text)

        # Only return a snippet of stderr so the agent payload stays small.
        stderr_lines = stderr_text.splitlines()[:20]
        return {
            "findings": findings,
            "total": len(findings),
            "return_code": proc.returncode,
            "stderr_snippet": "\n".join(stderr_lines),
            "error": None,
        }

    except Exception as exc:
        logger.exception("Nuclei run failed: %s", exc)
        return {"findings": [], "error": str(exc)}


# ─── Agent tools ──────────────────────────────────────────────────────────────

if _HAS_AGENTS:
    @function_tool
    async def check_nuclei_available(ctx: RunContextWrapper) -> str:
        """Check whether nuclei is installed and available on this system.

        Returns the nuclei version string, or an installation message if missing.
        """
        path = _nuclei_path()
        if not path:
            return (
                "nuclei is NOT installed. "
                "Install it from: https://docs.projectdiscovery.io/tools/nuclei/install\n"
                "  macOS:  brew install nuclei\n"
                "  Linux:  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                "  Docker: docker run projectdiscovery/nuclei"
            )
        try:
            result = subprocess.run(
                [path, "-version"],
                capture_output=True, text=True, timeout=10
            )
            ver = result.stdout.strip() or result.stderr.strip() or "unknown version"
            return f"nuclei is available at {path}\n{ver}"
        except Exception as exc:
            return f"nuclei found at {path} but failed to run: {exc}"

    @function_tool
    async def run_nuclei_scan(
        ctx: RunContextWrapper,
        target: str,
        templates: str = "",
        severity: str = "",
        timeout_seconds: int = 300,
    ) -> str:
        """Run a nuclei scan against a target URL or host.

        Args:
            target:           The URL or hostname to scan (e.g. https://example.com).
            templates:        Comma-separated list of nuclei template tags or paths
                              (e.g. "cves,exposures,default-logins"). Leave blank for all.
            severity:         Minimum severity to report: critical, high, medium, low, info.
                              Leave blank for all severities.
            timeout_seconds:  Max seconds to wait for the scan (default 300).

        Returns:
            JSON summary of findings, or an error message.
        """
        if not target:
            return "Error: target is required."

        result = await _run_nuclei_async(
            target=target,
            templates=templates,
            severity=severity,
            timeout=timeout_seconds,
        )

        if result.get("error"):
            return f"Nuclei error: {result['error']}"

        findings = result.get("findings", [])
        if not findings:
            return f"Nuclei scan complete. No findings for {target}."

        # Return compact JSON for the agent to process.
        return json.dumps({
            "target": target,
            "total_findings": len(findings),
            "findings": findings[:_MAX_OUTPUT_LINES],
        }, indent=2, ensure_ascii=False)

else:
    # Stub for environments without the agents SDK.
    async def check_nuclei_available() -> str:  # type: ignore[misc]
        return "agents SDK not installed"

    async def run_nuclei_scan(target: str, **_: Any) -> str:  # type: ignore[misc]
        return "agents SDK not installed"
