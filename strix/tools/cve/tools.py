"""CVE research tools for Strix.

Provides tools for:
- Looking up CVEs by ID, product, or keyword
- Checking OSV.dev for vulnerability data
- Searching Exploit-DB / searchsploit
- Looking up PoC exploits on GitHub
- Generating CVE advisory drafts
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_API = "https://api.osv.dev/v1"
_GITHUB_API = "https://api.github.com"


def _http_get(url: str, headers: dict | None = None, timeout: int = 15) -> dict | str:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Strix/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


if _HAS_AGENTS:
    @function_tool
    async def lookup_cve(
        ctx: RunContextWrapper,
        cve_id: str,
    ) -> str:
        """Look up a CVE by ID from NVD (National Vulnerability Database).

        Args:
            cve_id: CVE identifier, e.g. "CVE-2021-44228"

        Returns full CVE details including CVSS score, description, references, and affected products.
        """
        url = f"{_NVD_API}?cveId={urllib.parse.quote(cve_id.upper())}"
        data = _http_get(url)

        if isinstance(data, dict) and "error" in data:
            return f"Error looking up {cve_id}: {data['error']}"

        try:
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return f"CVE {cve_id} not found in NVD."

            cve = vulns[0]["cve"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No English description"
            )

            # Get CVSS score
            score_info = ""
            metrics = cve.get("metrics", {})
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if v in metrics and metrics[v]:
                    m = metrics[v][0]["cvssData"]
                    score_info = f"CVSS {m.get('version', '')}: {m.get('baseScore', '')} ({m.get('baseSeverity', '')})\nVector: {m.get('vectorString', '')}"
                    break

            # References
            refs = [r["url"] for r in cve.get("references", [])[:5]]

            result = {
                "id": cve_id.upper(),
                "published": cve.get("published", ""),
                "modified": cve.get("lastModified", ""),
                "description": desc,
                "cvss": score_info,
                "references": refs,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
            }
            return json.dumps(result, indent=2)

        except Exception as e:
            return f"Error parsing NVD response: {e}"

    @function_tool
    async def search_cves(
        ctx: RunContextWrapper,
        keyword: str = "",
        product: str = "",
        vendor: str = "",
        min_cvss: float = 0.0,
        limit: int = 10,
    ) -> str:
        """Search NVD for CVEs by keyword, product, vendor, or minimum CVSS score.

        Args:
            keyword: Search keyword, e.g. "log4j", "buffer overflow"
            product: Product name, e.g. "apache httpd"
            vendor: Vendor name, e.g. "microsoft"
            min_cvss: Minimum CVSS score filter (e.g. 7.0 for High+)
            limit: Maximum results to return (default 10)
        """
        params = {"resultsPerPage": min(limit, 20)}
        if keyword:
            params["keywordSearch"] = keyword
        if product or vendor:
            params["keywordSearch"] = f"{vendor} {product}".strip()

        url = f"{_NVD_API}?" + urllib.parse.urlencode(params)
        data = _http_get(url)

        if isinstance(data, dict) and "error" in data:
            return f"Error: {data['error']}"

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No CVEs found for query: {keyword or product or vendor}"

        results = []
        for v in vulns:
            cve = v["cve"]
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"][:200] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            # Get score
            score = 0.0
            metrics = cve.get("metrics", {})
            for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if mk in metrics and metrics[mk]:
                    score = metrics[mk][0]["cvssData"].get("baseScore", 0.0)
                    break

            if score >= min_cvss:
                results.append({
                    "id": cve_id,
                    "score": score,
                    "published": cve.get("published", "")[:10],
                    "description": desc + ("..." if len(desc) == 200 else ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return json.dumps(results[:limit], indent=2)

    @function_tool
    async def search_exploitdb(
        ctx: RunContextWrapper,
        query: str,
    ) -> str:
        """Search Exploit-DB / searchsploit for public exploits matching a query.

        Args:
            query: Search query, e.g. "Apache 2.4.49", "WordPress SQLi", "CVE-2021-44228"
        """
        if shutil.which("searchsploit"):
            try:
                result = subprocess.run(
                    ["searchsploit", "--json", query],
                    capture_output=True, text=True, timeout=30,
                )
                try:
                    data = json.loads(result.stdout)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    if not exploits:
                        return f"No Exploit-DB results for: {query}"
                    out = []
                    for e in exploits[:15]:
                        out.append({
                            "title": e.get("Title", ""),
                            "type": e.get("Type", ""),
                            "platform": e.get("Platform", ""),
                            "date": e.get("Date", ""),
                            "path": e.get("Path", ""),
                            "edb_id": e.get("EDB-ID", ""),
                            "url": f"https://www.exploit-db.com/exploits/{e.get('EDB-ID', '')}",
                        })
                    return json.dumps(out, indent=2)
                except json.JSONDecodeError:
                    return result.stdout or result.stderr or "No output from searchsploit"
            except subprocess.TimeoutExpired:
                return "searchsploit timed out"
            except Exception as e:
                return f"searchsploit error: {e}"

        # Fallback: Exploit-DB web search
        q = urllib.parse.quote(query)
        url = f"https://www.exploit-db.com/search?q={q}"
        return (
            f"searchsploit not installed. Search manually at:\n{url}\n\n"
            f"Install: apt install exploitdb  or  git clone https://github.com/offensive-security/exploit-database"
        )

    @function_tool
    async def search_poc_github(
        ctx: RunContextWrapper,
        query: str,
        limit: int = 10,
    ) -> str:
        """Search GitHub for public PoC exploits.

        Args:
            query: Search query, e.g. "CVE-2021-44228", "Apache RCE exploit"
            limit: Max results (default 10)
        """
        q = urllib.parse.quote(f"{query} exploit OR poc OR proof-of-concept")
        url = f"{_GITHUB_API}/search/repositories?q={q}&sort=stars&per_page={limit}"

        data = _http_get(url, headers={
            "User-Agent": "Strix/1.0",
            "Accept": "application/vnd.github.v3+json",
        })

        if isinstance(data, dict) and "error" in data:
            return f"GitHub search error: {data['error']}"

        items = data.get("items", [])
        if not items:
            return f"No GitHub PoC repos found for: {query}"

        results = []
        for item in items[:limit]:
            results.append({
                "name": item.get("full_name", ""),
                "description": item.get("description", "")[:150],
                "stars": item.get("stargazers_count", 0),
                "url": item.get("html_url", ""),
                "updated": item.get("updated_at", "")[:10],
                "language": item.get("language", ""),
            })

        results.sort(key=lambda x: x["stars"], reverse=True)
        return json.dumps(results, indent=2)

    @function_tool
    async def osv_lookup(
        ctx: RunContextWrapper,
        package: str,
        ecosystem: str = "",
        version: str = "",
    ) -> str:
        """Look up vulnerabilities for a package in OSV (Open Source Vulnerabilities).

        Args:
            package: Package name, e.g. "log4j", "django", "lodash"
            ecosystem: Package ecosystem — PyPI, npm, Maven, Go, crates.io, etc. (optional)
            version: Specific version to check, e.g. "1.2.3" (optional)
        """
        payload: dict[str, Any] = {"package": {"name": package}}
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
        if version:
            payload["version"] = version

        req = urllib.request.Request(
            f"{_OSV_API}/query",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Strix/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as e:
            return f"OSV lookup error: {e}"

        vulns = data.get("vulns", [])
        if not vulns:
            return f"No known vulnerabilities found for {package}" + (f" {version}" if version else "") + f" in OSV."

        results = []
        for v in vulns[:15]:
            affected_ranges = []
            for pkg in v.get("affected", []):
                for rng in pkg.get("ranges", []):
                    for event in rng.get("events", []):
                        if "introduced" in event or "fixed" in event:
                            affected_ranges.append(event)

            results.append({
                "id": v.get("id", ""),
                "aliases": v.get("aliases", [])[:3],
                "summary": v.get("summary", "")[:200],
                "severity": [s.get("score", "") for s in v.get("severity", [])],
                "affected_ranges": affected_ranges[:4],
                "published": v.get("published", "")[:10],
                "references": [r["url"] for r in v.get("references", [])[:3]],
            })

        return json.dumps(results, indent=2)

    @function_tool
    async def generate_cve_advisory(
        ctx: RunContextWrapper,
        product: str,
        version: str,
        vuln_type: str,
        description: str,
        cvss_vector: str,
        researcher: str = "Anonymous",
        affected_versions: str = "",
        fixed_version: str = "",
        poc_description: str = "",
        vendor_response: str = "",
        disclosure_date: str = "",
        output_file: str = "",
    ) -> str:
        """Generate a CVE advisory document in standard disclosure format.

        Args:
            product: Affected product name, e.g. "Apache Struts"
            version: Affected version, e.g. "2.5.30"
            vuln_type: Vulnerability type, e.g. "Remote Code Execution"
            description: Technical description of the vulnerability
            cvss_vector: CVSS v3.1 vector string
            researcher: Discoverer name/handle
            affected_versions: Range like "<= 2.5.30" or "2.5.0 - 2.5.30"
            fixed_version: Patched version, e.g. "2.5.31"
            poc_description: Description of proof-of-concept
            vendor_response: Vendor's response and fix information
            disclosure_date: Public disclosure date (YYYY-MM-DD)
            output_file: If set, save advisory to this file in /workspace
        """
        from datetime import date

        # Parse CVSS score
        score_str = cvss_vector
        try:
            from strix.tools.bounty.tools import _cvss31_score
            parts = dict(p.split(":") for p in cvss_vector.replace("CVSS:3.1/", "").split("/"))
            score, label = _cvss31_score(
                parts["AV"], parts["AC"], parts["PR"], parts["UI"], parts["S"],
                parts["C"], parts["I"], parts["A"],
            )
            score_str = f"{score} ({label})\n**Vector:** {cvss_vector}"
        except Exception:
            pass

        today = disclosure_date or date.today().isoformat()

        advisory = f"""# Security Advisory: {vuln_type} in {product} {version}

**CVE ID:** Pending / TBD
**Severity:** {score_str}
**Product:** {product}
**Affected Versions:** {affected_versions or f"<= {version}"}
**Fixed In:** {fixed_version or "See vendor advisory"}
**Researcher:** {researcher}
**Disclosure Date:** {today}

---

## Summary

A {vuln_type.lower()} vulnerability was discovered in {product} version {version}.
{description}

## Technical Details

{description}

## Proof of Concept

{poc_description or 'A proof-of-concept demonstrating the vulnerability has been developed and shared with the vendor.'}

## Impact

An attacker exploiting this vulnerability could potentially compromise the affected system.
The actual impact depends on the deployment context and privileges of the running process.

## Remediation

{f"Update to {product} version {fixed_version} or later." if fixed_version else ""}
{vendor_response or "Contact the vendor for patch availability."}

### Workarounds

If an immediate patch is not possible, consider the following mitigations:
- Restrict network access to the affected service
- Enable WAF rules for the specific attack pattern
- Monitor logs for exploitation attempts

## Timeline

| Date | Event |
|------|-------|
| TBD  | Vulnerability discovered |
| TBD  | Vendor notified |
| TBD  | Vendor confirmed |
| {fixed_version and 'TBD' or 'N/A'}  | Patch released |
| {today} | Public disclosure |

## References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX *(pending)*
- Vendor Advisory: *(pending)*
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1#{cvss_vector}

---
*This advisory was generated by Strix Security Scanner.*
"""

        if output_file:
            from pathlib import Path
            out = Path(f"/workspace/{output_file}") if not output_file.startswith("/") else Path(output_file)
            out.write_text(advisory, encoding="utf-8")
            return f"Advisory saved to {out}\n\n{advisory}"

        return advisory

else:
    def lookup_cve(*a, **kw): raise ImportError("agents SDK not installed")
    def search_cves(*a, **kw): raise ImportError("agents SDK not installed")
    def search_exploitdb(*a, **kw): raise ImportError("agents SDK not installed")
    def search_poc_github(*a, **kw): raise ImportError("agents SDK not installed")
    def osv_lookup(*a, **kw): raise ImportError("agents SDK not installed")
    def generate_cve_advisory(*a, **kw): raise ImportError("agents SDK not installed")
