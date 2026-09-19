"""Subdomain discovery tools for Strix.

Wraps subfinder/amass for fast subdomain enumeration, with a pure-Python
DNS fallback when neither external tool is installed.

External tools (faster, more results):
  subfinder: https://docs.projectdiscovery.io/tools/subfinder/install
  amass:     https://github.com/owasp-amass/amass

Usage::
    # As agent tools — registered via @function_tool
    discover_subdomains(ctx, domain="example.com")
    check_recon_tools(ctx)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import socket
from typing import Any

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)

_COMMON_PREFIXES = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "api", "dev", "staging",
    "test", "admin", "portal", "app", "mobile", "static", "cdn", "vpn",
    "git", "gitlab", "github", "jira", "confluence", "docs", "wiki",
    "beta", "prod", "uat", "qa", "db", "database", "mysql", "postgres",
    "redis", "elasticsearch", "kibana", "grafana", "prometheus", "jenkins",
    "ci", "build", "deploy", "monitor", "metrics", "logs", "sentry",
    "ns1", "ns2", "mx", "smtp1", "smtp2", "webmail", "cpanel", "whm",
    "shop", "store", "blog", "forum", "community", "support", "helpdesk",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "internal", "intranet", "corp", "remote", "secure", "ssl",
]
_MAX_DNS_WORKERS = 20
_DNS_TIMEOUT = 2.0


def _is_valid_domain(d: str) -> bool:
    return bool(re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', d))


async def _dns_probe(hostname: str) -> str | None:
    """Return hostname if it resolves, else None."""
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, hostname),
            timeout=_DNS_TIMEOUT,
        )
        return hostname
    except Exception:
        return None


async def _dns_bruteforce(domain: str) -> list[str]:
    """Probe common subdomain prefixes via DNS resolution."""
    candidates = [f"{p}.{domain}" for p in _COMMON_PREFIXES]
    sem = asyncio.Semaphore(_MAX_DNS_WORKERS)

    async def probe_with_sem(h: str) -> str | None:
        async with sem:
            return await _dns_probe(h)

    results = await asyncio.gather(*[probe_with_sem(c) for c in candidates])
    return [r for r in results if r]


async def _run_subfinder(domain: str, timeout: int = 60) -> list[str] | None:
    path = shutil.which("subfinder")
    if not path:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "-d", domain, "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]
    except Exception as exc:
        logger.debug("subfinder failed: %s", exc)
        return None


async def _run_amass(domain: str, timeout: int = 120) -> list[str] | None:
    path = shutil.which("amass")
    if not path:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "enum", "-passive", "-d", domain, "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]
    except Exception as exc:
        logger.debug("amass failed: %s", exc)
        return None


async def _discover_subdomains_async(domain: str, timeout: int = 120) -> dict[str, Any]:
    """Discover subdomains using the best available tool, then DNS fallback."""
    if not _is_valid_domain(domain):
        return {"error": f"Invalid domain: {domain!r}"}

    tool_used = "dns-bruteforce"
    subdomains: list[str] = []

    # Prefer subfinder → amass → DNS bruteforce.
    sf = await _run_subfinder(domain, timeout=min(timeout, 60))
    if sf is not None:
        subdomains = sf
        tool_used = "subfinder"
    else:
        am = await _run_amass(domain, timeout=min(timeout, 90))
        if am is not None:
            subdomains = am
            tool_used = "amass"
        else:
            subdomains = await _dns_bruteforce(domain)

    # Deduplicate and sort.
    subdomains = sorted(set(s.lower() for s in subdomains if s))

    # Probe IPs for the discovered subdomains (best-effort).
    ip_map: dict[str, str] = {}
    loop = asyncio.get_event_loop()
    for sub in subdomains[:50]:  # cap to avoid huge requests
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, sub),
                timeout=1.5,
            )
            ip_map[sub] = ip
        except Exception:
            ip_map[sub] = ""

    return {
        "domain": domain,
        "tool_used": tool_used,
        "total": len(subdomains),
        "subdomains": [
            {"hostname": s, "ip": ip_map.get(s, "")}
            for s in subdomains
        ],
    }


# ─── Agent tools ──────────────────────────────────────────────────────────────

if _HAS_AGENTS:
    @function_tool
    async def check_recon_tools(ctx: RunContextWrapper) -> str:
        """Check which subdomain/recon tools are installed on this system.

        Returns a status summary for subfinder, amass, and the built-in DNS fallback.
        """
        lines = []
        for name in ("subfinder", "amass", "nmap", "httpx", "dnsx"):
            path = shutil.which(name)
            lines.append(f"{'✅' if path else '❌'} {name}: {path or 'not found'}")
        lines.append("✅ dns-bruteforce: always available (built-in)")
        return "\n".join(lines)

    @function_tool
    async def discover_subdomains(
        ctx: RunContextWrapper,
        domain: str,
        timeout_seconds: int = 120,
    ) -> str:
        """Discover subdomains for a given domain.

        Uses subfinder if installed, falls back to amass, then to a built-in
        DNS bruteforce against ~50 common subdomain prefixes.

        Args:
            domain:           The root domain to enumerate (e.g. example.com).
            timeout_seconds:  Max seconds to wait (default 120).

        Returns:
            JSON with discovered subdomains and their resolved IPs.
        """
        if not domain:
            return "Error: domain is required."

        result = await _discover_subdomains_async(domain.strip().lower(), timeout=timeout_seconds)

        if result.get("error"):
            return f"Recon error: {result['error']}"

        subs = result.get("subdomains", [])
        if not subs:
            return f"No subdomains discovered for {domain}."

        return json.dumps({
            "domain": domain,
            "tool_used": result.get("tool_used"),
            "total": result.get("total"),
            "subdomains": subs,
        }, indent=2, ensure_ascii=False)

    @function_tool
    async def dns_lookup(
        ctx: RunContextWrapper,
        hostname: str,
    ) -> str:
        """Resolve a hostname to its IP address(es).

        Args:
            hostname: The hostname to look up (e.g. api.example.com).

        Returns:
            Resolved IP(s) or an error message.
        """
        if not hostname:
            return "Error: hostname is required."
        try:
            loop = asyncio.get_event_loop()
            results = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, hostname, None),
                timeout=5.0,
            )
            ips = sorted({r[4][0] for r in results})
            return f"{hostname} → {', '.join(ips)}"
        except Exception as exc:
            return f"DNS lookup failed for {hostname}: {exc}"

else:
    async def check_recon_tools() -> str:  # type: ignore[misc]
        return "agents SDK not installed"

    async def discover_subdomains(domain: str, **_: Any) -> str:  # type: ignore[misc]
        return "agents SDK not installed"

    async def dns_lookup(hostname: str) -> str:  # type: ignore[misc]
        return "agents SDK not installed"
