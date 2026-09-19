"""Parallel multi-target scanning for Strix.

Runs Strix scans against multiple targets concurrently. The number of
simultaneous scans is controlled by STRIX_PARALLEL_TARGETS (default: 3).

Usage::
    from strix.core.parallel_scanner import run_parallel_scans
    results = await run_parallel_scans(
        targets=["https://a.example.com", "https://b.example.com"],
        scan_fn=your_scan_function,   # async fn(target: str) -> ScanResult
    )
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

_DEFAULT_PARALLEL = 3
_MAX_PARALLEL = 10


def _get_parallelism() -> int:
    raw = os.environ.get("STRIX_PARALLEL_TARGETS", "").strip()
    if not raw:
        return _DEFAULT_PARALLEL
    try:
        n = int(raw)
        return max(1, min(n, _MAX_PARALLEL))
    except ValueError:
        logger.warning("Invalid STRIX_PARALLEL_TARGETS=%r — using default %d", raw, _DEFAULT_PARALLEL)
        return _DEFAULT_PARALLEL


@dataclass
class TargetResult:
    target: str
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    duration_s: float = 0.0
    scan_id: str = ""


@dataclass
class ParallelScanSummary:
    targets: list[str]
    results: list[TargetResult]
    total_duration_s: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def failed_targets(self) -> list[str]:
        return [r.target for r in self.results if not r.success]

    @property
    def all_findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in self.results:
            for f in r.findings:
                out.append({**f, "_target": r.target})
        return out


ScanFn = Callable[[str], Awaitable[TargetResult]]


async def run_parallel_scans(
    targets: list[str],
    scan_fn: ScanFn,
    parallelism: int | None = None,
) -> ParallelScanSummary:
    """Run scan_fn(target) for each target, with bounded concurrency.

    Args:
        targets:     List of target URLs/hosts.
        scan_fn:     Async function: async def scan(target: str) -> TargetResult
        parallelism: Max concurrent scans. Defaults to STRIX_PARALLEL_TARGETS env var.

    Returns:
        ParallelScanSummary with all results and aggregated findings.
    """
    if not targets:
        return ParallelScanSummary(targets=[], results=[])

    n = parallelism if parallelism is not None else _get_parallelism()
    sem = asyncio.Semaphore(n)
    start = time.monotonic()

    logger.info(
        "Starting parallel scan: %d targets, parallelism=%d",
        len(targets), n,
    )

    async def _scan_with_sem(target: str) -> TargetResult:
        async with sem:
            logger.info("[parallel] Starting scan of %s", target)
            t0 = time.monotonic()
            try:
                result = await scan_fn(target)
                result.duration_s = round(time.monotonic() - t0, 2)
                logger.info(
                    "[parallel] Done %s — %d findings in %.1fs",
                    target, len(result.findings), result.duration_s,
                )
                return result
            except Exception as exc:
                duration = round(time.monotonic() - t0, 2)
                logger.error("[parallel] Failed %s after %.1fs: %s", target, duration, exc)
                return TargetResult(
                    target=target,
                    success=False,
                    error=str(exc),
                    duration_s=duration,
                )

    results = await asyncio.gather(*[_scan_with_sem(t) for t in targets])

    summary = ParallelScanSummary(
        targets=targets,
        results=list(results),
        total_duration_s=round(time.monotonic() - start, 2),
    )

    logger.info(
        "Parallel scan complete: %d/%d targets OK, %d total findings in %.1fs",
        sum(1 for r in results if r.success),
        len(targets),
        summary.total_findings,
        summary.total_duration_s,
    )
    return summary


def parse_targets(raw: str) -> list[str]:
    """Parse a comma or newline-separated list of targets into a clean list.

    Also handles a single target string.
    """
    targets: list[str] = []
    for part in raw.replace(",", "\n").splitlines():
        t = part.strip()
        if t and not t.startswith("#"):
            targets.append(t)
    return list(dict.fromkeys(targets))  # deduplicate, preserve order
