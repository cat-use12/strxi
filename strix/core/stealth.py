"""Stealth/throttling profiles for Strix scan requests.

Reduces scanner fingerprint to avoid triggering WAF/IDS rate-limiting and
detection. Configure via STRIX_STEALTH environment variable:

  STRIX_STEALTH=silent      very slow, max stealth  (5–15s per request)
  STRIX_STEALTH=slow        slow scan               (2–5s per request)
  STRIX_STEALTH=normal      balanced (default)      (0.3–1.5s per request)
  STRIX_STEALTH=aggressive  fast, easily detected   (0–0.2s per request)
  STRIX_STEALTH=off         no delays at all

Usage::
    from strix.core.stealth import get_stealth_config, StealthConfig
    cfg = get_stealth_config()
    await asyncio.sleep(cfg.next_delay())
    headers["User-Agent"] = cfg.next_user_agent()
"""

from __future__ import annotations

import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

StealthLevel = Literal["off", "aggressive", "normal", "slow", "silent"]

# Realistic browser User-Agent strings — rotate to avoid scanner fingerprinting.
_USER_AGENTS: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# (min_seconds, max_seconds) delay ranges per profile.
_DELAY_RANGES: dict[StealthLevel, tuple[float, float]] = {
    "off":        (0.0,  0.0),
    "aggressive": (0.0,  0.2),
    "normal":     (0.3,  1.5),
    "slow":       (2.0,  5.0),
    "silent":     (5.0, 15.0),
}

_LEVEL_DESCRIPTIONS: dict[StealthLevel, str] = {
    "off":        "no delays — maximum speed",
    "aggressive": "0–200ms jitter — fast but detectable",
    "normal":     "300ms–1.5s jitter — balanced (default)",
    "slow":       "2–5s delays — slow scan, harder to detect",
    "silent":     "5–15s delays — maximum stealth",
}


@dataclass
class StealthConfig:
    """Active stealth configuration for this scan run."""

    level: StealthLevel = "normal"
    rotate_user_agents: bool = True
    _rng: random.Random = field(default_factory=random.Random, repr=False)
    _ua_index: int = field(default=0, repr=False)
    _request_count: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self._rng.seed(int(time.time() * 1000) % (2**32))
        self._ua_index = self._rng.randint(0, len(_USER_AGENTS) - 1)
        logger.info(
            "StealthConfig: level=%s (%s) ua_rotation=%s",
            self.level,
            _LEVEL_DESCRIPTIONS.get(self.level, ""),
            self.rotate_user_agents,
        )

    def next_delay(self) -> float:
        """Return seconds to sleep before the next request. 0.0 when level is 'off'."""
        lo, hi = _DELAY_RANGES[self.level]
        if lo == hi == 0.0:
            return 0.0
        # Add extra pause every ~10 requests to mimic human browsing rhythm.
        base = self._rng.uniform(lo, hi)
        if self.level in ("slow", "silent") and self._request_count > 0 and self._request_count % 10 == 0:
            base += self._rng.uniform(lo, hi * 2)
        self._request_count += 1
        return round(base, 3)

    def next_user_agent(self) -> str:
        """Return the next User-Agent string (rotates on each call when enabled)."""
        ua = _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]
        if self.rotate_user_agents:
            # Advance index with small random skip so rotation is not perfectly sequential.
            self._ua_index += self._rng.randint(1, 3)
        return ua

    def request_headers(self, existing: dict[str, str] | None = None) -> dict[str, str]:
        """Merge stealth headers into an existing header dict (returns a new dict)."""
        headers: dict[str, str] = dict(existing or {})
        if self.level != "off":
            headers.setdefault("User-Agent", self.next_user_agent())
            # Mimic real browser Accept headers.
            headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            headers.setdefault("Accept-Language", "en-US,en;q=0.9")
            headers.setdefault("Accept-Encoding", "gzip, deflate, br")
            if self.level in ("slow", "silent"):
                # Avoid cache hits that would make timing inconsistent.
                headers["Cache-Control"] = "no-cache"
                headers["Pragma"] = "no-cache"
        return headers

    @property
    def description(self) -> str:
        return f"stealth={self.level} — {_LEVEL_DESCRIPTIONS.get(self.level, '')}"


def _parse_level(raw: str) -> StealthLevel:
    val = raw.strip().lower()
    if val in _DELAY_RANGES:
        return val  # type: ignore[return-value]
    # Aliases
    aliases: dict[str, StealthLevel] = {
        "0": "off", "false": "off", "none": "off",
        "1": "aggressive", "fast": "aggressive",
        "2": "normal", "default": "normal", "medium": "normal",
        "3": "slow",
        "4": "silent", "paranoid": "silent", "ghost": "silent",
    }
    mapped = aliases.get(val)
    if mapped:
        return mapped
    logger.warning(
        "Unknown STRIX_STEALTH value %r — falling back to 'normal'. "
        "Valid: off, aggressive, normal, slow, silent",
        raw,
    )
    return "normal"


# Process-level singleton.
_config: StealthConfig | None = None


def get_stealth_config() -> StealthConfig:
    """Return the process-wide StealthConfig, built lazily from env."""
    global _config
    if _config is None:
        raw = os.environ.get("STRIX_STEALTH", "normal").strip()
        level = _parse_level(raw)
        rotate = os.environ.get("STRIX_STEALTH_ROTATE_UA", "true").lower() not in ("0", "false", "no")
        _config = StealthConfig(level=level, rotate_user_agents=rotate)
    return _config


def reset_stealth_config() -> None:
    """Reset singleton (for tests or profile switches)."""
    global _config
    _config = None
