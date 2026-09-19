"""Named scan profiles for Strix.

Profiles are YAML files stored in ~/.strix/profiles/ that bundle common
scan settings so you can switch between them with --profile <name>.

Built-in profiles (overridable by creating a same-named file):
  stealth     — slow + stealth UA rotation + conservative limits
  normal      — balanced defaults
  aggressive  — fast + high turn limit + no delays
  api-only    — no shell/browser tools, API-focused scan
  recon       — subdomain discovery + light fingerprinting, no exploitation

Custom profile example (~/.strix/profiles/myprofile.yaml):
    name: myprofile
    description: My custom scan profile
    stealth: slow
    llm: groq/llama-3.3-70b-versatile
    max_turns: 300
    instruction: Focus on authentication and authorization flaws only.

Usage::
    from strix.config.profiles import load_profile, apply_profile
    profile = load_profile("stealth")
    apply_profile(profile)   # sets env vars
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ─── Built-in profiles ────────────────────────────────────────────────────────

_BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "normal": {
        "name": "normal",
        "description": "Balanced defaults — suitable for most pentest engagements.",
        "stealth": "normal",
    },
    "stealth": {
        "name": "stealth",
        "description": "Slow requests, User-Agent rotation, low noise. Ideal for production targets.",
        "stealth": "slow",
        "stealth_rotate_ua": True,
        "max_turns": 300,
    },
    "silent": {
        "name": "silent",
        "description": "Maximum stealth — very slow, difficult to detect. Use on sensitive targets.",
        "stealth": "silent",
        "stealth_rotate_ua": True,
        "max_turns": 500,
    },
    "aggressive": {
        "name": "aggressive",
        "description": "Fast scan — high turn limit, minimal delays. Easy to detect. Use on lab targets.",
        "stealth": "aggressive",
        "max_turns": 800,
    },
    "api-only": {
        "name": "api-only",
        "description": "API-focused scan — no browser tools, targets REST/GraphQL endpoints.",
        "stealth": "normal",
        "instruction": (
            "Focus exclusively on API security: authentication bypass, IDOR, "
            "injection flaws in API parameters, broken object-level authorization, "
            "mass assignment, and rate limiting issues. "
            "Do not test browser-side XSS or client-side attacks."
        ),
    },
    "recon": {
        "name": "recon",
        "description": "Reconnaissance only — subdomain discovery, fingerprinting, no exploitation.",
        "stealth": "slow",
        "instruction": (
            "Perform reconnaissance only. Enumerate subdomains, identify technologies, "
            "map the attack surface, and document exposed services. "
            "Do NOT attempt any exploitation or send any payloads. "
            "Report findings as informational."
        ),
        "max_turns": 150,
    },
    "quick": {
        "name": "quick",
        "description": "Quick triage scan — top OWASP 10 only, fast turnaround.",
        "stealth": "normal",
        "instruction": (
            "Perform a rapid triage scan covering only the OWASP Top 10. "
            "Focus on quick wins: SQLi, XSS, auth bypass, IDOR, misconfigurations. "
            "Stop after finding the first Critical or 3 High severity issues."
        ),
        "max_turns": 100,
    },
}

# ─── Profile loading ──────────────────────────────────────────────────────────

def _profiles_dir() -> Path:
    env = os.environ.get("STRIX_PROFILES_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".strix" / "profiles"


def list_profiles() -> list[str]:
    """Return all available profile names (built-in + custom)."""
    names = set(_BUILTIN_PROFILES.keys())
    d = _profiles_dir()
    if d.exists():
        for p in d.glob("*.yaml"):
            names.add(p.stem)
        for p in d.glob("*.yml"):
            names.add(p.stem)
    return sorted(names)


def load_profile(name: str) -> dict[str, Any]:
    """Load a profile by name. Custom profiles override built-ins.

    Returns the profile dict, or raises ValueError if not found.
    """
    name = name.strip().lower()

    # Check custom profiles dir first (allows overriding built-ins).
    d = _profiles_dir()
    for ext in ("yaml", "yml"):
        path = d / f"{name}.{ext}"
        if path.exists():
            try:
                import importlib.util
                # Use yaml if available, else manual parse for simple cases.
                try:
                    import yaml  # type: ignore[import-untyped]
                    with path.open(encoding="utf-8") as f:
                        profile = yaml.safe_load(f) or {}
                    logger.info("Loaded custom profile '%s' from %s", name, path)
                    return profile
                except ImportError:
                    # Fall back to built-in if yaml not installed
                    logger.debug("PyYAML not available — skipping custom profile file")
            except Exception as exc:
                logger.warning("Failed to load profile file %s: %s", path, exc)

    # Fall back to built-in.
    if name in _BUILTIN_PROFILES:
        logger.info("Using built-in profile '%s'", name)
        return dict(_BUILTIN_PROFILES[name])

    available = ", ".join(list_profiles())
    raise ValueError(
        f"Profile '{name}' not found. "
        f"Available profiles: {available}. "
        f"Custom profiles go in {_profiles_dir()}/"
    )


def apply_profile(profile: dict[str, Any]) -> None:
    """Apply a loaded profile by setting the corresponding environment variables.

    Only sets variables that are not already set in the environment (env wins).
    """
    name = profile.get("name", "?")
    applied: list[str] = []

    def _setenv(key: str, value: Any) -> None:
        if key not in os.environ and value is not None:
            os.environ[key] = str(value)
            applied.append(f"{key}={value}")

    _setenv("STRIX_STEALTH", profile.get("stealth"))
    _setenv("STRIX_STEALTH_ROTATE_UA", "true" if profile.get("stealth_rotate_ua") else None)
    _setenv("STRIX_MAX_TURNS", profile.get("max_turns"))
    _setenv("STRIX_LLM", profile.get("llm"))
    _setenv("STRIX_PROFILE_INSTRUCTION", profile.get("instruction"))

    if applied:
        logger.info("Profile '%s' applied: %s", name, ", ".join(applied))
    else:
        logger.info("Profile '%s' loaded — all vars already set by environment", name)


def save_profile(name: str, profile: dict[str, Any]) -> Path:
    """Save a profile dict to ~/.strix/profiles/<name>.yaml."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError("PyYAML is required to save profiles: pip install pyyaml") from exc

    d = _profiles_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name.lower()}.yaml"
    profile["name"] = name.lower()
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(profile, f, default_flow_style=False, allow_unicode=True)
    logger.info("Profile '%s' saved to %s", name, path)
    return path


def profile_summary() -> str:
    """Return a human-readable table of all available profiles."""
    lines = ["Available Strix profiles:", ""]
    for name in list_profiles():
        try:
            p = load_profile(name)
            desc = p.get("description") or ""
            stealth = p.get("stealth") or "normal"
            lines.append(f"  {name:<16} stealth={stealth:<12} {desc}")
        except Exception:
            lines.append(f"  {name}")
    return "\n".join(lines)
