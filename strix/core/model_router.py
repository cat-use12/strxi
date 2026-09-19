"""Multi-model router for Strix — pick the right LLM for each task type.

Strix supports three model roles:

  main  — primary agent: deep reasoning, exploit planning, report generation.
           Configured via STRIX_LLM (required). Use your best/most capable model here.

  fast  — optional fast/cheap model for high-volume, low-complexity tasks:
           port scan summaries, recon lookups, header parsing, quick grep.
           Configured via STRIX_LLM_FAST. Falls back to main when unset.
           Use a fast cheap model here (e.g. groq/llama-3.1-8b-instant).

  code  — optional code-specialised model for deep code analysis:
           PoC exploit review, dependency CVE triage, source code audit.
           Configured via STRIX_LLM_CODE. Falls back to main when unset.
           Use a code model here (e.g. ollama/qwen2.5-coder:14b).

Example .env for all three:
    STRIX_LLM=groq/llama-3.3-70b-versatile        # main: best model
    STRIX_LLM_FAST=groq/llama-3.1-8b-instant      # fast: cheap + quick
    STRIX_LLM_CODE=ollama/qwen2.5-coder:14b        # code: local, private

Or mix providers — cloud for speed, local for privacy:
    STRIX_LLM=gemini/gemini-2.0-flash
    STRIX_LLM_CODE=ollama/phi4
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

ModelRole = Literal["main", "fast", "code"]

_ROLE_DESCRIPTIONS = {
    "main": "primary reasoning",
    "fast": "fast/cheap tasks (recon, lookups)",
    "code": "code analysis (exploits, CVE triage)",
}


@dataclass(frozen=True)
class ResolvedModel:
    """A resolved model name + its optional API credentials."""

    name: str
    api_key: str | None = None
    api_base: str | None = None
    extra_headers: dict[str, str] | None = None
    role: ModelRole = "main"

    def __str__(self) -> str:
        return self.name


class ModelRouter:
    """Resolves the correct model for a given task role.

    Build once per scan run from the loaded settings, then call resolve(role)
    to get the model name + credentials for that role.
    """

    def __init__(self, settings: object) -> None:
        """
        Args:
            settings: A loaded strix.config.settings.Settings instance.
        """
        self._settings = settings
        self._resolved: dict[ModelRole, ResolvedModel] = {}
        self._log_config()

    def _log_config(self) -> None:
        s = self._settings
        main_name = (s.llm.model or "").strip() or "(not set)"
        fast_name = (s.fast_model.model or "").strip() or f"→ fallback to main ({main_name})"
        code_name = (s.code_model.model or "").strip() or f"→ fallback to main ({main_name})"
        logger.info(
            "ModelRouter: main=%s | fast=%s | code=%s",
            main_name, fast_name, code_name,
        )

    def resolve(self, role: ModelRole = "main") -> ResolvedModel:
        """Return the ResolvedModel for the given role, with fallback to main."""
        if role in self._resolved:
            return self._resolved[role]

        s = self._settings
        main_model = (s.llm.model or "").strip() or None

        if role == "main":
            result = ResolvedModel(
                name=main_model or "",
                api_key=s.llm.api_key,
                api_base=s.llm.api_base,
                extra_headers=s.llm.extra_headers,
                role="main",
            )
        elif role == "fast":
            fast_name = (s.fast_model.model or "").strip() or None
            if fast_name:
                result = ResolvedModel(
                    name=fast_name,
                    api_key=s.fast_model.api_key or s.llm.api_key,
                    api_base=s.fast_model.api_base or s.llm.api_base,
                    extra_headers=s.fast_model.extra_headers or s.llm.extra_headers,
                    role="fast",
                )
                logger.debug("ModelRouter: fast role → %s", fast_name)
            else:
                result = self.resolve("main")
                logger.debug("ModelRouter: fast role → fallback to main (%s)", result.name)
        elif role == "code":
            code_name = (s.code_model.model or "").strip() or None
            if code_name:
                result = ResolvedModel(
                    name=code_name,
                    api_key=s.code_model.api_key or s.llm.api_key,
                    api_base=s.code_model.api_base or s.llm.api_base,
                    extra_headers=s.code_model.extra_headers or s.llm.extra_headers,
                    role="code",
                )
                logger.debug("ModelRouter: code role → %s", code_name)
            else:
                result = self.resolve("main")
                logger.debug("ModelRouter: code role → fallback to main (%s)", result.name)
        else:
            raise ValueError(f"Unknown model role: {role!r}. Use 'main', 'fast', or 'code'.")

        self._resolved[role] = result
        return result

    def model_name(self, role: ModelRole = "main") -> str:
        """Shortcut: just the model name string for the given role."""
        return self.resolve(role).name

    def summary(self) -> dict[str, str]:
        """Return a human-readable summary of all configured models."""
        s = self._settings
        return {
            "main": (s.llm.model or "").strip() or "(not configured)",
            "fast": (s.fast_model.model or "").strip() or "(uses main)",
            "code": (s.code_model.model or "").strip() or "(uses main)",
        }


# Module-level singleton — populated on first use by get_router().
_router: ModelRouter | None = None


def get_router() -> ModelRouter:
    """Return the process-wide ModelRouter, building it lazily from settings."""
    global _router
    if _router is None:
        from strix.config.loader import load_settings
        _router = ModelRouter(load_settings())
    return _router


def reset_router() -> None:
    """Reset the singleton (for testing or when settings change mid-process)."""
    global _router
    _router = None


def model_for(role: ModelRole = "main") -> str:
    """Convenience: get model name for a role in one call.

    Usage::
        from strix.core.model_router import model_for
        model = model_for("code")   # e.g. "ollama/qwen2.5-coder:14b"
    """
    return get_router().model_name(role)
