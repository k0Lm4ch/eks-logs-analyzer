"""Configuration loading.

Merges (in increasing priority):
1. built-in defaults,
2. ``config/config.yaml`` if present, else ``config/config.example.yaml``,
3. environment (``.env`` is loaded if python-dotenv is installed).

Only the ``llm`` and ``redact`` sections matter for Phase 3; ``analysis`` is
carried through for completeness.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

_CONFIG_DIR = Path("config")
_USER_CONFIG = _CONFIG_DIR / "config.yaml"
_EXAMPLE_CONFIG = _CONFIG_DIR / "config.example.yaml"

API_KEY_ENV = "OPENROUTER_API_KEY"


class LLMConfig(BaseModel):
    provider: str = "openrouter"
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "anthropic/claude-3.5-sonnet"
    temperature: float = 0.1
    max_tokens: int = 2500


class RedactConfig(BaseModel):
    ip: bool = True
    account_id: bool = True
    arn: bool = True
    bearer_tokens: bool = True
    emails: bool = True


class AnalysisConfig(BaseModel):
    max_events_in_llm_context: int = 500
    max_input_chars: int = 120000


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    redact: RedactConfig = Field(default_factory=RedactConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration, preferring ``config/config.yaml`` then the example.

    A custom ``path`` overrides the search entirely.
    """
    _load_dotenv()

    if path is not None:
        raw = _read_yaml(Path(path))
    elif _USER_CONFIG.exists():
        raw = _read_yaml(_USER_CONFIG)
    else:
        raw = _read_yaml(_EXAMPLE_CONFIG)

    # Only keep the sections we model; ignore unknown keys (e.g. analysis.window).
    analysis_raw = raw.get("analysis") or {}
    analysis_known = {
        k: analysis_raw[k]
        for k in ("max_events_in_llm_context", "max_input_chars")
        if k in analysis_raw
    }
    return Config(
        llm=LLMConfig(**(raw.get("llm") or {})),
        redact=RedactConfig(**(raw.get("redact") or {})),
        analysis=AnalysisConfig(**analysis_known),
    )


def get_api_key() -> str | None:
    """Return the OpenRouter API key from the environment, if set."""
    _load_dotenv()
    key = os.environ.get(API_KEY_ENV, "").strip()
    return key or None
