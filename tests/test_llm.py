"""Tests for LLM synthesis (prompt building, redaction, map-reduce, DI).

No network calls: a fake ``chat`` function is injected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eks_log_analyzer.cli import analyze_log_dir
from eks_log_analyzer.config import AnalysisConfig, Config
from eks_log_analyzer.llm import (
    LLMUnavailable,
    build_user_prompt,
    synthesize,
)
from eks_log_analyzer.redact import default_redactor

RULEBOOK = Path(__file__).resolve().parents[1] / "config" / "eks-signatures.yaml"


def _result(sample_export):
    return analyze_log_dir(sample_export, RULEBOOK)


class _Recorder:
    """Fake chat that records every call and returns canned content."""

    def __init__(self, reply: str = "### Ranked hypotheses\n- ok") -> None:
        self.calls: list[list[dict]] = []
        self.reply = reply

    def __call__(self, messages: list[dict]) -> str:
        self.calls.append(messages)
        return self.reply


def test_synthesize_requires_key_without_chat(sample_export) -> None:
    result = _result(sample_export)
    with pytest.raises(LLMUnavailable):
        synthesize(result, Config(), api_key=None)


def test_build_user_prompt_is_redacted(sample_export) -> None:
    result = _result(sample_export)
    prompt = build_user_prompt(result, default_redactor(), max_events=500)
    # kube-proxy.log contains a literal IP in the throttling line.
    assert "10.100.0.1" not in prompt
    assert "<IP>" in prompt
    # Finding ids must be present so the model can cite them.
    assert "cni-ip-exhaustion" in prompt


def test_synthesize_single_shot(sample_export) -> None:
    result = _result(sample_export)
    chat = _Recorder()
    out = synthesize(result, Config(), chat=chat)
    assert out == "### Ranked hypotheses\n- ok"
    assert len(chat.calls) == 1
    # System prompt present and the user content is redacted.
    sys_msg, user_msg = chat.calls[0]
    assert sys_msg["role"] == "system"
    assert "senior SRE" in sys_msg["content"]
    assert "10.100.0.1" not in user_msg["content"]


def test_synthesize_map_reduce_when_over_budget(sample_export) -> None:
    result = _result(sample_export)
    # Tiny budget forces multiple map shards + one reduce call.
    cfg = Config(analysis=AnalysisConfig(max_input_chars=400, max_events_in_llm_context=500))
    chat = _Recorder(reply="notes")
    synthesize(result, cfg, chat=chat)
    # More than a single call means map-reduce kicked in (>=2 maps + 1 reduce).
    assert len(chat.calls) >= 2
    # The final (reduce) call should reference the full findings index.
    last_user = chat.calls[-1][1]["content"]
    assert "All findings" in last_user
    assert "Preliminary notes" in last_user


def test_map_reduce_never_leaks_raw_ip(sample_export) -> None:
    result = _result(sample_export)
    cfg = Config(analysis=AnalysisConfig(max_input_chars=400, max_events_in_llm_context=500))
    chat = _Recorder(reply="notes")
    synthesize(result, cfg, chat=chat)
    for messages in chat.calls:
        for msg in messages:
            assert "10.100.0.1" not in msg["content"]
