"""Optional LLM synthesis via an OpenAI-compatible endpoint (OpenRouter).

Contract (non-negotiables):
- This is the *only* module that performs outbound network calls.
- Every excerpt of log/finding text is passed through :mod:`redact` first.
- Offline analysis never depends on this module; the CLI degrades gracefully
  when no API key is present.

The model is asked to *explain and prioritize* the deterministic findings — it
must cite finding ids or quoted (redacted) log lines and must not invent
findings. Large inputs are handled with a map-reduce over findings.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from .config import Config
from .models import AnalysisResult, Finding
from .redact import Redactor

# Type of the injectable chat function: takes chat messages, returns content.
ChatFn = Callable[[list[dict]], str]

SYSTEM_PROMPT = """\
You are a senior SRE/DevOps engineer specializing in Amazon EKS node and \
control-plane adjacent failures. You receive:

1. Deterministic findings (already matched from logs by a rule engine).
2. A timeline of notable events.
3. Redacted log excerpts.

Rules:
- Rank root causes by confidence (high/medium/low).
- For each hypothesis, cite specific evidence: a finding id (e.g. `cni-ip-exhaustion`)
  or a quoted log line with its file:line reference.
- Separate symptom vs root cause vs contributing factors.
- Provide kubectl/AWS CLI checks to confirm or rule out each hypothesis.
- Provide remediation and prevention (runbooks, monitoring, limits).
- If evidence is insufficient, say so; do not invent resources, metrics, or findings.
- Do not contradict the deterministic findings; if you disagree, mark it as uncertainty.
- Never recommend destructive actions without calling out blast radius and rollback.

Output Markdown with exactly these sections:
### Ranked hypotheses
### Next checks
### Fixes
"""

_MAP_INSTRUCTION = """\
This is ONE SHARD of a larger incident (shard {n} of {total}). Produce concise \
preliminary notes about likely root causes for ONLY the findings below, citing \
finding ids or file:line log lines. Do not write final sections yet.
"""

_REDUCE_INSTRUCTION = """\
Below are (a) the full list of deterministic findings and (b) preliminary notes \
from analyzing shards of the evidence. Synthesize the FINAL answer using the \
required sections. Cite finding ids or file:line references.
"""

# Reserve part of the char budget for the system prompt + instructions overhead.
_OVERHEAD_CHARS = 4000
_MAX_EVIDENCE_PER_FINDING = 8


class LLMError(RuntimeError):
    """Generic LLM failure."""


class LLMUnavailable(LLMError):
    """Raised when synthesis is requested but no API key is configured."""


def _render_finding(finding: Finding, redactor: Redactor) -> str:
    lines = [
        f"- finding `{finding.id}` ({finding.severity.value}) — "
        f"{redactor.redact(finding.title)} [{finding.count} matches]"
    ]
    if finding.description:
        lines.append(f"  meaning: {redactor.redact(finding.description.strip())}")
    for ev in finding.evidence[:_MAX_EVIDENCE_PER_FINDING]:
        lines.append(f"  evidence {ev.ref}: {redactor.redact(ev.text.strip())}")
    extra = finding.count - _MAX_EVIDENCE_PER_FINDING
    if extra > 0:
        lines.append(f"  (+{extra} more matches)")
    return "\n".join(lines)


def _render_timeline(result: AnalysisResult, redactor: Redactor, *, max_events: int) -> str:
    if not result.timeline:
        return "(no timestamped notable events)"
    out = []
    for entry in result.timeline[:max_events]:
        ts = entry.ts.isoformat() if entry.ts else "—"
        marker = " [FIRST SIGNAL]" if entry.is_first_signal else ""
        out.append(
            f"{ts}{marker} {entry.source.value} {entry.finding_id} "
            f"{entry.ref}: {redactor.redact(entry.text.strip())}"
        )
    return "\n".join(out)


def _findings_index(result: AnalysisResult, redactor: Redactor) -> str:
    """Compact id/title/severity index (no evidence) for the reduce step."""
    return "\n".join(
        f"- `{f.id}` ({f.severity.value}, {f.count} matches): {redactor.redact(f.title)}"
        for f in result.sorted_findings()
    )


def build_user_prompt(result: AnalysisResult, redactor: Redactor, *, max_events: int) -> str:
    """Build the single-shot user prompt (used when input fits the budget)."""
    findings_block = "\n".join(_render_finding(f, redactor) for f in result.sorted_findings())
    timeline_block = _render_timeline(result, redactor, max_events=max_events)
    return (
        f"Log directory: {result.log_dir}\n"
        f"Files scanned: {result.files_scanned}; events parsed: {result.events_total}\n\n"
        f"## Deterministic findings\n{findings_block or '(none)'}\n\n"
        f"## Timeline\n{timeline_block}\n"
    )


def _chunk_findings(
    result: AnalysisResult, redactor: Redactor, budget: int
) -> list[list[Finding]]:
    """Greedily group findings so each shard's rendered size fits ``budget``."""
    shards: list[list[Finding]] = []
    current: list[Finding] = []
    current_len = 0
    for finding in result.sorted_findings():
        block = _render_finding(finding, redactor)
        blen = len(block) + 1
        if current and current_len + blen > budget:
            shards.append(current)
            current, current_len = [], 0
        current.append(finding)
        current_len += blen
    if current:
        shards.append(current)
    return shards or [[]]


def synthesize(
    result: AnalysisResult,
    config: Config,
    *,
    api_key: str | None = None,
    chat: ChatFn | None = None,
) -> str:
    """Return the LLM synthesis Markdown for ``result``.

    Args:
        api_key: OpenRouter key; required unless ``chat`` is injected (tests).
        chat: optional chat function ``(messages) -> content`` for testing/DI.

    Raises:
        LLMUnavailable: if neither ``chat`` nor ``api_key`` is provided.
    """
    if chat is None:
        if not api_key:
            raise LLMUnavailable(
                "LLM synthesis requested but OPENROUTER_API_KEY is not set."
            )
        chat = _make_openrouter_chat(config, api_key)

    redactor = Redactor(config.redact)
    max_events = config.analysis.max_events_in_llm_context
    max_chars = config.analysis.max_input_chars

    single_prompt = build_user_prompt(result, redactor, max_events=max_events)
    if len(single_prompt) <= max_chars:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": single_prompt},
        ]
        return chat(messages).strip()

    return _map_reduce(result, redactor, chat, max_events=max_events, max_chars=max_chars)


def _map_reduce(
    result: AnalysisResult,
    redactor: Redactor,
    chat: ChatFn,
    *,
    max_events: int,
    max_chars: int,
) -> str:
    budget = max(1000, max_chars - _OVERHEAD_CHARS)
    shards = _chunk_findings(result, redactor, budget)

    notes: list[str] = []
    for i, shard in enumerate(shards, start=1):
        shard_block = "\n".join(_render_finding(f, redactor) for f in shard)
        user = (
            _MAP_INSTRUCTION.format(n=i, total=len(shards))
            + "\n\n## Findings in this shard\n"
            + (shard_block or "(none)")
        )
        notes.append(
            chat(
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ]
            ).strip()
        )

    timeline_block = _render_timeline(result, redactor, max_events=max_events)
    reduce_user = (
        _REDUCE_INSTRUCTION
        + "\n\n## All findings\n"
        + _findings_index(result, redactor)
        + "\n\n## Timeline\n"
        + timeline_block
        + "\n\n## Preliminary notes\n"
        + "\n\n---\n\n".join(notes)
    )
    return chat(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": reduce_user},
        ]
    ).strip()


def _make_openrouter_chat(config: Config, api_key: str) -> ChatFn:
    """Build a chat function backed by the OpenAI-compatible OpenRouter API."""
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - dependency declared in pyproject
        raise LLMError("The 'openai' package is required for --llm.") from exc

    client = OpenAI(base_url=config.llm.base_url, api_key=api_key)

    def _chat(messages: list[dict]) -> str:
        try:
            resp = client.chat.completions.create(
                model=config.llm.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=config.llm.temperature,
                max_tokens=config.llm.max_tokens,
                extra_headers={
                    "HTTP-Referer": "https://github.com/eks-log-analyzer",
                    "X-Title": "eks-log-analyzer",
                },
            )
        except Exception as exc:  # noqa: BLE001 - surface a clean CLI error
            raise LLMError(f"LLM request failed: {exc}") from exc
        content = resp.choices[0].message.content if resp.choices else None
        if not content:
            raise LLMError("LLM returned an empty response.")
        return content

    return _chat


def redaction_summary(result: AnalysisResult, config: Config, *, max_events: int) -> Counter[str]:
    """Count what would be redacted from the outbound prompt (for transparency)."""
    redactor = Redactor(config.redact)
    counter: Counter[str] = Counter()
    for finding in result.findings:
        redactor.redact_counted(finding.title, counter)
        redactor.redact_counted(finding.description, counter)
        for ev in finding.evidence:
            redactor.redact_counted(ev.text, counter)
    for entry in result.timeline[:max_events]:
        redactor.redact_counted(entry.text, counter)
    return counter
