"""Render an :class:`AnalysisResult` to a Markdown report.

Sections: Summary, Timeline, Findings (with file:line evidence), Suggested
checks. Phase 3 will append an LLM synthesis section after Findings.
"""

from __future__ import annotations

from datetime import datetime

from .models import AnalysisResult, Finding, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

# How many evidence lines to show per finding in the report.
_MAX_EVIDENCE_IN_REPORT = 10
# How many entries to render in the timeline table.
_MAX_TIMELINE_ROWS = 50


def _fmt_ts(ts: datetime | None) -> str:
    return ts.isoformat() if ts else "—"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(
    result: AnalysisResult,
    *,
    generated_at: datetime | None = None,
    llm_section: str | None = None,
) -> str:
    """Return a full Markdown report for ``result``.

    If ``llm_section`` is provided, it is inserted (under an "LLM synthesis"
    header) after the deterministic Findings section.
    """
    lines: list[str] = []
    lines.append("# EKS Log Analysis Report")
    lines.append("")
    lines.extend(_summary_section(result, generated_at))
    lines.append("")
    lines.extend(_timeline_section(result))
    lines.append("")
    lines.extend(_findings_section(result))
    lines.append("")
    if llm_section:
        lines.extend(_llm_section(llm_section))
        lines.append("")
    lines.extend(_checks_section(result))
    lines.append("")
    return "\n".join(lines)


def _llm_section(content: str) -> list[str]:
    return [
        "## LLM synthesis",
        "",
        "> AI-generated. Based on the deterministic findings above; verify before acting.",
        "",
        content.strip(),
    ]


def _summary_section(result: AnalysisResult, generated_at: datetime | None) -> list[str]:
    findings = result.sorted_findings()
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    out = ["## Summary", ""]
    gen = generated_at or datetime.now().astimezone()
    out.append(f"- **Generated:** {gen.isoformat()}")
    out.append(f"- **Log directory:** `{result.log_dir}`")
    out.append(f"- **Files scanned:** {result.files_scanned}")
    out.append(f"- **Events parsed:** {result.events_total}")
    if result.has_window:
        out.append(
            f"- **Incident window:** {_fmt_ts(result.window_start)} → {_fmt_ts(result.window_end)}"
            f" ({result.events_in_window} events in window)"
        )
    out.append(f"- **Findings:** {len(findings)}")

    sev_bits = [
        f"{_SEVERITY_EMOJI[sev]} {counts[sev]} {sev.value}"
        for sev in Severity
        if counts[sev]
    ]
    if sev_bits:
        out.append(f"- **By severity:** {', '.join(sev_bits)}")

    if result.timeline:
        first = next((t for t in result.timeline if t.is_first_signal), None)
        if first is not None:
            out.append(
                f"- **First signal:** {_fmt_ts(first.ts)} — `{first.ref}` "
                f"({first.finding_id})"
            )
    return out


def _timeline_section(result: AnalysisResult) -> list[str]:
    out = ["## Timeline", ""]
    if not result.timeline:
        out.append("_No timestamped notable events._")
        return out

    out.append("Cross-source ordering of notable events (from finding evidence).")
    out.append("")
    out.append("| Time (UTC) | Source | Finding | Location | Event |")
    out.append("|------------|--------|---------|----------|-------|")
    for entry in result.timeline[:_MAX_TIMELINE_ROWS]:
        marker = " ⭐" if entry.is_first_signal else ""
        text = _md_escape(entry.text.strip())
        if len(text) > 120:
            text = text[:117] + "…"
        out.append(
            f"| {_fmt_ts(entry.ts)}{marker} | {entry.source.value} | "
            f"{entry.finding_id} | `{entry.ref}` | {text} |"
        )
    if len(result.timeline) > _MAX_TIMELINE_ROWS:
        out.append("")
        out.append(f"_…and {len(result.timeline) - _MAX_TIMELINE_ROWS} more events._")
    out.append("")
    out.append("⭐ = first signal.")
    return out


def _findings_section(result: AnalysisResult) -> list[str]:
    findings = result.sorted_findings()
    out = ["## Findings", ""]
    if not findings:
        out.append("No known signatures matched. Logs may be clean, or coverage gaps exist.")
        return out

    for f in findings:
        out.extend(_one_finding(f))
        out.append("")
    return out


def _one_finding(f: Finding) -> list[str]:
    emoji = _SEVERITY_EMOJI[f.severity]
    out = [f"### {emoji} `{f.id}` — {f.title}"]
    out.append("")
    out.append(f"- **Severity:** {f.severity.value}")
    out.append(f"- **Matches:** {f.count}")
    if f.description:
        out.append(f"- **What it means:** {f.description.strip()}")
    out.append("")
    out.append("**Evidence:**")
    out.append("")
    out.append("```text")
    for ev in f.evidence[:_MAX_EVIDENCE_IN_REPORT]:
        out.append(f"{ev.ref}: {ev.text.strip()}")
    if f.count > _MAX_EVIDENCE_IN_REPORT:
        out.append(f"... ({f.count - _MAX_EVIDENCE_IN_REPORT} more)")
    out.append("```")
    return out


def _checks_section(result: AnalysisResult) -> list[str]:
    findings = result.sorted_findings()
    out = ["## Suggested checks", ""]
    any_hint = False
    for f in findings:
        if not f.hints:
            continue
        any_hint = True
        out.append(f"**`{f.id}`**")
        for hint in f.hints:
            out.append(f"- [ ] {hint}")
        out.append("")
    if not any_hint:
        out.append("_No remediation hints available for the current findings._")
    return out


def write_report(
    result: AnalysisResult,
    path,
    *,
    generated_at: datetime | None = None,
    llm_section: str | None = None,
) -> None:
    """Write the Markdown report to ``path`` (UTF-8)."""
    from pathlib import Path

    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        render_markdown(result, generated_at=generated_at, llm_section=llm_section),
        encoding="utf-8",
    )
