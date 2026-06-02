"""Tests for Markdown report generation and the windowed pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from eks_log_analyzer.cli import analyze_log_dir
from eks_log_analyzer.report import render_markdown, write_report

RULEBOOK = Path(__file__).resolve().parents[1] / "config" / "eks-signatures.yaml"


def _analyze(sample_export, **kw):
    return analyze_log_dir(sample_export, RULEBOOK, **kw)


def test_report_has_required_sections(sample_export) -> None:
    result = _analyze(sample_export)
    md = render_markdown(result, generated_at=datetime(2024, 5, 1, tzinfo=UTC))

    for header in ("# EKS Log Analysis Report", "## Summary", "## Timeline",
                   "## Findings", "## Suggested checks"):
        assert header in md, f"missing section: {header}"


def test_report_includes_file_line_evidence(sample_export) -> None:
    result = _analyze(sample_export)
    md = render_markdown(result)
    # Every finding's first evidence ref (file:line) must appear in the report.
    for f in result.findings:
        assert f.evidence
        assert f.evidence[0].ref in md


def test_report_timeline_shows_cross_source_and_first_signal(sample_export) -> None:
    result = _analyze(sample_export)
    md = render_markdown(result)
    # Cross-source ordering: at least two distinct sources appear in the timeline.
    sources = {t.source for t in result.timeline}
    assert len(sources) >= 2
    # First-signal marker rendered.
    assert "⭐" in md


def test_report_embeds_llm_section(sample_export) -> None:
    result = _analyze(sample_export)
    md = render_markdown(result, llm_section="### Ranked hypotheses\n- cni first")
    assert "## LLM synthesis" in md
    assert "AI-generated" in md
    assert "cni first" in md
    # LLM section sits between Findings and Suggested checks.
    assert md.index("## Findings") < md.index("## LLM synthesis") < md.index("## Suggested checks")


def test_write_report_creates_file(tmp_path, sample_export) -> None:
    result = _analyze(sample_export)
    out = tmp_path / "nested" / "report.md"
    write_report(result, out)
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("# EKS Log Analysis Report")


def test_window_filter_changes_event_count(sample_export) -> None:
    full = _analyze(sample_export)
    # The fixtures span 12:00:00 - 12:01:30Z. Narrow to the first ~7 seconds.
    windowed = _analyze(
        sample_export,
        window_start=datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC),
        window_end=datetime(2024, 5, 1, 12, 0, 8, tzinfo=UTC),
    )
    assert windowed.has_window
    assert windowed.events_in_window is not None
    # Window keeps undated lines but drops dated ones outside the range, so the
    # in-window count should not exceed the total parsed events.
    assert windowed.events_in_window <= full.events_total
    # The early CNI exhaustion signal is inside the window...
    assert "cni-ip-exhaustion" in {f.id for f in windowed.findings}
    # ...while a later-only signal (EBS mount at ~12:01:20) is excluded.
    assert "ebs-csi-mount" not in {f.id for f in windowed.findings}
