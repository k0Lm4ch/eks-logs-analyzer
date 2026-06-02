"""Typer CLI entry point: ``eks-log-analyzer``."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from dateutil import parser as dtparser
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import get_api_key, load_config
from .ingest import ingest_dir
from .llm import LLMError, redaction_summary, synthesize
from .models import AnalysisResult, Severity
from .normalize import normalize_files
from .report import write_report
from .rules import DEFAULT_RULEBOOK, load_rulebook, run_rules
from .timeline import build_timeline, filter_events_by_window, first_signal

app = typer.Typer(
    name="eks-log-analyzer",
    help="Analyze exported EKS node logs for SRE-grade findings (offline-first).",
    add_completion=False,
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect the signature rulebook.")
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"eks-log-analyzer {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """eks-log-analyzer command line."""


def _parse_window_bound(value: str | None, *, label: str) -> datetime | None:
    """Parse an ISO-8601 window bound into a UTC datetime."""
    if value is None:
        return None
    try:
        dt = dtparser.parse(value)
    except (ValueError, OverflowError) as exc:
        raise typer.BadParameter(f"{label}: not a valid ISO-8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def analyze_log_dir(
    log_dir: Path,
    rulebook: Path,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> AnalysisResult:
    """Run the analysis pipeline (ingest -> normalize -> window -> rules -> timeline)."""
    files = ingest_dir(log_dir)
    events = normalize_files(files)

    windowed = filter_events_by_window(events, window_start, window_end)
    signatures = load_rulebook(rulebook)
    findings = run_rules(windowed, signatures)
    timeline = build_timeline(findings)

    has_window = window_start is not None or window_end is not None
    return AnalysisResult(
        log_dir=str(log_dir),
        files_scanned=len(files),
        events_total=len(events),
        events_in_window=len(windowed) if has_window else None,
        window_start=window_start,
        window_end=window_end,
        findings=findings,
        events=windowed,
        timeline=timeline,
    )


def _render_summary(result: AnalysisResult) -> None:
    findings = result.sorted_findings()
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    summary = Text()
    summary.append(f"Directory : {result.log_dir}\n")
    summary.append(f"Files     : {result.files_scanned}\n")
    summary.append(f"Events    : {result.events_total}\n")
    if result.has_window:
        start = result.window_start.isoformat() if result.window_start else "-inf"
        end = result.window_end.isoformat() if result.window_end else "+inf"
        summary.append(f"Window    : {start} -> {end}  ({result.events_in_window} events)\n")
    summary.append(f"Findings  : {len(findings)}  ")
    for sev in Severity:
        if counts[sev]:
            summary.append(f"{counts[sev]} {sev.value}  ", style=_SEVERITY_STYLE[sev])

    fs = first_signal(findings)
    if fs is not None:
        when = fs.ts.isoformat() if fs.ts else "unknown time"
        summary.append(f"\nFirst signal: {when}  ({fs.ref})")

    console.print(Panel(summary, title="EKS Log Analysis", border_style="blue"))


def _render_timeline(result: AnalysisResult, *, max_rows: int = 15) -> None:
    if not result.timeline:
        return
    table = Table(title="Timeline (notable events)", header_style="bold")
    table.add_column("Time (UTC)", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Finding", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("Event")

    for entry in result.timeline[:max_rows]:
        when = entry.ts.isoformat() if entry.ts else "—"
        marker = " *" if entry.is_first_signal else ""
        style = _SEVERITY_STYLE[entry.severity]
        text = entry.text.strip()
        if len(text) > 90:
            text = text[:89] + "…"
        table.add_row(
            Text(when + marker, style="bold" if entry.is_first_signal else ""),
            entry.source.value,
            Text(entry.finding_id, style=style),
            entry.ref,
            text,
        )
    console.print(table)
    if len(result.timeline) > max_rows:
        console.print(f"[dim]…and {len(result.timeline) - max_rows} more events "
                      f"(see --report for the full timeline).[/dim]")
    console.print("[dim]* = first signal[/dim]")


def _render_findings(result: AnalysisResult) -> None:
    findings = result.sorted_findings()
    if not findings:
        console.print("[green]No known signatures matched.[/green] "
                      "Logs may be clean, or coverage gaps exist.")
        return

    table = Table(title="Findings", show_lines=True, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("ID", no_wrap=True)
    table.add_column("Title")
    table.add_column("Hits", justify="right", no_wrap=True)
    table.add_column("First evidence")

    for f in findings:
        sev_text = Text(f.severity.value.upper(), style=_SEVERITY_STYLE[f.severity])
        ev = f.evidence[0] if f.evidence else None
        ev_ref = ev.ref if ev else "-"
        table.add_row(sev_text, f.id, f.title, str(f.count), ev_ref)

    console.print(table)

    # Detail blocks: one example evidence line + top hint per finding.
    for f in findings:
        if not f.evidence:
            continue
        ex = f.evidence[0]
        body = Text()
        body.append(f"{ex.ref}\n", style="dim")
        body.append(ex.text.strip()[:300])
        if f.hints:
            body.append("\n\nNext check: ", style="bold")
            body.append(f.hints[0])
        console.print(
            Panel(body, title=f"[{f.severity.value}] {f.id}",
                  border_style=_SEVERITY_STYLE[f.severity].split()[-1])
        )


@app.command()
def analyze(
    log_dir: Path = typer.Argument(..., help="Directory of exported node logs."),
    rulebook: Path = typer.Option(
        DEFAULT_RULEBOOK, "--rulebook", help="Path to the signature YAML rulebook."
    ),
    llm: bool = typer.Option(
        False, "--llm/--no-llm", help="Add LLM root-cause synthesis (needs OPENROUTER_API_KEY)."
    ),
    report: Path | None = typer.Option(
        None, "--report", help="Write a Markdown report to this path."
    ),
    config_path: Path | None = typer.Option(
        None, "--config", help="Path to a config YAML (defaults to config/config.yaml)."
    ),
    window_start: str | None = typer.Option(
        None, "--window-start", help="Only analyze events at/after this ISO-8601 time."
    ),
    window_end: str | None = typer.Option(
        None, "--window-end", help="Only analyze events at/before this ISO-8601 time."
    ),
) -> None:
    """Analyze a log directory and print findings."""
    start = _parse_window_bound(window_start, label="--window-start")
    end = _parse_window_bound(window_end, label="--window-end")
    if start is not None and end is not None and start > end:
        raise typer.BadParameter("--window-start must be <= --window-end")

    try:
        result = analyze_log_dir(log_dir, rulebook, window_start=start, window_end=end)
    except (FileNotFoundError, NotADirectoryError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    _render_summary(result)
    _render_timeline(result)
    _render_findings(result)

    llm_section = _maybe_run_llm(result, llm, config_path)

    if report is not None:
        write_report(result, report, llm_section=llm_section)
        console.print(f"\n[green]Report written:[/green] {report}")


def _maybe_run_llm(result: AnalysisResult, enabled: bool, config_path: Path | None) -> str | None:
    """Run LLM synthesis if requested; degrade gracefully on missing key/errors."""
    if not enabled:
        return None
    if not result.findings:
        err_console.print("[yellow]Skipping --llm: no deterministic findings to explain.[/yellow]")
        return None

    config = load_config(config_path)
    api_key = get_api_key()
    if not api_key:
        err_console.print(
            "[yellow]--llm requested but OPENROUTER_API_KEY is not set; "
            "continuing with offline analysis only.[/yellow]"
        )
        return None

    counts = redaction_summary(
        result, config, max_events=config.analysis.max_events_in_llm_context
    )
    if counts:
        summary = ", ".join(f"{n} {cat}" for cat, n in sorted(counts.items()))
        console.print(f"[dim]Redacting before send: {summary}.[/dim]")

    try:
        with console.status(f"Querying {config.llm.model} via {config.llm.provider}…"):
            section = synthesize(result, config, api_key=api_key)
    except LLMError as exc:
        err_console.print(f"[red]LLM synthesis failed:[/red] {exc}")
        return None

    console.print(Panel(Markdown(section), title="LLM synthesis", border_style="magenta"))
    return section


@rules_app.command("list")
def rules_list(
    rulebook: Path = typer.Option(
        DEFAULT_RULEBOOK, "--rulebook", help="Path to the signature YAML rulebook."
    ),
) -> None:
    """List all signature ids in the rulebook."""
    try:
        signatures = load_rulebook(rulebook)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Signatures ({len(signatures)})", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    table.add_column("Sources")
    for sig in sorted(signatures, key=lambda s: (s.severity.rank, s.id)):
        sources = ", ".join(s.value for s in sig.sources) or "(any)"
        sev_text = Text(sig.severity.value.upper(), style=_SEVERITY_STYLE[sig.severity])
        table.add_row(sig.id, sev_text, sig.title, sources)
    console.print(table)


if __name__ == "__main__":
    app()
