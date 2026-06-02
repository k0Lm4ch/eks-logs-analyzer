"""Timeline helpers: event ordering, incident-window filtering, and a
notable-event timeline built from finding evidence.
"""

from __future__ import annotations

from datetime import datetime

from .models import Evidence, Finding, LogEvent, Severity, TimelineEntry


def order_events(events: list[LogEvent]) -> list[LogEvent]:
    """Return events sorted by timestamp.

    Events without a timestamp sort after timestamped ones, preserving their
    original (file, line) order for stability.
    """
    indexed = list(enumerate(events))
    return [ev for _, ev in sorted(indexed, key=_sort_key)]


def _sort_key(item: tuple[int, LogEvent]):
    idx, ev = item
    if ev.ts is not None:
        return (0, ev.ts.timestamp(), idx)
    return (1, float("inf"), idx)


def filter_events_by_window(
    events: list[LogEvent],
    start: datetime | None = None,
    end: datetime | None = None,
    *,
    keep_undated: bool = True,
) -> list[LogEvent]:
    """Filter events to an inclusive ``[start, end]`` incident window.

    Args:
        start: lower bound (inclusive) or ``None`` for open-ended.
        end: upper bound (inclusive) or ``None`` for open-ended.
        keep_undated: when ``True``, events with no parseable timestamp are
            retained (we can't prove they're outside the window). When a window
            is active you may set this ``False`` to drop them.

    Returns:
        The filtered list (input order preserved). If both bounds are ``None``
        the original list is returned unchanged.
    """
    if start is None and end is None:
        return events

    out: list[LogEvent] = []
    for ev in events:
        if ev.ts is None:
            if keep_undated:
                out.append(ev)
            continue
        if start is not None and ev.ts < start:
            continue
        if end is not None and ev.ts > end:
            continue
        out.append(ev)
    return out


def first_signal(findings: list[Finding]) -> Evidence | None:
    """Return the earliest timestamped evidence across all findings.

    Falls back to the first piece of evidence if none have timestamps.
    """
    all_ev = [e for f in findings for e in f.evidence]
    if not all_ev:
        return None
    timestamped = [e for e in all_ev if e.ts is not None]
    if timestamped:
        return min(timestamped, key=lambda e: e.ts)  # type: ignore[arg-type, return-value]
    return all_ev[0]


def build_timeline(findings: list[Finding], *, limit: int | None = None) -> list[TimelineEntry]:
    """Build a cross-source, time-ordered timeline from finding evidence.

    Each piece of evidence becomes one entry tagged with its finding id and
    severity. Entries are sorted by timestamp (undated last). The earliest
    timestamped entry is flagged ``is_first_signal``.
    """
    entries: list[TimelineEntry] = []
    for finding in findings:
        for ev in finding.evidence:
            entries.append(
                TimelineEntry(
                    ts=ev.ts,
                    source=_infer_source(ev),
                    file=ev.file,
                    line_no=ev.line_no,
                    text=ev.text,
                    finding_id=finding.id,
                    severity=finding.severity,
                )
            )

    entries.sort(key=_timeline_sort_key)

    for entry in entries:
        if entry.ts is not None:
            entry.is_first_signal = True
            break

    if limit is not None and limit >= 0:
        return entries[:limit]
    return entries


def _timeline_sort_key(entry: TimelineEntry):
    if entry.ts is not None:
        return (0, entry.ts.timestamp(), entry.file, entry.line_no)
    return (1, float("inf"), entry.file, entry.line_no)


def _infer_source(ev: Evidence):
    """Best-effort source tag from the evidence file path.

    Evidence doesn't carry the source, so we re-derive it from the file name to
    keep the timeline cross-source-aware without changing the Evidence schema.
    """
    from .ingest import detect_source

    return detect_source(ev.file)


# Re-export for callers that want the severity ordering helper nearby.
__all__ = [
    "Severity",
    "build_timeline",
    "filter_events_by_window",
    "first_signal",
    "order_events",
]
