"""Parse ingested files into normalized :class:`LogEvent` records."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from dateutil import parser as dtparser

from .ingest import IngestedFile
from .models import LogEvent, Source

# Common timestamp shapes seen in EKS node logs. We extract a candidate
# substring then let dateutil parse it (robust to minor variants).
_TS_PATTERNS: list[re.Pattern[str]] = [
    # 2024-05-01T12:34:56.789Z / +00:00  (klog, JSON, RFC3339)
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    # klog short:  I0501 12:34:56.789012  -> month/day + time (year assumed current)
    re.compile(r"^[IWEF](\d{2})(\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    # syslog:  May  1 12:34:56
    re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
    # dmesg kernel uptime: [12345.678901]  -> not a wall clock; skip
]

_KLOG_RE = re.compile(r"^[IWEF](\d{2})(\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_RFC_RE = _TS_PATTERNS[0]


def parse_timestamp(text: str, *, assume_year: int | None = None) -> datetime | None:
    """Best-effort extraction of a UTC timestamp from a log line.

    Returns a timezone-aware UTC datetime, or ``None`` if no timestamp is found.
    """
    assume_year = assume_year or datetime.now(UTC).year

    m = _RFC_RE.search(text)
    if m:
        try:
            dt = dtparser.parse(m.group(1))
            return _to_utc(dt)
        except (ValueError, OverflowError):
            pass

    m = _KLOG_RE.match(text)
    if m:
        month, day, time_str = m.group(1), m.group(2), m.group(3)
        try:
            dt = dtparser.parse(f"{assume_year}-{month}-{day} {time_str}")
            return _to_utc(dt)
        except (ValueError, OverflowError):
            pass

    m = _SYSLOG_RE.match(text)
    if m:
        try:
            dt = dtparser.parse(f"{m.group(1)} {assume_year}")
            return _to_utc(dt)
        except (ValueError, OverflowError):
            pass

    return None


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def detect_reference_year(files: list[IngestedFile]) -> int | None:
    """Scan files for the first full-date (RFC3339-ish) timestamp and return
    its year.

    Klog (``I0501 ...``) and syslog (``May  1 ...``) formats omit the year; we
    anchor them to the year actually observed in the dataset so the timeline
    stays coherent instead of defaulting every undated-year line to "now".
    """
    for f in files:
        try:
            with f.path.open("r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    m = _RFC_RE.search(raw)
                    if not m:
                        continue
                    try:
                        return dtparser.parse(m.group(1)).year
                    except (ValueError, OverflowError):
                        continue
        except OSError:
            continue
    return None


def normalize_file(ingested: IngestedFile, *, assume_year: int | None = None) -> list[LogEvent]:
    """Read one file and emit a :class:`LogEvent` per non-empty line."""
    events: list[LogEvent] = []
    try:
        with ingested.path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw in enumerate(fh, start=1):
                text = raw.rstrip("\n").rstrip("\r")
                if not text.strip():
                    continue
                events.append(
                    LogEvent(
                        ts=parse_timestamp(text, assume_year=assume_year),
                        source=ingested.source,
                        file=ingested.rel_path,
                        line_no=line_no,
                        text=text,
                    )
                )
    except OSError:
        return events
    return events


def normalize_files(
    files: list[IngestedFile], *, assume_year: int | None = None
) -> list[LogEvent]:
    """Normalize many files into a flat list of events.

    If ``assume_year`` is not given, it is inferred from the first full-date
    timestamp found in the dataset (see :func:`detect_reference_year`).
    """
    if assume_year is None:
        assume_year = detect_reference_year(files)
    events: list[LogEvent] = []
    for f in files:
        events.extend(normalize_file(f, assume_year=assume_year))
    return events


def source_label(source: Source) -> str:
    return source.value
