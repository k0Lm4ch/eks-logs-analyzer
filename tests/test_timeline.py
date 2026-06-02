"""Tests for timeline ordering and normalization helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from eks_log_analyzer.models import Evidence, Finding, LogEvent, Severity, Source
from eks_log_analyzer.normalize import parse_timestamp
from eks_log_analyzer.timeline import (
    build_timeline,
    filter_events_by_window,
    first_signal,
    order_events,
)


def _ev(ts: datetime | None, text: str, *, src=Source.KUBELET, file="a.log", line=1) -> LogEvent:
    return LogEvent(ts=ts, source=src, file=file, line_no=line, text=text)


def test_parse_rfc3339() -> None:
    dt = parse_timestamp("2024-05-01T12:00:01.100Z [INFO] hello")
    assert dt == datetime(2024, 5, 1, 12, 0, 1, 100000, tzinfo=UTC)


def test_parse_klog() -> None:
    dt = parse_timestamp("E0501 12:00:30.654321 1234 file.go:1] boom", assume_year=2024)
    assert dt is not None
    assert (dt.month, dt.day, dt.hour, dt.minute, dt.second) == (5, 1, 12, 0, 30)
    assert dt.tzinfo == UTC


def test_parse_syslog() -> None:
    dt = parse_timestamp("May  1 12:00:40 host kernel: oom", assume_year=2024)
    assert dt is not None
    assert (dt.month, dt.day, dt.hour) == (5, 1, 12)


def test_parse_no_timestamp() -> None:
    assert parse_timestamp("plain line without time") is None


def test_order_events_sorts_by_ts_then_keeps_undated_last() -> None:
    e_late = LogEvent(
        ts=datetime(2024, 5, 1, 12, 5, tzinfo=UTC),
        source=Source.KUBELET, file="a", line_no=2, text="late",
    )
    e_early = LogEvent(
        ts=datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
        source=Source.KUBELET, file="a", line_no=1, text="early",
    )
    e_none = LogEvent(ts=None, source=Source.POD, file="b", line_no=1, text="undated")

    ordered = order_events([e_late, e_none, e_early])
    assert [e.text for e in ordered] == ["early", "late", "undated"]


def test_first_signal_picks_earliest_timestamp() -> None:
    findings = [
        Finding(
            id="x", title="X", severity=Severity.HIGH, matched_rule="x",
            evidence=[
                Evidence(file="a", line_no=5, text="later",
                         ts=datetime(2024, 5, 1, 12, 10, tzinfo=UTC)),
                Evidence(file="a", line_no=2, text="earliest",
                         ts=datetime(2024, 5, 1, 12, 1, tzinfo=UTC)),
            ],
        )
    ]
    sig = first_signal(findings)
    assert sig is not None
    assert sig.text == "earliest"


def test_first_signal_none_when_empty() -> None:
    assert first_signal([]) is None


def test_filter_window_no_bounds_returns_input() -> None:
    events = [_ev(datetime(2024, 5, 1, 12, 0, tzinfo=UTC), "a")]
    assert filter_events_by_window(events, None, None) is events


def test_filter_window_inclusive_bounds() -> None:
    e1 = _ev(datetime(2024, 5, 1, 11, 59, tzinfo=UTC), "before", line=1)
    e2 = _ev(datetime(2024, 5, 1, 12, 0, tzinfo=UTC), "start-edge", line=2)
    e3 = _ev(datetime(2024, 5, 1, 12, 30, tzinfo=UTC), "inside", line=3)
    e4 = _ev(datetime(2024, 5, 1, 13, 0, tzinfo=UTC), "end-edge", line=4)
    e5 = _ev(datetime(2024, 5, 1, 13, 1, tzinfo=UTC), "after", line=5)

    out = filter_events_by_window(
        [e1, e2, e3, e4, e5],
        datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
        datetime(2024, 5, 1, 13, 0, tzinfo=UTC),
    )
    assert [e.text for e in out] == ["start-edge", "inside", "end-edge"]


def test_filter_window_undated_handling() -> None:
    dated = _ev(datetime(2024, 5, 1, 12, 30, tzinfo=UTC), "dated", line=1)
    undated = _ev(None, "undated", line=2)
    bounds = (datetime(2024, 5, 1, 12, 0, tzinfo=UTC), datetime(2024, 5, 1, 13, 0, tzinfo=UTC))

    kept = filter_events_by_window([dated, undated], *bounds, keep_undated=True)
    assert [e.text for e in kept] == ["dated", "undated"]

    dropped = filter_events_by_window([dated, undated], *bounds, keep_undated=False)
    assert [e.text for e in dropped] == ["dated"]


def test_build_timeline_orders_and_marks_first_signal() -> None:
    findings = [
        Finding(
            id="cni", title="CNI", severity=Severity.CRITICAL, matched_rule="cni",
            evidence=[
                Evidence(file="aws-node.log", line_no=3, text="later ip fail",
                         ts=datetime(2024, 5, 1, 12, 5, tzinfo=UTC)),
            ],
        ),
        Finding(
            id="pleg", title="PLEG", severity=Severity.HIGH, matched_rule="pleg",
            evidence=[
                Evidence(file="kubelet.log", line_no=2, text="earliest pleg",
                         ts=datetime(2024, 5, 1, 12, 1, tzinfo=UTC)),
                Evidence(file="kubelet.log", line_no=9, text="undated tail", ts=None),
            ],
        ),
    ]
    timeline = build_timeline(findings)
    assert [t.text for t in timeline] == ["earliest pleg", "later ip fail", "undated tail"]
    # First signal is the earliest timestamped entry.
    assert timeline[0].is_first_signal
    assert sum(1 for t in timeline if t.is_first_signal) == 1
    # Source is inferred from the file path.
    assert timeline[0].source == Source.KUBELET
    assert timeline[1].source == Source.AWS_NODE


def test_build_timeline_limit() -> None:
    findings = [
        Finding(
            id="x", title="X", severity=Severity.LOW, matched_rule="x",
            evidence=[
                Evidence(file="a.log", line_no=i,
                         text=f"e{i}", ts=datetime(2024, 5, 1, 12, i, tzinfo=UTC))
                for i in range(5)
            ],
        )
    ]
    assert len(build_timeline(findings, limit=2)) == 2
