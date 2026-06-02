"""Pydantic models shared across the pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Source(StrEnum):
    """Normalized log source tags."""

    KUBELET = "kubelet"
    CONTAINERD = "containerd"
    AWS_NODE = "aws-node"
    KUBE_PROXY = "kube-proxy"
    DMESG = "dmesg"
    MESSAGES = "messages"
    POD = "pod"
    EVENTS = "events"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Finding severity, ordered most-to-least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Lower rank == more severe (useful for sorting)."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        return order[self]


class LogEvent(BaseModel):
    """A single normalized log line."""

    ts: datetime | None = Field(
        default=None, description="UTC timestamp if parseable, else None."
    )
    source: Source = Field(description="Normalized source tag.")
    file: str = Field(description="Path to the originating file (relative to log dir).")
    line_no: int = Field(description="1-based line number within the file.")
    text: str = Field(description="Raw log line text (trailing newline stripped).")


class Evidence(BaseModel):
    """A log line that triggered a finding, with provenance."""

    file: str
    line_no: int
    text: str
    ts: datetime | None = None

    @property
    def ref(self) -> str:
        """`file:line` citation string."""
        return f"{self.file}:{self.line_no}"


class Finding(BaseModel):
    """A deterministic match against a signature rule."""

    id: str = Field(description="Signature id that matched.")
    title: str
    severity: Severity
    description: str = ""
    matched_rule: str = Field(description="Signature id (provenance of the match).")
    hints: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.evidence)


class TimelineEntry(BaseModel):
    """A notable, time-ordered event derived from finding evidence."""

    ts: datetime | None = None
    source: Source
    file: str
    line_no: int
    text: str
    finding_id: str
    severity: Severity
    is_first_signal: bool = False

    @property
    def ref(self) -> str:
        return f"{self.file}:{self.line_no}"


class AnalysisResult(BaseModel):
    """Top-level result of analyzing a log directory."""

    log_dir: str
    files_scanned: int = 0
    events_total: int = 0
    events_in_window: int | None = Field(
        default=None, description="Event count after applying the incident window, if any."
    )
    window_start: datetime | None = None
    window_end: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    events: list[LogEvent] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)

    @property
    def has_window(self) -> bool:
        return self.window_start is not None or self.window_end is not None

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered by severity then by evidence count desc."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, -f.count, f.id),
        )
