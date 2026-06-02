"""Signature rulebook loading and matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Evidence, Finding, LogEvent, Severity, Source

DEFAULT_RULEBOOK = Path("config/eks-signatures.yaml")

# Cap evidence lines kept per finding so a noisy log can't blow up memory/report.
MAX_EVIDENCE_PER_FINDING = 25


@dataclass
class Signature:
    """A compiled signature rule."""

    id: str
    title: str
    severity: Severity
    patterns: list[re.Pattern[str]]
    description: str = ""
    sources: list[Source] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)

    def applies_to(self, source: Source) -> bool:
        return not self.sources or source in self.sources

    def matches(self, text: str) -> bool:
        return any(p.search(text) for p in self.patterns)


class RulebookError(ValueError):
    """Raised when the signature file is malformed."""


def _coerce_sources(raw: object, sig_id: str) -> list[Source]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RulebookError(f"signature '{sig_id}': sources must be a list")
    out: list[Source] = []
    for item in raw:
        try:
            out.append(Source(str(item)))
        except ValueError as exc:
            raise RulebookError(
                f"signature '{sig_id}': unknown source '{item}'"
            ) from exc
    return out


def load_rulebook(path: str | Path = DEFAULT_RULEBOOK) -> list[Signature]:
    """Load and compile signatures from a YAML rulebook."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rulebook not found: {p}")

    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    raw_sigs = data.get("signatures")
    if not isinstance(raw_sigs, list) or not raw_sigs:
        raise RulebookError(f"Rulebook '{p}' has no 'signatures' list")

    signatures: list[Signature] = []
    seen_ids: set[str] = set()
    for entry in raw_sigs:
        if not isinstance(entry, dict):
            raise RulebookError("each signature must be a mapping")
        sig_id = str(entry.get("id", "")).strip()
        if not sig_id:
            raise RulebookError("signature missing 'id'")
        if sig_id in seen_ids:
            raise RulebookError(f"duplicate signature id '{sig_id}'")
        seen_ids.add(sig_id)

        raw_patterns = entry.get("patterns") or []
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise RulebookError(f"signature '{sig_id}': 'patterns' must be a non-empty list")
        try:
            compiled = [re.compile(str(p), re.IGNORECASE) for p in raw_patterns]
        except re.error as exc:
            raise RulebookError(f"signature '{sig_id}': bad regex: {exc}") from exc

        try:
            severity = Severity(str(entry.get("severity", "medium")).lower())
        except ValueError as exc:
            raise RulebookError(
                f"signature '{sig_id}': invalid severity '{entry.get('severity')}'"
            ) from exc

        signatures.append(
            Signature(
                id=sig_id,
                title=str(entry.get("title", sig_id)),
                severity=severity,
                patterns=compiled,
                description=str(entry.get("description", "")).strip(),
                sources=_coerce_sources(entry.get("sources"), sig_id),
                hints=[str(h) for h in (entry.get("hints") or [])],
            )
        )
    return signatures


def run_rules(events: list[LogEvent], signatures: list[Signature]) -> list[Finding]:
    """Match events against signatures and aggregate findings."""
    by_id: dict[str, Finding] = {}

    for event in events:
        for sig in signatures:
            if not sig.applies_to(event.source):
                continue
            if not sig.matches(event.text):
                continue

            finding = by_id.get(sig.id)
            if finding is None:
                finding = Finding(
                    id=sig.id,
                    title=sig.title,
                    severity=sig.severity,
                    description=sig.description,
                    matched_rule=sig.id,
                    hints=list(sig.hints),
                    evidence=[],
                )
                by_id[sig.id] = finding

            if len(finding.evidence) < MAX_EVIDENCE_PER_FINDING:
                finding.evidence.append(
                    Evidence(
                        file=event.file,
                        line_no=event.line_no,
                        text=event.text,
                        ts=event.ts,
                    )
                )

    return list(by_id.values())
