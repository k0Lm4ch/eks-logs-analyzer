"""Tests for the signature rulebook and rule engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from eks_log_analyzer.ingest import ingest_dir
from eks_log_analyzer.models import LogEvent, Source
from eks_log_analyzer.normalize import normalize_files
from eks_log_analyzer.rules import load_rulebook, run_rules

SIGNATURE_SNIPPETS = Path(__file__).resolve().parent / "fixtures" / "signatures"

# Map each signature id to a source it applies to, so the source filter passes.
_SNIPPET_SOURCE = {
    "cni-ip-exhaustion": Source.AWS_NODE,
    "cni-aws-node": Source.AWS_NODE,
    "kubelet-pleg": Source.KUBELET,
    "kubelet-disk-pressure": Source.KUBELET,
    "kubelet-memory-pressure": Source.KUBELET,
    "container-oomkilled": Source.DMESG,
    "image-pull-failure": Source.KUBELET,
    "dns-failure": Source.POD,
    "tls-x509": Source.KUBELET,
    "irsa-oidc": Source.AWS_NODE,
    "api-throttling": Source.AWS_NODE,
    "ebs-csi-mount": Source.KUBELET,
}


def test_rulebook_loads_min_signatures(rulebook_path: Path) -> None:
    sigs = load_rulebook(rulebook_path)
    assert len(sigs) >= 10, "AGENTS.md requires >=10 signatures"
    ids = {s.id for s in sigs}
    assert len(ids) == len(sigs), "signature ids must be unique"


@pytest.mark.parametrize("sig_id", sorted(_SNIPPET_SOURCE))
def test_each_signature_matches_its_snippet(sig_id: str, rulebook_path: Path) -> None:
    snippet = SIGNATURE_SNIPPETS / f"{sig_id}.txt"
    assert snippet.exists(), f"missing fixture snippet for {sig_id}"

    source = _SNIPPET_SOURCE[sig_id]
    events = [
        LogEvent(ts=None, source=source, file=snippet.name, line_no=i, text=line)
        for i, line in enumerate(snippet.read_text(encoding="utf-8").splitlines(), start=1)
        if line.strip()
    ]

    sigs = load_rulebook(rulebook_path)
    findings = run_rules(events, sigs)
    found_ids = {f.id for f in findings}
    assert sig_id in found_ids, f"{sig_id} should match its own snippet (got {found_ids})"


def test_source_filter_excludes_wrong_source(rulebook_path: Path) -> None:
    # An aws-node-only pattern should NOT match when the source is kube-proxy.
    events = [
        LogEvent(
            ts=None,
            source=Source.KUBE_PROXY,
            file="kube-proxy.log",
            line_no=1,
            text="no available IP addresses in datastore",
        )
    ]
    sigs = load_rulebook(rulebook_path)
    findings = run_rules(events, sigs)
    assert "cni-ip-exhaustion" not in {f.id for f in findings}


def test_sample_export_produces_findings(sample_export, rulebook_path: Path) -> None:
    files = ingest_dir(sample_export)
    events = normalize_files(files)
    sigs = load_rulebook(rulebook_path)
    findings = run_rules(events, sigs)
    assert findings, "sample export should produce at least one finding"
    found = {f.id for f in findings}
    # Spot-check a few we know are present in the fixtures.
    assert "cni-ip-exhaustion" in found
    assert "image-pull-failure" in found
    # Every finding must carry evidence with file:line provenance.
    for f in findings:
        assert f.evidence
        assert all(e.line_no >= 1 and e.file for e in f.evidence)
