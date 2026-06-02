"""Tests for file ingestion and source detection."""

from __future__ import annotations

import pytest

from eks_log_analyzer.ingest import detect_source, ingest_dir
from eks_log_analyzer.models import Source


@pytest.mark.parametrize(
    "rel_path,expected",
    [
        ("aws-node.log", Source.AWS_NODE),
        ("ipamd.log", Source.AWS_NODE),
        ("kube-proxy.log", Source.KUBE_PROXY),
        ("kubelet.log", Source.KUBELET),
        ("containerd.log", Source.CONTAINERD),
        ("dmesg.log", Source.DMESG),
        ("var/log/messages", Source.MESSAGES),
        ("describe-events.txt", Source.EVENTS),
        ("pods/default_web-7c_app.log", Source.POD),
        ("random-thing.log", Source.UNKNOWN),
    ],
)
def test_detect_source(rel_path: str, expected: Source) -> None:
    assert detect_source(rel_path) == expected


def test_ingest_sample_export(sample_export) -> None:
    files = ingest_dir(sample_export)
    assert files, "expected to ingest at least one file"
    sources = {f.source for f in files}
    # The sample export deliberately spans multiple sources.
    assert Source.AWS_NODE in sources
    assert Source.KUBELET in sources
    assert Source.POD in sources


def test_ingest_missing_dir(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        ingest_dir(tmp_path / "does-not-exist")


def test_ingest_not_a_dir(tmp_path) -> None:
    f = tmp_path / "a.log"
    f.write_text("hi", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        ingest_dir(f)
