"""Tests for redaction helpers."""

from __future__ import annotations

from collections import Counter

from eks_log_analyzer.config import RedactConfig
from eks_log_analyzer.redact import Redactor, default_redactor


def test_redacts_ipv4() -> None:
    r = default_redactor()
    out = r.redact("connection refused to 10.100.0.1:53 from 192.168.1.20")
    assert "10.100.0.1" not in out
    assert "192.168.1.20" not in out
    assert out.count("<IP>") == 2


def test_redacts_account_id_and_arn() -> None:
    r = default_redactor()
    out = r.redact("role arn:aws:iam::123456789012:role/eks-node assumed")
    assert "123456789012" not in out
    assert "<ARN>" in out


def test_redacts_standalone_account_id() -> None:
    r = default_redactor()
    out = r.redact("account 210987654321 throttled")
    assert "210987654321" not in out
    assert "<ACCOUNT_ID>" in out


def test_redacts_tokens() -> None:
    r = default_redactor()
    samples = [
        "Authorization: Bearer abc.def-123",
        "key AKIAIOSFODNN7EXAMPLE leaked",
        "using sk-or-v1-deadbeefcafebabe0123",
    ]
    for s in samples:
        out = r.redact(s)
        assert "<TOKEN>" in out


def test_redacts_email() -> None:
    r = default_redactor()
    out = r.redact("paged oncall@example.com about the node")
    assert "oncall@example.com" not in out
    assert "<EMAIL>" in out


def test_does_not_touch_timestamps_or_versions() -> None:
    r = default_redactor()
    text = "2024-05-01T12:00:06.310Z CNI version v1.18.0 started"
    assert r.redact(text) == text


def test_toggle_disables_category() -> None:
    r = Redactor(RedactConfig(ip=False))
    assert "10.0.0.1" in r.redact("ip 10.0.0.1")


def test_redact_counted_tracks_categories() -> None:
    r = default_redactor()
    counter: Counter[str] = Counter()
    r.redact_counted("10.0.0.1 and 10.0.0.2 mailed bob@x.io", counter)
    assert counter["ip"] == 2
    assert counter["email"] == 1
