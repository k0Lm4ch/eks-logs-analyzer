"""Shared test fixtures and paths."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_EXPORT = FIXTURES / "sample-export"
SIGNATURE_SNIPPETS = FIXTURES / "signatures"
RULEBOOK = REPO_ROOT / "config" / "eks-signatures.yaml"


@pytest.fixture(scope="session")
def rulebook_path() -> Path:
    return RULEBOOK


@pytest.fixture(scope="session")
def sample_export() -> Path:
    return SAMPLE_EXPORT
