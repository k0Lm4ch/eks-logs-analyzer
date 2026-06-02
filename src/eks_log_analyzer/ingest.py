"""Walk a log export directory and classify files by source."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Source

# Filenames/paths we never want to treat as log content.
_SKIP_SUFFIXES = {".gz", ".zip", ".tar", ".tgz", ".png", ".jpg", ".pdf"}
_SKIP_NAMES = {".ds_store", "thumbs.db"}

# Ordered (source, pattern) rules. First match wins, so put specific patterns
# before generic ones. Patterns match against the lowercased relative path.
_SOURCE_PATTERNS: list[tuple[Source, re.Pattern[str]]] = [
    (Source.AWS_NODE, re.compile(r"aws[-_]?node|ipamd|vpc[-_]?cni|\bcni\b")),
    (Source.KUBE_PROXY, re.compile(r"kube[-_]?proxy")),
    (Source.KUBELET, re.compile(r"kubelet")),
    (Source.CONTAINERD, re.compile(r"containerd|dockerd|cri[-_]?o")),
    (Source.DMESG, re.compile(r"dmesg|kern\.log|kernel")),
    (Source.EVENTS, re.compile(r"events|describe")),
    (Source.MESSAGES, re.compile(r"messages|syslog|journal")),
    (Source.POD, re.compile(r"(^|/)pods?(/|[-_])|/containers?/")),
]

_TEXT_SUFFIXES = {".log", ".txt", ".json", ".out", ".yaml", ".yml", ""}


@dataclass(frozen=True)
class IngestedFile:
    """A file selected for analysis with its detected source."""

    path: Path
    rel_path: str
    source: Source


def detect_source(rel_path: str) -> Source:
    """Classify a file's source from its (relative) path/name."""
    key = rel_path.replace("\\", "/").lower()
    for source, pattern in _SOURCE_PATTERNS:
        if pattern.search(key):
            return source
    return Source.UNKNOWN


def _looks_like_text(path: Path) -> bool:
    if path.suffix.lower() in _SKIP_SUFFIXES:
        return False
    if path.suffix.lower() not in _TEXT_SUFFIXES:
        # Allow rotated logs like messages.1
        if not re.search(r"(log|messages|dmesg|syslog)", path.name.lower()):
            return False
    return True


def ingest_dir(log_dir: str | Path) -> list[IngestedFile]:
    """Recursively collect candidate log files under ``log_dir``.

    Raises:
        FileNotFoundError: if the directory does not exist.
        NotADirectoryError: if the path is not a directory.
    """
    root = Path(log_dir)
    if not root.exists():
        raise FileNotFoundError(f"Log directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    results: list[IngestedFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.lower() in _SKIP_NAMES:
            continue
        if not _looks_like_text(path):
            continue
        rel = path.relative_to(root).as_posix()
        results.append(IngestedFile(path=path, rel_path=rel, source=detect_source(rel)))
    return results
