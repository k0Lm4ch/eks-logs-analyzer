"""Redaction of sensitive tokens before any content leaves the process.

Every string sent to the LLM in :mod:`eks_log_analyzer.llm` is passed through a
:class:`Redactor` first. Redaction is intentionally conservative and ordered:
ARNs (which embed account ids) and credential-like tokens are scrubbed before
the more generic account-id / IP patterns run.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .config import RedactConfig

# (category, placeholder, compiled pattern). Order matters — see module docstring.
_ARN = (
    "arn",
    "<ARN>",
    re.compile(r"arn:aws[a-z\-]*:[^\s\"']+"),
)
_AWS_ACCESS_KEY = (
    "token",
    "<TOKEN>",
    re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA)[0-9A-Z]{12,}\b"),
)
_BEARER = (
    "token",
    "Bearer <TOKEN>",
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),
)
_SK_KEY = (
    "token",
    "<TOKEN>",
    re.compile(r"\bsk-[A-Za-z0-9\-]{8,}\b"),
)
_JWT = (
    "token",
    "<TOKEN>",
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
)
_EMAIL = (
    "email",
    "<EMAIL>",
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
)
_ACCOUNT_ID = (
    "account_id",
    "<ACCOUNT_ID>",
    re.compile(r"\b\d{12}\b"),
)
_IPV4 = (
    "ip",
    "<IP>",
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
)
_IPV6 = (
    "ip",
    "<IP>",
    re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b"),
)


@dataclass
class Redactor:
    """Applies configured redactions to text and tracks how much it scrubbed."""

    config: RedactConfig

    def _rules(self):
        cfg = self.config
        rules = []
        # ARNs first so embedded account ids/regions aren't half-redacted.
        if cfg.arn:
            rules.append(_ARN)
        if cfg.bearer_tokens:
            rules.extend([_AWS_ACCESS_KEY, _BEARER, _SK_KEY, _JWT])
        if cfg.emails:
            rules.append(_EMAIL)
        if cfg.account_id:
            rules.append(_ACCOUNT_ID)
        if cfg.ip:
            rules.extend([_IPV4, _IPV6])
        return rules

    def redact(self, text: str) -> str:
        """Return ``text`` with all enabled categories scrubbed."""
        out = text
        for _category, placeholder, pattern in self._rules():
            out = pattern.sub(placeholder, out)
        return out

    def redact_counted(self, text: str, counter: Counter[str]) -> str:
        """Like :meth:`redact` but increments ``counter`` per category hit."""
        out = text
        for category, placeholder, pattern in self._rules():
            out, n = pattern.subn(placeholder, out)
            if n:
                counter[category] += n
        return out

    def redact_lines(self, lines: list[str]) -> list[str]:
        return [self.redact(line) for line in lines]


def default_redactor() -> Redactor:
    return Redactor(RedactConfig())
