"""Machine credentials: API keys, tokens, webhooks, private keys.

The export's live Slack webhook read as a low-severity URL. These rank critical.
"""

from __future__ import annotations

import re
from typing import Iterable

from pii_redactor.model import PiiType, Span

# Each entry is (name, pattern, group). The group lets a pattern require context
# it does not want to report -- `Authorization: Bearer <token>` reports the token.
_PATTERNS: list[tuple[str, str, int]] = [
    # Long-lived provider keys, all self-identifying by prefix.
    ("aws_access_key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 0),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", 0),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", 0),
    ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b", 0),
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b", 0),
    ("twilio_sid", r"\bAC[0-9a-f]{32}\b", 0),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", 0),
    # Webhooks: the path *is* the credential, so the whole URL is the finding.
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", 0),
    ("discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", 0),
    # A JWT carries claims about a person as well as granting access.
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", 0),
    # Credentials in a URL's userinfo, which logs and exports copy verbatim.
    ("url_password", r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:([^\s/@]{4,})@", 1),
    # Labelled secrets. The label is what makes an opaque blob a credential, so
    # the value alone is never enough to match on.
    (
        "labelled_secret",
        r"(?i)\b(?:api[_\-\s]?key|secret[_\-\s]?(?:key|access[_\-\s]?key)?|access[_\-\s]?token"
        r"|auth[_\-\s]?token|password|passwd|client[_\-\s]?secret|private[_\-\s]?key)\b"
        r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=_\-]{12,})[\"']?",
        1,
    ),
    ("bearer_token", r"(?i)\bBearer\s+([A-Za-z0-9_\-.=/+]{16,})", 1),
    ("basic_auth", r"(?i)\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})", 1),
]

# Placeholders that exist to be replaced. Reporting them buries the real ones.
_PLACEHOLDER = re.compile(
    r"^(?:x{4,}|\*{4,}|\.{4,}|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|"
    r"(?:your|my|the|some|test|dummy|sample|example|placeholder|redacted|changeme|"
    r"none|null|nil|todo|fixme|insert|replace)[_\-]?.*)$",
    re.I,
)
# A run with no variety is a mask (`aaaaaaaa`) or a filler, not a key.
_MIN_DISTINCT = 5


def _plausible(value: str) -> bool:
    value = value.strip().strip("\"'")
    if len(value) < 12 or _PLACEHOLDER.match(value):
        return False
    return len(set(value)) >= _MIN_DISTINCT


class SecretDetector:
    """One credential pattern, with a plausibility filter over the match."""

    type = PiiType.SECRET

    def __init__(self, name: str, pattern: str, group: int):
        self.name = name
        self.re = re.compile(pattern)
        self.group = group
        # A private-key header is short and fixed; plausibility does not apply.
        self.check = name not in ("private_key",)

    def find(self, text: str) -> Iterable[Span]:
        for match in self.re.finditer(text):
            value = match.group(self.group)
            if not value or (self.check and not _plausible(value)):
                continue
            yield Span(
                match.start(self.group), match.end(self.group),
                PiiType.SECRET, value, f"secret.{self.name}",
            )


SECRET_DETECTORS = [SecretDetector(name, pattern, group) for name, pattern, group in _PATTERNS]
