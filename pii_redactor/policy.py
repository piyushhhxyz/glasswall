"""What counts as PII here, and what deliberately does not.

The brief asks for precision as well as recall, which makes these choices part of
the deliverable rather than an implementation detail. They are all overridable
from the CLI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .entities import INSTITUTION_DOMAINS
from .model import PiiType, Span

ALL_TYPES = set(PiiType)

# Redacted by default although the brief does not list them: each one re-identifies
# a named individual or entity against a public registry.
BEYOND_BRIEF = {PiiType.DIN, PiiType.CIN, PiiType.SEBI_REGN, PiiType.PAN, PiiType.AADHAAR,
                PiiType.GSTIN, PiiType.IFSC, PiiType.BANK_ACCOUNT, PiiType.PASSPORT, PiiType.URL}

# Never redacted: financial substance, statutory references and page pointers are
# the signal the document exists to carry. Removing them would produce sanitised
# noise rather than a usable training environment.
_KEEP = re.compile(
    r"^(?:₹|Rs\.?|INR|USD|\$)|"                       # monetary amounts
    r"^(?:page|section|regulation|clause|schedule)\s|"  # internal references
    r"^\d{1,3}(?:,\d{2,3})+(?:\.\d+)?$|"               # grouped figures: 26,704,570
    r"^\d+(?:\.\d+)?\s*%$",                            # percentages
    re.I,
)


def _hostname(url: str) -> str:
    """Bare host, whatever the URL is dressed in: scheme, `www.`, path, stray spaces."""
    host = re.sub(r"\s+", "", url.lower())
    host = re.sub(r"^[a-z]+://", "", host)
    host = host.split("/")[0].split("?")[0].split("@")[-1]
    return re.sub(r"^www\.", "", host)


def _is_institution(host: str) -> bool:
    """True for an institution's host or any sub-domain of it (siportal.sebi.gov.in)."""
    return any(host == d or host.endswith("." + d) for d in INSTITUTION_DOMAINS)


@dataclass
class Policy:
    enabled: set[PiiType] = field(default_factory=lambda: set(ALL_TYPES))
    # The issuer is a company name and therefore in scope. For an RL-environment
    # corpus the whole entity graph must be synthetic, so it is redacted like any
    # other -- consistently, which keeps the document internally coherent.
    redact_issuer: bool = True
    min_confidence: float = 0.0

    def accepts(self, span: Span, context: str = "") -> bool:
        if span.type not in self.enabled or span.confidence < self.min_confidence:
            return False
        if _KEEP.match(span.text.strip()):
            return False
        # A pure figure only becomes PII when a detector with a validator claims it.
        if span.type in {PiiType.PHONE, PiiType.BANK_ACCOUNT} and "," in span.text:
            return False
        # Public-institution web addresses follow the same rule as their names.
        if span.type is PiiType.URL and _is_institution(_hostname(span.text)):
            return False
        return True

    @classmethod
    def from_names(cls, names: list[str] | None, **kwargs) -> "Policy":
        if not names:
            return cls(**kwargs)
        return cls(enabled={PiiType[n.upper()] for n in names}, **kwargs)
