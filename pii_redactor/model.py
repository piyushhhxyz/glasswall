"""Span model and overlap resolution shared by every detector."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PiiType(str, Enum):
    PERSON = "PERSON"
    ORG = "ORG"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    URL = "URL"
    IP = "IP"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    DOB = "DOB"
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    DIN = "DIN"
    CIN = "CIN"
    SEBI_REGN = "SEBI_REGN"
    REG_NUMBER = "REG_NUMBER"
    GSTIN = "GSTIN"
    IFSC = "IFSC"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    PASSPORT = "PASSPORT"
    ID_DOCUMENT = "ID_DOCUMENT"


# Higher wins when two detections overlap by the same length.
PRIORITY: dict[PiiType, int] = {
    PiiType.EMAIL: 100,
    PiiType.URL: 95,
    PiiType.IP: 94,
    PiiType.CIN: 93,
    PiiType.SEBI_REGN: 92,
    PiiType.REG_NUMBER: 66,
    PiiType.GSTIN: 91,
    PiiType.IFSC: 90,
    PiiType.PAN: 89,
    PiiType.AADHAAR: 88,
    PiiType.SSN: 87,
    PiiType.CREDIT_CARD: 86,
    PiiType.PASSPORT: 80,
    PiiType.ID_DOCUMENT: 79,
    PiiType.PHONE: 75,
    PiiType.BANK_ACCOUNT: 70,
    PiiType.DIN: 65,
    PiiType.DOB: 60,
    PiiType.ADDRESS: 50,
    PiiType.LOCATION: 20,
    PiiType.ORG: 40,
    PiiType.PERSON: 30,
}


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: PiiType
    text: str
    detector: str
    confidence: float = 1.0

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


def resolve(spans: list[Span]) -> list[Span]:
    """Greedy longest-match-wins, ties broken by detector priority.

    Overlaps are the norm, not the exception: an address contains a pincode, an
    email contains a domain, an org name contains a person's surname. Keeping the
    longest span avoids double-substitution corrupting the surrounding text.
    """
    ordered = sorted(spans, key=lambda s: (-len(s), -PRIORITY.get(s.type, 0), s.start))
    kept: list[Span] = []
    for span in ordered:
        if not any(span.overlaps(k) for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: s.start)
