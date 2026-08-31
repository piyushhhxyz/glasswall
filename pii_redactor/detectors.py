"""Pattern detectors.

Every detector is a `Detector` with a `find(text) -> Iterable[Span]`. Adding a new
PII type means writing one class and appending it to `PATTERN_DETECTORS` -- no
other module changes.

Two themes run through this file:

1. **Validators over patterns.** A 16-digit run is only a card if it passes Luhn;
   twelve digits are only an Aadhaar if they pass Verhoeff. Cheap arithmetic buys
   most of the precision that a looser regex would throw away.
2. **Dirty-input tolerance.** Real-world DOCX input contains `www.acmeindustries. com`
   (stray space) and phone numbers broken across lines. Patterns therefore allow
   optional whitespace at the separators a PDF-to-DOCX conversion tends to inject.
"""

from __future__ import annotations

import re
from typing import Iterable, Protocol

from .model import PiiType, Span

# Optional whitespace, including the newlines produced by run/line breaks.
_S = r"[\s ]*"


class Detector(Protocol):
    name: str
    type: PiiType

    def find(self, text: str) -> Iterable[Span]: ...


class RegexDetector:
    """Regex + optional validator. `group` selects the span within the match."""

    def __init__(self, name, pii_type, pattern, flags=0, validator=None, group=0):
        self.name = name
        self.type = pii_type
        self.re = re.compile(pattern, flags)
        self.validator = validator
        self.group = group

    def find(self, text: str) -> Iterable[Span]:
        for m in self.re.finditer(text):
            value = m.group(self.group)
            if not value or (self.validator and not self.validator(value)):
                continue
            yield Span(m.start(self.group), m.end(self.group), self.type, value, self.name)


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19:
        return False
    total, parity = 0, len(d) % 2
    for i, ch in enumerate(d):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff(value: str) -> bool:
    """Aadhaar's checksum. Rejects the vast majority of incidental 12-digit runs."""
    d = _digits(value)
    if len(d) != 12 or d[0] in "01":
        return False
    check = 0
    for i, ch in enumerate(reversed(d)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


def valid_pan(value: str) -> bool:
    # 4th character encodes holder type; anything else is a coincidental token.
    return value[3] in "ABCFGHLJPTKE"


def plausible_phone(value: str) -> bool:
    d = _digits(value)
    if not 10 <= len(d) <= 13:
        return False
    national = d[2:] if d.startswith("91") and len(d) > 10 else d
    return len(set(national)) > 2  # rejects 0000000000-style filler


def looks_like_identifier(value: str) -> bool:
    """Registration numbers carry digits; a run of prose after the label does not."""
    return bool(re.search(r"\d", value)) and not re.search(r"\b[a-z]{3,}\b", value)


def valid_ipv4(value: str) -> bool:
    return all(0 <= int(p) <= 255 for p in value.split("."))


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

PATTERN_DETECTORS: list[Detector] = [
    # `foo@bar. com` and `foo @bar.com` both occur after PDF conversion.
    RegexDetector(
        "email", PiiType.EMAIL,
        rf"[A-Za-z0-9._%+\-]+{_S}@{_S}[A-Za-z0-9\-]+(?:{_S}\.{_S}[A-Za-z0-9\-]+)*{_S}\.{_S}[A-Za-z]{{2,}}",
    ),
    RegexDetector(
        "url", PiiType.URL,
        rf"(?:https?://|www{_S}\.{_S})[A-Za-z0-9\-]+(?:{_S}\.{_S}[A-Za-z0-9\-]+)*{_S}\.{_S}[A-Za-z]{{2,}}(?:/[^\s,;)\"'<>]*)?",
        re.I,
    ),
    RegexDetector("ipv4", PiiType.IP, r"\b(?:\d{1,3}\.){3}\d{1,3}\b", validator=valid_ipv4),
    RegexDetector("ipv6", PiiType.IP, r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I),
    RegexDetector("cin", PiiType.CIN, r"\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b"),
    RegexDetector("sebi_regn", PiiType.SEBI_REGN, r"\bIN[A-Z]\d{9}\b"),
    RegexDetector("gstin", PiiType.GSTIN, r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b"),
    RegexDetector("ifsc", PiiType.IFSC, r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    RegexDetector("pan", PiiType.PAN, r"\b[A-Z]{5}\d{4}[A-Z]\b", validator=valid_pan),
    RegexDetector("aadhaar", PiiType.AADHAAR, r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", validator=verhoeff),
    RegexDetector("ssn", PiiType.SSN, r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    RegexDetector("credit_card", PiiType.CREDIT_CARD, r"\b(?:\d[ \-]?){12,18}\d\b", validator=luhn),
    # International prefix present: unambiguous.
    RegexDetector("phone_intl", PiiType.PHONE, rf"\+{_S}\d{{1,3}}[\s\-]?\(?\d[\d\s\-()]{{7,16}}\d", validator=plausible_phone),
    # Bare numbers only when a label vouches for them, so share counts stay put.
    RegexDetector(
        "phone_labelled", PiiType.PHONE,
        rf"(?:Tel(?:ephone)?|Phone|Mobile|Fax|Contact\s+(?:No|Number))\.?:?{_S}(\+?[\d][\d\s\-]{{8,15}}\d)",
        re.I, plausible_phone, group=1,
    ),
    RegexDetector("passport", PiiType.PASSPORT, r"(?:Passport(?:\s+No\.?)?:?\s*)([A-PR-WY]\d{7})", re.I, group=1),
    RegexDetector(
        "bank_account", PiiType.BANK_ACCOUNT,
        # \b on both sides: without it "A/?c" matches the letters "ac" inside a hex
        # trace id ("e8ac901517608901") and invents a bank account in every log line.
        r"\b(?:A/?c|Account)\b\s*(?:No\.?|Number)?:?\s*(\d{9,18})\b", re.I, group=1,
    ),
    # DIN is a statutory *personal* identifier for company directors. It is absent
    # from the brief's list but is exactly the kind of key that re-identifies a
    # person against a public registry, so it is redacted by default.
    RegexDetector(
        "registration_number", PiiType.REG_NUMBER,
        r"(?:(?:firm|company|peer\s+review|licence|license|membership|enrol(?:l)?ment)\s+"
        r"(?:registration\s+)?(?:number|no\.?)|registration\s+(?:number|no\.?))\s*:?\s*"
        r"([A-Z0-9][A-Z0-9/\- ]{3,24}[A-Z0-9])",
        re.I, looks_like_identifier, group=1,
    ),
    RegexDetector("din_labelled", PiiType.DIN, r"\bDIN[:\s]*(\d{8})\b", re.I, group=1),
    RegexDetector(
        "dob", PiiType.DOB,
        r"(?:date\s+of\s+birth|D\.?O\.?B\.?|born\s+on)\s*:?\s*"
        r"([0-3]?\d[\s/\-.][A-Za-z0-9]{1,9}[\s/\-.]\d{2,4}"
        r"|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})",
        re.I, group=1,
    ),
]


class StandaloneDinDetector:
    """DIN in a bare table cell, where the `DIN` label lives in the header row.

    The prospectus lists directors as `Name | Designation | DIN | Address`, so the
    number arrives with no adjacent cue. A cell that is *nothing but* eight digits
    is a safe signal; an eight-digit run inside prose is not.
    """

    name = "din_cell"
    type = PiiType.DIN

    def find(self, text: str) -> Iterable[Span]:
        stripped = text.strip()
        if re.fullmatch(r"\d{8}", stripped):
            start = text.index(stripped)
            yield Span(start, start + 8, PiiType.DIN, stripped, self.name)


class AddressDetector:
    """Postal addresses, anchored on the pincode and grown outwards.

    Indian addresses have no reliable left edge, but they do have a near-reliable
    right edge: `<pincode>[, State][, India]`. We anchor there and walk left to the
    nearest hard boundary (sentence end, colon, or start of the cell), capped so a
    runaway match cannot swallow a paragraph.
    """

    name = "address"
    type = PiiType.ADDRESS
    MAX_LEFT = 240
    _PIN = re.compile(r"\b\d{3}\s?\d{3}\b")
    # The state/country tail must stop before the next field label, or the address
    # eats "Telephone:" and takes the cue the phone detector depends on with it.
    _LABEL = (r"Tel|Telephone|Phone|Mobile|Fax|E-?mail|Website|Contact|Investor|CIN|DIN|"
              r"Address|Registered|Corporate|SEBI|Compliance|Company|Designation|Name")
    _TAIL = re.compile(
        rf"[,\s]*(?:(?!(?:{_LABEL})\b)[A-Z][A-Za-z]+(?:\s+(?!(?:{_LABEL})\b)[A-Z][A-Za-z]+){{0,2}})?"
        rf"[,\s]*(?:India)?",
        re.M,
    )
    # A full stop only ends a sentence when a real word precedes it -- addresses are
    # full of abbreviations ("S. no.", "Gat No.", "lane no.") that must not split them.
    _BOUNDARY = re.compile(r"(?:(?<=[a-z]{3})\.\s|:\s|\bat\s|\baddress\s|\n)", re.I)
    # A pincode needs address-ish company nearby, else it is a plain number.
    _CONTEXT = re.compile(
        r"\b(?:road|marg|street|st\.|lane|nagar|society|apartment|apartments|flat|plot|floor|tower|"
        r"building|colony|village|taluka|district|sector|block|house|park|estate|area|complex|"
        r"gymkhana|bunglow|bungalow|residency|chambers|centre|center|premises|"
        r"pune|mumbai|delhi|bengaluru|bangalore|chennai|kolkata|hyderabad|bhopal|ahmedabad|"
        r"maharashtra|karnataka|gujarat|india)\b",
        re.I,
    )

    def find(self, text: str) -> Iterable[Span]:
        for pin in self._PIN.finditer(text):
            left_bound = max(0, pin.start() - self.MAX_LEFT)
            window = text[left_bound:pin.start()]
            if not self._CONTEXT.search(window):
                continue
            starts = [m.end() for m in self._BOUNDARY.finditer(window)]
            start = left_bound + (starts[-1] if starts else 0)
            tail = self._TAIL.match(text, pin.end())
            end = tail.end() if tail else pin.end()
            value = text[start:end].strip()
            if len(value) < 10:
                continue
            start = text.index(value, start)
            yield Span(start, start + len(value), PiiType.ADDRESS, value, self.name)


class AddressLineDetector:
    """Address lines with no pincode to anchor on.

    A postal address routinely spans several table cells: the street in one, the
    city and pincode in the next. `AddressDetector` needs the pincode, so lines
    like "5th Floor, Wing A, Gopal House" slip past it. Those lines do, however,
    open with a strong structural cue, which is precise enough to stand alone.
    """

    name = "address_line"
    type = PiiType.ADDRESS
    _LEAD = re.compile(
        r"^\s*(?:\d{1,4}(?:st|nd|rd|th)?\s+)?"
        r"(?:Floor|Wing|Plot|Flat|Tower|Block|Building|House|Survey|Gat|Khasra|Unit|Shop|Room|Door)"
        r"\b[^\n]{6,150}$",
        re.I,
    )
    _REJECT = re.compile(r"\b(?:shall|means|includes|pursuant|regulation|shares?|price|company)\b", re.I)

    def find(self, text: str) -> Iterable[Span]:
        stripped = text.strip()
        if self._LEAD.match(stripped) and not self._REJECT.search(stripped) and "," in stripped:
            start = text.index(stripped)
            yield Span(start, start + len(stripped), PiiType.ADDRESS, stripped, self.name)


PATTERN_DETECTORS += [StandaloneDinDetector(), AddressDetector(), AddressLineDetector()]


# --------------------------------------------------------------------------- #
# Second-pass detectors, built from what the first pass discovered
# --------------------------------------------------------------------------- #

# Words that appear inside addresses but identify nothing on their own.
_GENERIC_PLACE_WORDS = {
    "road", "lane", "street", "marg", "society", "societies", "apartment", "apartments",
    "flat", "plot", "floor", "tower", "building", "colony", "village", "taluka", "district",
    "sector", "block", "house", "park", "estate", "area", "complex", "premises", "unit",
    "opposite", "near", "behind", "next", "off", "and", "the", "of", "no", "nos", "gat",
    "india", "maharashtra", "karnataka", "gujarat", "madhya", "pradesh", "phase", "wing",
    "pune", "mumbai", "delhi", "bengaluru", "bangalore", "chennai", "kolkata", "hyderabad",
    "bhopal", "ahmedabad", "co", "operative", "housing", "industrial", "chambers", "centre",
}


def place_tokens(addresses: list[str], lowercase_vocab: set[str] | None = None) -> set[str]:
    """Distinctive locality words seen inside detected addresses.

    Addresses fragment across paragraphs -- a table cell holds the street, the next
    holds the city, a third holds the pincode -- so the pincode-anchored detector
    cannot see them whole. Harvesting the identifying words lets a second pass
    catch the pieces wherever they surface.
    """
    vocab = lowercase_vocab or set()
    tokens: set[str] = set()
    for address in addresses:
        # Only mine spans that really look like an address; an over-captured span
        # would otherwise seed common words into a document-wide literal match.
        if len(address) > 220 or not re.search(r"\b\d{3}\s?\d{3}\b", address):
            continue
        for token in re.findall(r"\b[A-Z][A-Za-z]{3,}\b", address):
            low = token.lower()
            # A word that also occurs lowercase in the document is a common noun
            # ("securities", "court"), not a place name ("Ambernath").
            if low not in _GENERIC_PLACE_WORDS and low not in vocab:
                tokens.add(token)
    return tokens


class LiteralDetector:
    """Matches a fixed vocabulary discovered by an earlier pass."""

    def __init__(self, name: str, pii_type: PiiType, vocabulary, word_boundary: bool = True):
        self.name = name
        self.type = pii_type
        terms = sorted({v for v in vocabulary if v and v.strip()}, key=len, reverse=True)
        boundary = r"\b" if word_boundary else ""
        self.re = re.compile(f"{boundary}(?:{'|'.join(map(re.escape, terms))}){boundary}", re.I) if terms else None

    def find(self, text: str) -> Iterable[Span]:
        if not self.re:
            return
        for m in self.re.finditer(text):
            yield Span(m.start(), m.end(), self.type, m.group(0), self.name)
