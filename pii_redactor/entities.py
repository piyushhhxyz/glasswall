"""Person and organisation detection.

Generic NER on a 330k-character legal document is a precision disaster: it tags
"Equity Shares", "Red Herring Prospectus" and "Bid cum Application Form" as
entities while missing names that only ever appear inside a table cell. So we
work in two passes instead.

**Seed** -- mine the document's own structure for entities it *declares*:
`Contact Person: X`, the `OUR PROMOTERS:` masthead, the `Name | Designation | DIN
| Address` board table, `X is our Company Secretary`. These cues are near-perfect
precision and generic to prospectus-style filings.

**Expand** -- decompose every seeded person into name *tokens*. Matching then
happens token-wise, so `RAVI MOHAN SHARMA`, `Ravi Sharma` and a bare
`Sharma` are all caught without enumerating variants, and the shared-surname
structure of the promoter family survives into the redacted output.

An optional spaCy pass (`--ner`) adds recall for names the structural cues miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .model import PiiType, Span

DESIGNATIONS = (
    r"Chairman|Managing Director|Joint Managing Director|Whole-?time Director|Independent Director|"
    r"Executive Director|Non-?Executive Director|Nominee Director|Company Secretary|Compliance Officer|"
    r"Chief Financial Officer|Chief Executive Officer|Promoter|Contact Person|Partner|Proprietor"
)
HONORIFICS = r"Mr|Mrs|Ms|Dr|Shri|Smt|Sri|Prof"

_NAME = r"[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3}"
_NAME_CI = r"[A-Za-z'\-]{2,}"

# Tokens that look like names but never are, in this register of English.
_TOKEN_STOP = {
    "the", "and", "of", "for", "our", "this", "limited", "ltd", "llp", "private", "public",
    "company", "companies", "act", "board", "director", "directors", "offer", "issue", "share",
    "shares", "equity", "india", "indian", "bank", "trust", "fund", "capital", "securities",
    "prospectus", "red", "herring", "draft", "sebi", "bse", "nse", "rbi", "roc", "stock",
    "exchange", "registrar", "auditor", "auditors", "chartered", "accountants", "person",
    "contact", "name", "designation", "address", "telephone", "email", "website", "investor",
    "grievance", "manager", "managers", "lead", "book", "running", "date", "pune", "mumbai",
    "maharashtra", "chairman", "managing", "executive", "independent", "whole", "time", "joint",
    "secretary", "compliance", "officer", "chief", "financial", "promoter", "promoters",
    # Legal-register noise that survives capitalisation but is never a person.
    "selling", "shareholder", "shareholders", "agreement", "registration", "regn", "number",
    "group", "park", "persons", "person", "branch", "trusts", "maximum", "minimum", "family",
    "corporate", "office", "registered", "statement", "summary", "section", "annexure",
}

# Roman numerals read as name tokens ("Park VI") but carry no identity.
_ROMAN = re.compile(r"^(?=[MDCLXVI]+$)M*(?:CM|CD|D?C{0,3})(?:XC|XL|L?X{0,3})(?:IX|IV|V?I{0,3})$")

# Words that prefix an organisation without being part of its name.
_ORG_LEAD_STOP = {
    "and", "the", "of", "our", "to", "by", "with", "for", "a", "an", "contact", "person",
    "email", "telephone", "name", "company", "date", "branch", "regulations", "deposit",
    "group", "sr", "no", "type", "total", "details", "list",
}

# Organisations that are institutions, infrastructure or statute -- redacting them
# would destroy the document's meaning without protecting a single individual.
INSTITUTION_STOPLIST = {
    "securities and exchange board of india", "sebi", "bse limited", "bombay stock exchange",
    "national stock exchange of india limited", "nse", "reserve bank of india", "rbi",
    "registrar of companies", "ministry of corporate affairs", "government of india",
    "income tax department", "national securities depository limited",
    "central depository services (india) limited", "nsdl", "cdsl",
    "institute of chartered accountants of india", "supreme court of india",
    "insurance regulatory and development authority of india", "competition commission of india",
    "stock exchanges", "depositories", "companies act", "the companies act",
    "national payments corporation", "national payments corporation of india", "npci",
}

# Suffix words alone do not make an organisation ("Private Limited" is not a name).
_GENERIC_ORG_TOKENS = {
    "private", "public", "limited", "ltd", "llp", "inc", "corporation", "corp", "co",
    "india", "trust", "family", "the", "of", "and", "company", "bank", "holdings",
}

# Exchange, depository and government domains identify a public institution.
INSTITUTION_DOMAINS = {
    "bseindia.com", "nseindia.com", "sebi.gov.in", "rbi.org.in", "mca.gov.in",
    "nsdl.co.in", "cdslindia.com", "npci.org.in", "indiapost.gov.in", "incometax.gov.in",
    "nseindia.co.in", "bseindia.co.in", "watchoutinvestors.com", "investor.sebi.gov.in",
}

_ORG_SUFFIX = (
    r"Limited|Ltd\.?|LLP|Private Limited|Pvt\.?\s?Ltd\.?|Incorporated|Inc\.?|Corporation|Corp\.?|"
    r"GmbH|S\.A\.|B\.V\.|N\.V\.|Co\.|Holdings|Ventures|Enterprises|Industries|Family Trust|Trust|"
    r"LLC|L\.L\.C\.|AB|A/S|Pte\.?\s?Ltd\.?|Associates|Partners|Sons"
)
_ORG_TOKEN = r"[A-Za-z][A-Za-z0-9&.'()\-]*"
_ORG_RE = re.compile(rf"\b([A-Z][A-Za-z0-9&.'()\-]*(?:\s+(?:{_ORG_TOKEN}|&)){{0,6}}\s+(?:{_ORG_SUFFIX}))\b")
_ORG_RE_CAPS = re.compile(
    rf"\b([A-Z][A-Z0-9&.'()\-]*(?:\s+[A-Z][A-Z0-9&.'()\-]*){{0,6}}\s+"
    rf"(?:LIMITED|LTD\.?|LLP|PRIVATE LIMITED|FAMILY TRUST|TRUST))\b"
)


_ORG_SUFFIX_TAIL = re.compile(
    r"\s+(?:Private\s+Limited|Family\s+Trust|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?|Trust|Co\.?)$",
    re.I,
)


def strip_org_suffix(name: str) -> str:
    """Drop the legal suffix, leaving the brand: "Acme Industries Limited" -> "Acme Industries"."""
    return _ORG_SUFFIX_TAIL.sub("", name).strip()


@dataclass
class Gazetteer:
    persons: set[str] = field(default_factory=set)
    orgs: set[str] = field(default_factory=set)
    given_tokens: set[str] = field(default_factory=set)
    surname_tokens: set[str] = field(default_factory=set)
    lowercase_vocab: set[str] = field(default_factory=set)

    @property
    def name_tokens(self) -> set[str]:
        return self.given_tokens | self.surname_tokens

    def add_person(self, raw: str) -> None:
        tokens = _name_tokens(raw)
        if len(tokens) < 2:
            return
        self.persons.add(" ".join(tokens))
        self.surname_tokens.add(tokens[-1].lower())
        self.given_tokens.update(t.lower() for t in tokens[:-1])

    def add_org(self, raw: str) -> None:
        tokens = re.sub(r"\s+", " ", raw).strip(" ,.").split()
        while tokens and (tokens[0].lower().strip(".") in _ORG_LEAD_STOP or tokens[0][0].isdigit()):
            tokens.pop(0)
        name = " ".join(tokens)
        if len(name) > 3 and name.lower() not in INSTITUTION_STOPLIST:
            self.orgs.add(name)


def _name_tokens(raw: str) -> list[str]:
    raw = re.sub(rf"\b(?:{HONORIFICS})\.?\s+", "", raw.strip(), flags=re.I)
    tokens = [t for t in re.split(r"[\s.]+", raw) if t]
    return [
        t for t in tokens
        if len(t) > 2 and t.isalpha() and t.lower() not in _TOKEN_STOP and not _ROMAN.match(t.upper())
    ]


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #

_SEED_PATTERNS = [
    rf"Contact\s+Person\s*:?\s*({_NAME}(?:\s*[/,&]\s*(?:and\s+)?{_NAME})*)",
    rf"({_NAME})\s+is\s+our\b",
    rf"({_NAME})\s*,?\s*(?:the\s+)?(?:{DESIGNATIONS})\b",
    rf"\b(?:{DESIGNATIONS})\s*[:,]?\s*({_NAME})",
    rf"\b(?:{HONORIFICS})\.?\s+({_NAME_CI}(?:\s+{_NAME_CI}){{0,3}})",
]


def build_gazetteer(paragraphs: list[str]) -> Gazetteer:
    gaz = Gazetteer()
    joined = "\n".join(paragraphs)

    for pattern in _SEED_PATTERNS:
        for m in re.finditer(pattern, joined):
            for part in re.split(r"\s*[/,&]\s*|\s+and\s+", m.group(1)):
                gaz.add_person(part)

    # Masthead roster: "OUR PROMOTERS: A, B, C AND D PRIVATE LIMITED"
    for m in re.finditer(r"OUR PROMOTERS?\s*:?\s*(.+?)(?:\n\n|DETAILS OF)", joined, re.S):
        for item in re.split(r",|\bAND\b", m.group(1)):
            item = item.strip()
            if not item:
                continue
            (gaz.add_org if re.search(r"TRUST|LIMITED|LLP|HUF", item, re.I) else gaz.add_person)(item)

    # Holder tables give a name no structural cue at all -- it is simply the cell
    # before a share count and a percentage. That shape is the cue.
    _NUMBER = re.compile(r"^\s*[\d,]+\s*$")
    _PERCENT = re.compile(r"^\s*[\d.,]+\s*\**\s*%\s*$")
    _CELL_NAME = re.compile(r"^\s*[A-Z][a-z]+(?:\s+(?:[A-Z]\.|[A-Z][a-z]+)){1,3}\s*$")
    for i in range(len(paragraphs) - 2):
        if (_CELL_NAME.match(paragraphs[i]) and _NUMBER.match(paragraphs[i + 1])
                and _PERCENT.match(paragraphs[i + 2])
                and not re.search(_ORG_SUFFIX, paragraphs[i])):
            gaz.add_person(paragraphs[i])

    # Board table rows arrive as consecutive cells: name, designation, DIN, address.
    for i, text in enumerate(paragraphs):
        if re.fullmatch(r"\s*\d{8}\s*", text) and i >= 2:
            gaz.add_person(paragraphs[i - 2])

    # Emails and URLs contain lowercased *proper nouns* ("bluecrest.com"), which would
    # otherwise mask those brands from the common-noun test below.
    prose = re.sub(r"\S+@\S+|(?:https?://|www\.)\S+", " ", joined)
    lowercase_vocab = {w for w in re.findall(r"\b[a-z]{3,}\b", prose)}
    for regex in (_ORG_RE, _ORG_RE_CAPS):
        for m in regex.finditer(joined):
            gaz.add_org(m.group(1))
    _prune_orgs(gaz, lowercase_vocab)

    # A token is a surname if it ever ends a full name; drop the ambiguous overlap
    # from the given-name set so each token maps through exactly one pool.
    _drop_org_fragments(gaz)
    gaz.lowercase_vocab = lowercase_vocab
    gaz.orgs |= _org_aliases(gaz.orgs, lowercase_vocab)
    gaz.given_tokens -= gaz.surname_tokens
    return gaz


def _org_aliases(orgs: set[str], lowercase_vocab: set[str]) -> set[str]:
    """Short forms: "Bluecrest Capital Limited" is usually just "Bluecrest".

    Two aliases per organisation -- the name without its legal suffix, and the
    leading token when that token is distinctive (an acronym, or a word that never
    appears lowercase in the document, so it cannot be a common noun).
    """
    aliases: set[str] = set()
    for org in orgs:
        trimmed = _ORG_SUFFIX_TAIL.sub("", org).strip()
        if len(trimmed.split()) >= 2:
            aliases.add(trimmed)
        for head in trimmed.split():  # first distinctive word wins
            low = head.lower().strip(".,")
            if not head.isalpha() or low in _GENERIC_ORG_TOKENS:
                continue
            if len(low) < 3 or (len(low) == 3 and not head.isupper()):
                continue
            if head.isupper() or low not in lowercase_vocab:
                aliases.add(head)
                break
    return {a for a in aliases if a.lower() not in INSTITUTION_STOPLIST}


def _is_substantive_org(name: str) -> bool:
    """Reject candidates made only of generic corporate furniture."""
    tokens = [t.lower().strip(".,()[]") for t in name.split()]
    return any(t and t not in _GENERIC_ORG_TOKENS for t in tokens)


def _prune_orgs(gaz: Gazetteer, lowercase_vocab: set[str]) -> None:
    """Trim leading context that the greedy match absorbed.

    A candidate is over-captured when it token-ends with another, shorter valid
    candidate. We only trust that signal when the extra prefix looks like prose --
    it contains a digit-bearing token, or a word that also occurs *lowercase*
    somewhere in the document, which makes it a common noun rather than part of a
    proper name. That keeps "Kirtane & Pandit LLP" intact while reducing
    "Book Running Lead Managers Bluecrest Capital Limited" to the name.
    """
    gaz.orgs = {o for o in gaz.orgs if _is_substantive_org(o) and o.lower() not in INSTITUTION_STOPLIST}
    by_tokens = {tuple(o.lower().split()) for o in gaz.orgs}
    for original in sorted(gaz.orgs):
        tokens = tuple(original.lower().split())
        for cut in range(1, len(tokens)):
            tail = tokens[cut:]
            # An institution at either end means the rest is surrounding prose,
            # and redacting the match would delete a regulator's name.
            if " ".join(tail) in INSTITUTION_STOPLIST or " ".join(tokens[:cut]) in INSTITUTION_STOPLIST:
                gaz.orgs.discard(original)
                break
            if tail not in by_tokens:
                continue
            prefix = original.split()[:cut]
            if any(any(c.isdigit() for c in t) or t.lower().strip(".,") in lowercase_vocab for t in prefix):
                gaz.orgs.discard(original)
                break


def _drop_org_fragments(gaz: Gazetteer) -> None:
    """Remove "persons" that are really the opening words of an organisation."""
    org_prefixes = {o.lower() for o in gaz.orgs}
    for person in list(gaz.persons):
        low = person.lower()
        if any(o.startswith(low) and o != low for o in org_prefixes):
            gaz.persons.discard(person)
            tokens = low.split()
            gaz.surname_tokens.discard(tokens[-1])
            gaz.given_tokens.difference_update(tokens)


def seed_with_spacy(gaz: Gazetteer, paragraphs: list[str], model: str = "en_core_web_sm") -> Gazetteer:
    """Optional recall booster. Silently skipped when spaCy is not installed."""
    try:
        import spacy
    except ImportError:
        return gaz
    nlp = spacy.load(model, disable=["parser", "lemmatizer"])
    for doc in nlp.pipe(paragraphs, batch_size=256):
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                gaz.add_person(ent.text)
            elif ent.label_ == "ORG":
                gaz.add_org(ent.text)
    gaz.given_tokens -= gaz.surname_tokens
    return gaz


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

class GazetteerDetector:
    """Matches persons token-wise and organisations by longest literal."""

    name = "gazetteer"

    def __init__(self, gaz: Gazetteer):
        self.gaz = gaz
        tokens = sorted(gaz.name_tokens, key=len, reverse=True)
        alt = "|".join(map(re.escape, tokens))
        self._person_re = re.compile(
            rf"\b(?:(?:{HONORIFICS})\.?\s+)?(?:{alt})(?:\s+(?:{alt}))*\b", re.I
        ) if tokens else None
        orgs = sorted(gaz.orgs, key=len, reverse=True)
        self._org_re = re.compile(rf"\b(?:{'|'.join(map(re.escape, orgs))})\b", re.I) if orgs else None

    def find(self, text: str) -> Iterable[Span]:
        if self._org_re:
            for m in self._org_re.finditer(text):
                if m.group(0).lower().strip() not in INSTITUTION_STOPLIST:
                    yield Span(m.start(), m.end(), PiiType.ORG, m.group(0), "gazetteer.org")
        if self._person_re:
            for m in self._person_re.finditer(text):
                yield Span(m.start(), m.end(), PiiType.PERSON, m.group(0), "gazetteer.person")
