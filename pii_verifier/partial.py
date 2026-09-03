"""Fragments of an original value that survived when the whole did not.

`a.person@x.in` -> `a.person@y.net` reads as redacted; the mailbox survived.
"""

from __future__ import annotations

import re

from pii_redactor.model import PiiType

from . import noise

# Mailbox names that belong to a function rather than a person.
ROLE_MAILBOXES = {
    "info", "admin", "support", "sales", "contact", "help", "billing", "accounts",
    "noreply", "no-reply", "donotreply", "hello", "team", "office", "hr", "careers",
    "security", "abuse", "postmaster", "webmaster", "service", "enquiry", "enquiries",
}

# Public mail and link hosts: shared by millions, so they identify nobody.
PUBLIC_HOSTS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me",
    "rediffmail.com", "zoho.com", "example.com", "example.net", "example.org",
    "google.com", "docs.google.com", "drive.google.com", "meet.google.com",
    "github.com", "slack.com", "zoom.us", "microsoft.com", "amazonaws.com",
}

# Words that appear inside names and addresses but identify nothing alone.
GENERIC_TOKENS = {
    "road", "lane", "street", "marg", "society", "apartment", "apartments", "flat",
    "plot", "floor", "tower", "block", "colony", "village", "taluka", "district",
    "sector", "house", "park", "estate", "area", "complex", "premises", "unit", "wing",
    "phase", "opposite", "near", "behind", "next", "india", "maharashtra", "karnataka",
    "gujarat", "pune", "mumbai", "delhi", "bengaluru", "bangalore", "chennai", "kolkata",
    "hyderabad", "limited", "private", "pvt", "ltd", "llp", "inc", "corp", "company",
    "technologies", "solutions", "services", "systems", "group", "holdings", "ventures",
    "the", "and", "for", "with", "from", "team", "office", "mobility", "industries",
}

MIN_TOKEN = 4
# A digit run this long is enough to look up a person in the system it came from.
MIN_DIGIT_RUN = 8
# An Indian pincode. Shorter than a digit run, but a postal code plus anything
# else narrows a person down, so an address is checked at this length.
PINCODE = re.compile(r"\b(\d{6})\b")

# Types whose value is a digit string, where a surviving run is the risk.
_DIGIT_TYPES = {
    PiiType.AADHAAR, PiiType.CREDIT_CARD, PiiType.PHONE, PiiType.BANK_ACCOUNT,
    PiiType.SSN, PiiType.DIN, PiiType.REG_NUMBER, PiiType.ID_DOCUMENT,
}
# Only names carry identity in their individual words. URLs and secrets do not:
# splitting a webhook yields `https`, `hooks`, `slack`, none of which is the
# secret. Addresses over-capture in JSON, so they are checked by pincode instead.
_WORD_TYPES = {PiiType.PERSON, PiiType.ORG}

# JSON escapes arrive inside string values and glue onto the next word, turning
# `\nUrban` into the token `nUrban`.
_ESCAPES = re.compile(r"\\[nrtfvb0]|\\u[0-9a-fA-F]{4}|[\\/]")


def _distinctive(token: str) -> bool:
    """A word that could name someone, rather than boilerplate or an opaque id."""
    return (
        len(token) >= MIN_TOKEN
        and token.lower() not in GENERIC_TOKENS
        and not token.isdigit()
        # `U000000BBB0` and `T00000000` are machine handles, not names.
        and not token.isupper()
        and token[0].isupper()
    )


def _public(host: str) -> bool:
    """True for a shared or asset host, or any subdomain of one.

    Suffix matching: `files.slack.com` is infrastructure just as `slack.com` is.
    """
    known_hosts = PUBLIC_HOSTS | noise.ASSET_HOSTS
    return any(host == known or host.endswith("." + known) for known in known_hosts)


def _digit_runs(value: str) -> list[str]:
    """Contiguous windows of the value's digits, longest first."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < MIN_DIGIT_RUN:
        return []
    return [digits[i:i + MIN_DIGIT_RUN] for i in range(len(digits) - MIN_DIGIT_RUN + 1)]


def survivors(pii_type: PiiType, value: str, after_squeezed: str, after_digits: str) -> list[dict]:
    """Identifying fragments of `value` still present in the redacted text.

    `after_squeezed` is whitespace-free and lowercased; `after_digits` is digits.
    """
    found: list[dict] = []

    if pii_type is PiiType.EMAIL and "@" in value:
        local, _, domain = value.strip().rpartition("@")
        local, domain = local.strip().lower(), domain.strip().lower()
        if len(local) >= MIN_TOKEN and local not in ROLE_MAILBOXES and local in after_squeezed:
            found.append({"fragment": local, "kind": "email local part"})
        if domain and not _public(domain) and domain in after_squeezed:
            found.append({"fragment": domain, "kind": "email domain"})

    if pii_type is PiiType.URL:
        host = re.sub(r"^[a-z]+://", "", value.strip().lower()).split("/")[0].split("?")[0]
        host = re.sub(r"^www\.", "", host.split("@")[-1])
        if host and not _public(host) and host.replace(" ", "") in after_squeezed:
            found.append({"fragment": host, "kind": "hostname"})

    if pii_type in _WORD_TYPES:
        cleaned = _ESCAPES.sub(" ", value)
        for token in {t for t in re.findall(r"[A-Za-z][A-Za-z'\-]+", cleaned) if _distinctive(t)}:
            if token.lower() in after_squeezed:
                found.append({"fragment": token, "kind": "name token"})

    if pii_type is PiiType.ADDRESS:
        for pincode in set(PINCODE.findall(value)):
            if pincode in after_digits:
                found.append({"fragment": pincode, "kind": "pincode"})

    if pii_type in _DIGIT_TYPES:
        for run in _digit_runs(value):
            if run in after_digits:
                found.append({"fragment": run, "kind": f"{MIN_DIGIT_RUN}-digit run"})
                break  # one surviving window is the finding; the rest overlap it

    # Deduplicate while keeping the order fragments were discovered in.
    seen, unique = set(), []
    for item in found:
        if item["fragment"] not in seen:
            seen.add(item["fragment"])
            unique.append(item)
    return unique
