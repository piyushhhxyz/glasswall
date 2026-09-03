"""Suppressing detections that machine-generated JSON creates by accident."""

from __future__ import annotations

import re

from pii_redactor.model import PiiType

# Types that numeric structure can imitate; everything else is reported as found.
# DOB is absent on purpose: it fires only behind an explicit label, so it is
# precise enough to trust, and a date is the shape the rules below discard.
NOISY_TYPES = {
    PiiType.CREDIT_CARD,
    PiiType.ADDRESS,
    PiiType.PHONE,
    PiiType.BANK_ACCOUNT,
    PiiType.AADHAAR,
    PiiType.DIN,
    PiiType.REG_NUMBER,
}

# JSON/JSONL fields whose values are identifiers or clocks, never personal data.
STRUCTURAL_KEYS = {
    "ts", "thread_ts", "event_ts", "deleted_ts", "latest", "last_read", "last_set",
    "id", "client_msg_id", "channel", "channel_id", "team", "team_id", "user", "user_id",
    "bot_id", "app_id", "file_id", "parent_id", "issue_id", "account_id", "project_id",
    "created", "created_at", "updated", "updated_at", "timestamp", "time", "date_create",
    "epoch", "start", "end", "expires", "expiry", "duration", "size", "count", "version",
    "revision", "seq", "offset", "index", "hash", "etag", "checksum", "arn", "uuid", "guid",
}

# Epoch clocks at second, millisecond and microsecond resolution. The leading `1`
# pins these to 2001-2033, so ordinary quantities are not swept up.
_EPOCH = re.compile(r"^1\d{9}(?:\.\d{1,9})?$|^1\d{12}$|^1\d{15}$")

# Types whose value cannot be meaningful without letters in it. A postal address
# is words; a card number is not. Applying the "no letters" rule to the numeric
# identifier types would suppress exactly the PII they exist to find.
_NEEDS_LETTERS = {PiiType.ADDRESS}

# Calendar dates and clock times. `2025-06-20 13-06-06` is fourteen digits that
# satisfy Luhn, so without this it is reported as a critical card number.
_DATETIME = re.compile(
    r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}[-:.]\d{2}(?:[-:.]\d{2})?Z?)?$"
    r"|^\d{1,2}[-/.]\d{1,2}[-/.]\d{4}(?:[ T]\d{1,2}[-:.]\d{2}(?:[-:.]\d{2})?Z?)?$"
)

# JSON punctuation an over-captured span can drag in from around its own value.
_JSON_PUNCTUATION = '"{}[],:\\ \t\r\n'

# How far back to look for the key that owns this value.
_KEY_WINDOW = 80
_KEY_PATTERN = re.compile(r'"([A-Za-z0-9_.\-]+)"\s*:\s*"?\s*$')


def _epoch_like(value: str) -> bool:
    """True when the digits, ignoring separators, spell a plausible epoch."""
    compact = re.sub(r"[\s\-]", "", value.strip().strip('"'))
    if _EPOCH.match(compact):
        return True
    # A digit run with an epoch prefix and a machine suffix, e.g. the
    # `...-1772942080303` in a generated channel name.
    digits = re.sub(r"\D", "", compact)
    return bool(re.match(r"^1\d{12}$|^1\d{9}$", digits)) and len(digits) == len(compact)


def owning_key(text: str, start: int) -> str | None:
    """The JSON key whose value contains offset `start`, if it is right there."""
    match = _KEY_PATTERN.search(text[max(0, start - _KEY_WINDOW):start])
    return match.group(1).lower() if match else None


def classify(pii_type: PiiType, value: str, text: str = "", start: int = -1) -> str | None:
    """Why this finding is structural noise, or None if it is a real detection."""
    if pii_type not in NOISY_TYPES:
        return None

    inner = value.strip(_JSON_PUNCTUATION)

    # An address of only digits is a timestamp the pincode anchor grew out of.
    # Checked on the stripped span, because an over-captured real address also
    # carries stray JSON punctuation and must not be written off for it.
    if pii_type in _NEEDS_LETTERS and not re.search(r"[A-Za-z]", inner):
        return "no letters - a timestamp or id, not an address"

    if _epoch_like(inner):
        return "epoch timestamp"

    if _DATETIME.match(inner.strip()):
        return "calendar date or clock time"

    # Field-name rules only ever apply to values that are pure digits. A field
    # called `id` holding prose is not licence to discard whatever is in it.
    if not re.fullmatch(r"[\d.\s\-]*", inner):
        return None

    if start >= 0 and text:
        key = owning_key(text, start)
        if key in STRUCTURAL_KEYS:
            return f'value of the structural field "{key}"'
        # The pincode anchor also fires on a bare numeric array element.
        if key is None:
            preceding = text[max(0, start - 12):start]
            if re.search(r"[\[,]\s*$", preceding):
                return "bare number in a JSON array"

    return None
