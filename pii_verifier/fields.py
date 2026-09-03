"""PII identified by the field it sits in, not by its own shape.

No pattern matches a person's name, but `"real_name": "..."` labels one.
"""

from __future__ import annotations

import re
from typing import Iterable

from pii_redactor.model import PiiType, Span

# Field name -> what its value is. Deliberately narrow: a bare `name` is a
# channel or a file just as often as a person, so it is left out.
FIELD_TYPES: dict[str, PiiType] = {
    # People
    "real_name": PiiType.PERSON, "real_name_normalized": PiiType.PERSON,
    "display_name": PiiType.PERSON, "display_name_normalized": PiiType.PERSON,
    "full_name": PiiType.PERSON, "first_name": PiiType.PERSON,
    "last_name": PiiType.PERSON, "middle_name": PiiType.PERSON,
    "user_name": PiiType.PERSON, "username": PiiType.PERSON,
    "nickname": PiiType.PERSON, "author_name": PiiType.PERSON,
    "assignee_name": PiiType.PERSON, "reporter_name": PiiType.PERSON,
    "owner_name": PiiType.PERSON, "creator_name": PiiType.PERSON,
    "contact_name": PiiType.PERSON, "sender_name": PiiType.PERSON,
    # Contact details
    "email": PiiType.EMAIL, "email_address": PiiType.EMAIL,
    "emailaddress": PiiType.EMAIL, "mail": PiiType.EMAIL,
    "reply_to": PiiType.EMAIL, "from_address": PiiType.EMAIL,
    "phone": PiiType.PHONE, "phone_number": PiiType.PHONE,
    "mobile": PiiType.PHONE, "mobile_number": PiiType.PHONE,
    "telephone": PiiType.PHONE, "contact_number": PiiType.PHONE,
    "whatsapp": PiiType.PHONE, "fax": PiiType.PHONE,
    # Places and organisations
    "address": PiiType.ADDRESS, "address1": PiiType.ADDRESS,
    "address_line1": PiiType.ADDRESS, "street_address": PiiType.ADDRESS,
    "postal_address": PiiType.ADDRESS, "residence": PiiType.ADDRESS,
    "company": PiiType.ORG, "company_name": PiiType.ORG,
    "organisation": PiiType.ORG, "organization": PiiType.ORG,
    "employer": PiiType.ORG,
    # Other identifiers
    "dob": PiiType.DOB, "date_of_birth": PiiType.DOB, "birthday": PiiType.DOB,
    "ip": PiiType.IP, "ip_address": PiiType.IP, "client_ip": PiiType.IP,
    "pan": PiiType.PAN, "aadhaar": PiiType.AADHAAR, "gstin": PiiType.GSTIN,
    "passport": PiiType.PASSPORT, "account_number": PiiType.BANK_ACCOUNT,
}

_FIELD_ALTERNATION = "|".join(sorted(map(re.escape, FIELD_TYPES), key=len, reverse=True))
# A JSON string field and its value. Escaped quotes inside the value are kept so
# the span matches the text exactly as it appears.
_PATTERN = re.compile(rf'"({_FIELD_ALTERNATION})"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)

MIN_VALUE = 3
MAX_VALUE = 200
# Values that carry no identity, so reporting them only adds noise.
_EMPTY = re.compile(
    r"^(?:|-|n/?a|null|none|nil|unknown|unnamed|anonymous|deleted|slackbot|bot|"
    r"here|channel|everyone|0+|true|false)$",
    re.I,
)


class FieldDetector:
    """One span per labelled PII field, typed by the field name."""

    name = "field"
    type = PiiType.PERSON  # nominal; each span carries its own type

    def find(self, text: str) -> Iterable[Span]:
        for match in _PATTERN.finditer(text):
            field, value = match.group(1).lower(), match.group(2)
            stripped = value.strip()
            if not MIN_VALUE <= len(stripped) <= MAX_VALUE or _EMPTY.match(stripped):
                continue
            # Report the value, not the whole `"key": "value"` pair.
            start = match.start(2) + (len(value) - len(value.lstrip()))
            yield Span(
                start, start + len(stripped), FIELD_TYPES[field], stripped,
                f"field.{field}",
            )


FIELD_DETECTORS = [FieldDetector()]
