"""Recall improvements: credentials, labelled fields, and partial survivors."""

from __future__ import annotations

import json

import pytest

from pii_redactor.model import PiiType
from pii_verifier import partial
from pii_verifier.fields import FieldDetector
from pii_verifier.scan import scan, scan_only, verify
from pii_verifier.secrets import SECRET_DETECTORS

# Assembled at runtime rather than written out: a literal webhook URL trips
# GitHub's push protection even when the token is obviously fake.
WEBHOOK = "https://hooks.slack.com/services/" + "T00000000/" + "B00000000/" + "a" * 24


def types_of(rows):
    return {row["type"] for row in rows}


def texts_of(rows):
    return {row["text"] for row in rows}


def detect(text):
    return {(span.type, span.text) for d in SECRET_DETECTORS for span in d.find(text)}


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "text, expected",
    [
        (f'"purpose": "<{WEBHOOK}>"', WEBHOOK),
        ("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
        ("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("xoxb-1234567890-abcdefghijkl", "xoxb-1234567890-abcdefghijkl"),
        ("AIza" + "SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q", "AIza" + "SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q"),
        ("Authorization: Bearer aB3dE6fH9jK2mN5pQ8rS1tU4v", "aB3dE6fH9jK2mN5pQ8rS1tU4v"),
        ('api_key = "s3cr3tV4lu3W1thM1x"', "s3cr3tV4lu3W1thM1x"),
        ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"),
        ("https://svc:h0rr1blePassw0rd@internal.example.com", "h0rr1blePassw0rd"),
    ],
)
def test_credentials_are_detected(text, expected):
    assert (PiiType.SECRET, expected) in detect(text)


def test_a_leaked_webhook_is_critical_not_a_low_severity_url():
    """The reference export had a live webhook reported only as a URL."""
    line = f'"purpose": {{"value": "<{WEBHOOK}>"}}'
    report = verify(line, line)
    secret = next(row for row in report.leaks if row["type"] == "SECRET")
    assert secret["severity"] == "critical"
    assert report.stats["highest_severity"] == "critical"


@pytest.mark.parametrize(
    "text",
    [
        'api_key = "xxxxxxxxxxxx"',
        'api_key = "<your-api-key>"',
        'api_key = "${API_KEY}"',
        'password = "changeme123"',
        'secret = "aaaaaaaaaaaaaa"',
        'api_key = "short"',
    ],
)
def test_placeholders_are_not_reported_as_credentials(text):
    assert not detect(text)


def test_an_unlabelled_blob_is_not_a_credential():
    """Without a label, a base64-ish run is just data."""
    assert not detect("checksum aB3dE6fH9jK2mN5pQ8rS1tU4v")


# --------------------------------------------------------------------------- #
# Labelled fields -- how a person's name is found at all
# --------------------------------------------------------------------------- #

def test_a_name_is_found_by_its_field_not_its_shape():
    """Nothing in `Rajesh Kumar Nair` matches a pattern; the key is the signal."""
    found = {(s.type, s.text) for s in FieldDetector().find('"real_name": "Rajesh Kumar Nair"')}
    assert (PiiType.PERSON, "Rajesh Kumar Nair") in found


@pytest.mark.parametrize(
    "field, pii_type",
    [
        ("real_name", PiiType.PERSON), ("display_name", PiiType.PERSON),
        ("email", PiiType.EMAIL), ("phone", PiiType.PHONE),
        ("address", PiiType.ADDRESS), ("company", PiiType.ORG),
        ("date_of_birth", PiiType.DOB),
    ],
)
def test_field_names_map_to_types(field, pii_type):
    found = {s.type for s in FieldDetector().find(f'"{field}": "Some Plausible Value"')}
    assert pii_type in found


def test_a_bare_name_field_is_not_treated_as_a_person():
    """`name` is a channel or a file as often as a person, so it is excluded."""
    assert not list(FieldDetector().find('"name": "general-discussion"'))


@pytest.mark.parametrize("value", ["", "-", "N/A", "null", "unknown", "Slackbot", "0000"])
def test_empty_field_values_are_skipped(value):
    assert not list(FieldDetector().find(f'"real_name": "{value}"'))


def test_field_span_covers_the_value_not_the_key():
    text = '{"real_name": "Anita Deshpande"}'
    span = next(iter(FieldDetector().find(text)))
    assert text[span.start:span.end] == "Anita Deshpande"


def test_a_surviving_name_is_a_leak():
    before = json.dumps({"real_name": "Rajesh Kumar Nair", "note": "ok"})
    after = json.dumps({"real_name": "Rajesh Kumar Nair", "note": "ok"})
    assert types_of(verify(before, after).leaks) == {"PERSON"}


def test_a_replaced_name_is_redacted():
    before = json.dumps({"real_name": "Rajesh Kumar Nair"})
    after = json.dumps({"real_name": "Farley Wexcombe Brill"})
    report = verify(before, after)
    assert report.verdict == "clean"
    assert texts_of(report.redacted) == {"Rajesh Kumar Nair"}


# --------------------------------------------------------------------------- #
# Partial survivors
# --------------------------------------------------------------------------- #

def test_an_email_local_part_that_survives_is_a_partial_leak():
    """The string changed, so exact matching calls this redacted. It is not."""
    report = verify("mail rajesh.nair@acme.in", "mail rajesh.nair@surrogate.net")
    assert report.verdict == "partial"
    row = report.partials[0]
    assert [f["fragment"] for f in row["fragments"]] == ["rajesh.nair"]
    assert row["in_redacted"][0]["line"] == 1


def test_a_surviving_private_domain_is_a_partial_leak():
    report = verify("mail a.person@acmecorp.in", "mail surrogate@acmecorp.in")
    assert report.verdict == "partial"
    assert "acmecorp.in" in [f["fragment"] for f in report.partials[0]["fragments"]]


def test_a_role_mailbox_local_part_is_not_a_partial_leak():
    """`support@` identifies a function, not a person."""
    assert verify("mail support@acme.in", "mail support@surrogate.net").verdict == "clean"


def test_a_public_host_is_not_a_partial_leak():
    assert verify("mail someone@gmail.com", "mail surrogate@gmail.com").verdict == "clean"


def test_a_surviving_surname_is_a_partial_leak():
    before = json.dumps({"real_name": "Rajesh Kumar Nair"})
    after = json.dumps({"real_name": "Farley Nair"})
    report = verify(before, after)
    assert report.verdict == "partial"
    assert "Nair" in [f["fragment"] for f in report.partials[0]["fragments"]]


def test_a_generic_token_is_not_a_partial_leak():
    before = json.dumps({"company": "Redwood Technologies Limited"})
    after = json.dumps({"company": "Bluestone Technologies Limited"})
    # `Technologies` and `Limited` are shared boilerplate, not identity.
    assert verify(before, after).verdict == "clean"


def test_a_surviving_digit_run_is_a_partial_leak():
    """Only the tail of the number survived, which is still enough to look up."""
    before = "Aadhaar 2234 5678 9002"          # passes Verhoeff, so it is detected
    after = "audit reference ends 56789002 ok"  # the last eight digits remain
    report = verify(before, after)
    assert report.partials
    assert any("digit run" in f["kind"] for f in report.partials[0]["fragments"])


def test_partial_severity_is_one_notch_below_a_full_leak():
    full = verify("mail rajesh.nair@acme.in", "mail rajesh.nair@acme.in").leaks[0]
    part = verify("mail rajesh.nair@acme.in", "mail rajesh.nair@other.net").partials[0]
    assert full["severity"] == "high" and part["severity"] == "medium"


def test_partials_are_separate_from_leaks_and_from_redacted():
    report = verify("mail rajesh.nair@acme.in", "mail rajesh.nair@other.net")
    assert report.leaks == [] and report.redacted == []
    assert len(report.partials) == 1
    assert report.stats["partial"] == 1


def test_survivors_needs_no_report_to_run():
    found = partial.survivors(PiiType.EMAIL, "a.person@acmecorp.in", "mail x@acmecorp.in", "")
    assert [f["kind"] for f in found] == ["email domain"]


# --------------------------------------------------------------------------- #
# Single-sided scans carry locations too
# --------------------------------------------------------------------------- #

def test_scan_only_reports_where_each_finding_is():
    result = scan_only('line one\n{"email": "a.person@acme.in"}')
    site = result["findings"][0]["sites"][0]
    assert site["line"] == 2 and site["path"] == "email"


def test_secret_and_field_detectors_are_on_by_default():
    detectors = {d.name for d in [type("x", (), {"name": "x"})()]}  # placeholder
    found = {f.detector for f in scan(f'{{"real_name": "Anita Deshpande", "hook": "{WEBHOOK}"}}')}
    assert "field.real_name" in found
    assert "secret.slack_webhook" in found
    assert detectors  # keeps the linter quiet about the unused local
