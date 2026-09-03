"""Structural-noise suppression."""

from __future__ import annotations

import pytest

from pii_redactor.model import PiiType
from pii_verifier import noise
from pii_verifier.scan import scan_only, verify


# --------------------------------------------------------------------------- #
# Real false positives from the Slack export
# --------------------------------------------------------------------------- #

# The `address` detector needs locality words near the pincode before it fires,
# so a bare `"ts"` line reproduces nothing. The address earlier in this record
# supplies that context; the timestamp two fields later is what gets captured.
SLACK_TS_RECORD = (
    '  {\n'
    '    "text": "Unit No 1234, 2nd floor, Sample Road, Test Layout, Bengaluru 560001",\n'
    '    "user": "U000000AAA0",\n'
    '    "type": "message",\n'
    '    "ts": "%s",\n'
    '    "client_msg_id": "00000000-0000-4000-8000-000000000000"\n'
    '  }\n'
)


@pytest.mark.parametrize(
    "stamp",
    ["1712128948.892889", "1580129539.008100", "1604559771.002200"],
)
def test_slack_timestamps_are_not_leaks(stamp):
    """Unchanged on both sides, but structure -- so `ignored`, never `leaks`."""
    record = SLACK_TS_RECORD % stamp
    report = verify(record, record)
    leaked = [row["text"] for row in report.leaks]
    assert not any(stamp.split(".")[0] in text for text in leaked), f"false leak: {leaked}"


@pytest.mark.parametrize(
    "line",
    [
        # An epoch-millisecond suffix that happens to satisfy Luhn.
        '  "name": "team-001-discussion-1772942080303",',
        '  "name": "team-002-discussion-1780148342831",',
    ],
)
def test_epoch_millisecond_ids_are_not_credit_cards(line):
    report = verify(line, line)
    assert report.leaks == [], f"false leak: {[row['text'] for row in report.leaks]}"
    assert report.ignored


def test_ignored_findings_are_reported_not_dropped():
    line = '  "name": "team-001-discussion-1772942080303",'
    report = verify(line, line)
    assert report.ignored
    assert all(row["ignored_because"] for row in report.ignored)


def test_suppression_can_be_switched_off():
    """The judgement is reversible: nothing is hidden unconditionally."""
    line = '  "name": "team-001-discussion-1772942080303",'
    off = verify(line, line, suppress_noise=False)
    assert off.leaks and off.ignored == []


# --------------------------------------------------------------------------- #
# Real PII must survive suppression
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "line",
    [
        '  "email": "person.one@example.com",',
        '  "pan": "ABCPD1234E",',
        '  "text": "call me on +91 98765 43210",',
        '  "profile": {"real_name": "reach me at person.two@example.com"},',
    ],
)
def test_real_pii_is_never_written_off_as_structure(line):
    report = verify(line, line)
    assert report.leaks, f"real PII was suppressed: {line}"


def test_structural_key_does_not_excuse_an_email():
    """`id` is a structural key, but an EMAIL is not a numeric type."""
    line = '  "id": "person.one@example.com",'
    assert verify(line, line).leaks


def test_epoch_rule_does_not_swallow_a_real_card():
    """A card number is not epoch-shaped, even though both are digit runs."""
    assert noise.classify(PiiType.CREDIT_CARD, "4111111111111111") is None


@pytest.mark.parametrize(
    "value",
    [
        "2025-06-20 13-06-06",  # from an export metadata file: 14 digits, passes Luhn
        "2025-06-20",
        "20-06-2025",
        "2026-09-03T11:41:52",
    ],
)
def test_dates_and_times_are_not_card_numbers(value):
    assert noise.classify(PiiType.CREDIT_CARD, value) == "calendar date or clock time"


@pytest.mark.parametrize("value", ["12/05/1985", "2025-06-20", "20 June 1985"])
def test_a_labelled_date_of_birth_is_never_suppressed(value):
    """DOB fires only behind an explicit label, so it is trusted as-is."""
    assert noise.classify(PiiType.DOB, value) is None


def test_a_labelled_dob_survives_verification():
    line = "Date of Birth: 12/05/1985"
    assert verify(line, line).leaks


# --------------------------------------------------------------------------- #
# The rules themselves
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value, expected",
    [
        ("1712128948", True),        # epoch seconds
        ("1712128948.892889", True),  # epoch seconds with fraction
        ("1772942080303", True),     # epoch milliseconds
        ("411001", False),           # a pincode is not epoch-shaped
        ("4111111111111111", False),  # a card number
        ("9876543210", False),       # a phone number
    ],
)
def test_epoch_detection(value, expected):
    assert noise._epoch_like(value) is expected


def test_numeric_only_address_span_is_structural():
    assert noise.classify(PiiType.ADDRESS, '"1604559771.002200')


def test_over_captured_real_address_is_still_reported():
    """A real address drags in stray JSON punctuation; that must not excuse it."""
    captured = ('"<@U000000BBB0> \\nExample Mobility Pvt Ltd\\nUnit No 1234, 2nd floor, '
                'Sample Road, Test Layout, Bengaluru, Karnataka- 560001')
    assert noise.classify(PiiType.ADDRESS, captured) is None


def test_structural_field_does_not_excuse_a_letter_bearing_value():
    text = '{"id": "Unit No 1234, Sample Road, Bengaluru 560001"}'
    assert noise.classify(PiiType.ADDRESS, text[8:-2], text, 8) is None


def test_owning_key_is_read_from_the_json_around_it():
    text = '{"thread_ts": "1712128948.892889"}'
    assert noise.owning_key(text, text.index("1712")) == "thread_ts"
    assert noise.owning_key('{"email": "a@b.com"}', 11) == "email"


def test_non_numeric_types_bypass_the_rules_entirely():
    for pii_type in (PiiType.EMAIL, PiiType.PAN, PiiType.URL, PiiType.PERSON):
        assert noise.classify(pii_type, '"1712128948.892889') is None


# --------------------------------------------------------------------------- #
# Asset URLs, which outnumbered every real finding in the export
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "url",
    [
        "https://fonts.gstatic.com/s/i/productlogos/meet_2020q4/v1/logo.png",
        "https://a.slack-edge.com/80588/img/avatars/ava_0007.png",
        "https://secure.gravatar.com/avatar/0123456789abcdef",
        "https://notion.so/images/logo-for-slack-integration.png",
    ],
)
def test_static_assets_are_not_reported_as_leaks(url):
    assert noise.classify(PiiType.URL, url)


@pytest.mark.parametrize(
    "url",
    [
        "https://meet.google.com/okb-upyi-tku",
        "https://docs.google.com/spreadsheets/d/1-cEpPMkSzEO3t0",
        "https://www.notion.so/Ble-etim-gps-dispatch-accuracy-3ddfff",
        "https://internal.example.com/hr/salaries.xlsx",
    ],
)
def test_urls_that_identify_something_are_still_reported(url):
    """A meeting code or a document id is not decoration."""
    assert noise.classify(PiiType.URL, url) is None


def test_an_asset_url_that_survives_is_ignored_not_leaked():
    line = '"footer_icon": "https://a.slack-edge.com/80588/img/icon.png"'
    report = verify(line, line)
    assert report.leaks == []
    assert report.ignored


def test_scan_only_separates_structural_findings():
    result = scan_only('{"name": "team-001-discussion-1772942080303", "email": "a@example.com"}')
    assert {row["type"] for row in result["findings"]} == {"EMAIL"}
    assert {row["type"] for row in result["ignored"]} == {"CREDIT_CARD"}
