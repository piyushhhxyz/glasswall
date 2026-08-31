import pytest

from pii_redactor.detectors import (AddressDetector, PATTERN_DETECTORS, StandaloneDinDetector,
                                    luhn, place_tokens, valid_pan, verhoeff)
from pii_redactor.model import PiiType, Span, resolve


def find(text, pii_type=None):
    spans = [s for d in PATTERN_DETECTORS for s in d.find(text)]
    spans = resolve(spans)
    return [s for s in spans if pii_type is None or s.type is pii_type]


@pytest.mark.parametrize("text,expected", [
    ("Email: info@acmeindustries.com", "info@acmeindustries.com"),
    # Whitespace injected by PDF-to-DOCX conversion must not defeat the match.
    ("write to john.doe@ example .com now", "john.doe@ example .com"),
])
def test_email_tolerates_dirty_whitespace(text, expected):
    assert [s.text for s in find(text, PiiType.EMAIL)] == [expected]


def test_url_with_injected_space():
    assert find("Website: www.acmeindustries. com", PiiType.URL)[0].text == "www.acmeindustries. com"


@pytest.mark.parametrize("text", ["+ 91 20 45053237", "+91 22 4009 4400", "+91 81081 14949"])
def test_phone_variants(text):
    assert find(f"Telephone: {text}", PiiType.PHONE)


def test_share_counts_are_not_phone_numbers():
    assert not find("Up to 26,704,570 Equity Shares of face value of Rs 5", PiiType.PHONE)


def test_labelled_phone_without_country_code():
    assert find("Telephone: 8879770456", PiiType.PHONE)[0].text == "8879770456"


def test_luhn_gate_on_credit_cards():
    assert find("Card 4539148803436467", PiiType.CREDIT_CARD)      # valid
    assert not find("Card 4539148803436460", PiiType.CREDIT_CARD)  # checksum fails


def test_verhoeff_gate_on_aadhaar():
    assert verhoeff("234567890123") is False
    assert luhn("4539148803436467") is True


def test_pan_holder_type_character():
    assert valid_pan("ABCPD1234E")
    assert not valid_pan("ABCXD1234E")


def test_ssn_rejects_reserved_ranges():
    assert find("SSN 123-45-6789", PiiType.SSN)
    assert not find("SSN 000-45-6789", PiiType.SSN)


def test_standalone_din_cell_but_not_prose():
    assert list(StandaloneDinDetector().find("  00135070  "))
    assert not list(StandaloneDinDetector().find("circular 20220803 dated August 3"))


def test_labelled_din():
    assert find("DIN: 00135070", PiiType.DIN)[0].text == "00135070"


def test_address_anchors_on_pincode_and_keeps_abbreviations():
    text = ("S. no. 245/ 104, Pushpakamal, Deccan Gymkhana Society, lane no. 3 Prabhat Road, "
            "Deccan Gymkhana, Pune – 411 004 Maharashtra, India")
    span = find(text, PiiType.ADDRESS)[0]
    assert span.text.startswith("S. no. 245"), "abbreviation must not truncate the address"
    assert span.text.endswith("India")


def test_bare_number_is_not_an_address():
    assert not find("Profit for the year was 411 004", PiiType.ADDRESS)


def test_place_tokens_reject_common_nouns():
    address = "Plot 4, Ambernath, Pune – 411 004, India"
    assert "Ambernath" in place_tokens([address], lowercase_vocab=set())
    assert "Ambernath" not in place_tokens([address], lowercase_vocab={"ambernath"})


def test_resolve_prefers_the_longest_span():
    spans = [Span(0, 10, PiiType.ADDRESS, "a" * 10, "x"), Span(3, 6, PiiType.PERSON, "aaa", "y")]
    assert resolve(spans) == [spans[0]]
