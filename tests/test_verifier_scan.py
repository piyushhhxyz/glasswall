"""The leak/redacted/surrogate split, and the respacing tolerance behind it."""

from __future__ import annotations

import pytest

from pii_redactor.model import PiiType
from pii_verifier.scan import MIN_LEAK_LENGTH, scan, scan_only, squeeze, verify


def types_of(rows) -> set[str]:
    return {row["type"] for row in rows}


def texts_of(rows) -> set[str]:
    return {row["text"] for row in rows}


# --------------------------------------------------------------------------- #
# The core three-way split
# --------------------------------------------------------------------------- #

def test_replaced_value_is_redacted_not_leaked():
    report = verify("write to person.one@example.com", "write to surrogate.one@example.net")
    assert report.verdict == "clean"
    assert report.leaks == []
    assert texts_of(report.redacted) == {"person.one@example.com"}


def test_surviving_value_is_a_leak():
    report = verify("write to person.one@example.com", "write to person.one@example.com")
    assert report.verdict == "leak"
    assert texts_of(report.leaks) == {"person.one@example.com"}


def test_new_value_in_output_is_a_surrogate_not_a_leak():
    """A redacted file is full of realistic fakes; none of them is a finding."""
    report = verify("write to person.one@example.com", "write to surrogate.one@example.net")
    assert texts_of(report.surrogates) == {"surrogate.one@example.net"}
    assert report.verdict == "clean"


def test_partial_redaction_reports_both_sides():
    before = "a@example.com and b@example.com"
    after = "x@example.net and b@example.com"
    report = verify(before, after)
    assert report.verdict == "leak"
    assert texts_of(report.leaks) == {"b@example.com"}
    assert texts_of(report.redacted) == {"a@example.com"}
    assert report.stats["redaction_rate"] == 50.0


def test_no_pii_in_original_is_not_a_leak():
    report = verify("the quick brown fox", "the quick brown fox")
    assert report.verdict == "no_pii"
    assert report.stats["redaction_rate"] is None


# --------------------------------------------------------------------------- #
# Respacing: the same value can be spelled with different whitespace on each side
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "before, after",
    [
        # Detector tolerates the stray space; the rewrite normalised it away.
        ("mail foo@bar. com", "mail foo@bar.com"),
        # The reverse: a rewrap inserted a break the original did not have.
        ("mail person.one@example.com now", "mail person.one@example.\ncom now"),
        # Case is not a redaction.
        ("Mail PERSON.ONE@example.com", "mail person.one@Example.com"),
    ],
)
def test_respacing_does_not_hide_a_leak(before, after):
    assert verify(before, after).verdict == "leak"


def test_squeeze_is_symmetric():
    assert squeeze("foo@bar. com") == squeeze("foo@bar.com") == "foo@bar.com"
    assert squeeze("A B\nC") == "abc"


def test_short_values_are_not_matched_by_accident():
    """Below the length floor a substring hit is coincidence, not a leak."""
    assert all(len(squeeze(row["text"])) >= MIN_LEAK_LENGTH for row in verify(
        "ip 10.0.0.1", "ip 10.0.0.1"
    ).leaks)


# --------------------------------------------------------------------------- #
# Grouping, severity and ordering
# --------------------------------------------------------------------------- #

def test_repeated_value_is_one_leak_with_a_count():
    before = "a@example.com " * 5
    report = verify(before, before)
    assert len(report.leaks) == 1
    assert report.leaks[0]["occurrences"] == 5


def test_leaks_are_ordered_by_severity():
    before = "org Acme Ltd site www.acme.com mail a@example.com pan ABCPD1234E"
    report = verify(before, before)
    severities = [row["severity"] for row in report.leaks]
    assert severities == sorted(severities, key=lambda s: ["critical", "high", "medium", "low"].index(s))
    assert report.stats["highest_severity"] == severities[0]


def test_leak_is_located_in_the_redacted_text():
    after = "PREFIX mail person.one@example.com"
    site = verify("mail person.one@example.com", after).leaks[0]["in_redacted"][0]
    assert after[site["start"]:site["end"]] == "person.one@example.com"
    assert site["line"] == 1 and site["column"] == 13


def test_leak_is_also_located_in_the_original():
    before = "line one\nmail person.one@example.com"
    site = verify(before, before).leaks[0]["in_original"][0]
    assert site["line"] == 2
    assert before[site["start"]:site["end"]] == "person.one@example.com"


def test_leak_location_carries_a_snippet():
    after = "PREFIX mail person.one@example.com SUFFIX"
    snippet = verify("mail person.one@example.com", after).leaks[0]["in_redacted"][0]["snippet"]
    assert snippet["match"] == "person.one@example.com"
    assert "PREFIX" in snippet["before"] and "SUFFIX" in snippet["after"]


# --------------------------------------------------------------------------- #
# Detection reuse and single-sided scans
# --------------------------------------------------------------------------- #

def test_scan_reuses_the_redactor_detectors():
    found = {f.type for f in scan("mail a@b.com pan ABCPD1234E ip 10.1.2.3")}
    assert {PiiType.EMAIL, PiiType.PAN, PiiType.IP} <= found


def test_scan_of_empty_text_is_empty():
    assert scan("") == []


def test_scan_only_groups_and_counts():
    result = scan_only("a@example.com a@example.com b@example.com")
    assert result["distinct"] == 2
    assert result["counts"]["EMAIL"] == 3
    assert {row["occurrences"] for row in result["findings"]} == {2, 1}


def test_policy_filter_narrows_the_scan():
    from pii_redactor.policy import Policy

    text = "mail a@b.com and pan ABCPD1234E"
    only_email = verify(text, text, Policy.from_names(["email"]))
    assert types_of(only_email.leaks) == {"EMAIL"}
