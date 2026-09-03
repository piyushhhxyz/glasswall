"""Auditing a whole subtree instead of one file at a time."""

from __future__ import annotations

import json

import pytest

from pii_verifier import audit
from tests.test_verifier_api import FakeS3

LEAK = json.dumps({"text": "mail a.person@acmecorp.in"}).encode()
CLEAN_BEFORE = json.dumps({"text": "mail b.person@acmecorp.in"}).encode()
CLEAN_AFTER = json.dumps({"text": "mail surrogate@example.net"}).encode()

OBJECTS = {
    # Same on both sides: the value survived.
    ("original", "chat/one/leak.json"): LEAK,
    ("redacted", "chat/one/leak.json"): LEAK,
    # Properly replaced.
    ("original", "chat/one/clean.json"): CLEAN_BEFORE,
    ("redacted", "chat/one/clean.json"): CLEAN_AFTER,
    # A nested folder, to prove the walk descends.
    ("original", "chat/two/deep/leak2.json"): LEAK,
    ("redacted", "chat/two/deep/leak2.json"): LEAK,
    # Only on one side, so there is no pair to check.
    ("original", "chat/two/orphan.json"): CLEAN_BEFORE,
    # No text to compare.
    ("original", "chat/two/logo.png"): b"\x89PNG\r\n\x1a\n\x00\x00",
    ("redacted", "chat/two/logo.png"): b"\x89PNG\r\n\x1a\n\x00\x00",
}


@pytest.fixture
def browser():
    return FakeS3(OBJECTS)


def by_key(result):
    return {row["relative"]: row for row in result.files}


def test_audit_walks_the_subtree_and_finds_every_leak(browser):
    result = audit.run(browser, "chat/")
    rows = by_key(result)
    assert rows["chat/one/leak.json"]["verdict"] == "leak"
    assert rows["chat/two/deep/leak2.json"]["verdict"] == "leak"
    assert rows["chat/one/clean.json"]["verdict"] == "clean"


def test_audit_skips_unpaired_files(browser):
    """An audit compares pairs; a one-sided file has nothing to compare to."""
    assert "chat/two/orphan.json" not in by_key(audit.run(browser, "chat/"))


def test_audit_reports_files_with_no_text(browser):
    row = by_key(audit.run(browser, "chat/"))["chat/two/logo.png"]
    assert row["verdict"] == "no_text"
    assert row["bytes_identical"] is True


def test_worst_files_come_first(browser):
    verdicts = [row["verdict"] for row in audit.run(browser, "chat/").files]
    assert verdicts[0] == "leak"
    assert verdicts.index("clean") > verdicts.index("leak")


def test_audit_summarises_by_verdict(browser):
    payload = audit.run(browser, "chat/").to_json()
    assert payload["by_verdict"]["leak"] == 2
    assert payload["flagged"] == 2
    assert payload["checked"] == 4


def test_each_flagged_file_says_where_the_leak_is(browser):
    row = by_key(audit.run(browser, "chat/"))["chat/one/leak.json"]
    finding = row["top"][0]
    assert finding["type"] == "EMAIL"
    assert finding["line"] == 2
    assert finding["path"] == "text"


def test_the_file_cap_is_reported_rather_than_silent(browser):
    result = audit.run(browser, "chat/", max_files=1)
    assert result.truncated
    assert any("Stopped after" in note for note in result.notes)
    assert len(result.files) == 1


def test_the_depth_cap_is_reported_rather_than_silent(browser):
    result = audit.run(browser, "chat/", max_depth=1)
    assert result.truncated
    # `chat/two/deep/` sits below the cap, so its leak is not reached.
    assert "chat/two/deep/leak2.json" not in by_key(result)


def test_a_file_that_fails_to_read_does_not_end_the_audit():
    class Broken(FakeS3):
        def get(self, side, relative, max_bytes=None):
            if relative.endswith("clean.json"):
                raise RuntimeError("boom")
            return super().get(side, relative, max_bytes)

    result = audit.run(Broken(OBJECTS), "chat/")
    rows = by_key(result)
    assert rows["chat/one/clean.json"]["verdict"] == "error"
    assert rows["chat/one/leak.json"]["verdict"] == "leak"


def test_collect_pairs_follows_a_renamed_folder():
    objects = {
        ("original", "jira/person.one@example.com/a/page_000001.jsonl"): LEAK,
        ("original", "jira/person.one@example.com/a/page_000002.jsonl"): b"{}",
        ("original", "jira/person.one@example.com/a/page_000003.jsonl"): b"{}",
        ("redacted", "jira/surrogate.one@example.net/a/page_000001.jsonl"): LEAK,
        ("redacted", "jira/surrogate.one@example.net/a/page_000002.jsonl"): b"{}",
        ("redacted", "jira/surrogate.one@example.net/a/page_000003.jsonl"): b"{}",
    }
    pairs, _, _ = audit.collect_pairs(FakeS3(objects), "jira/")
    found = {(p.relative, p.relative_redacted) for p in pairs}
    assert (
        "jira/person.one@example.com/a/page_000001.jsonl",
        "jira/surrogate.one@example.net/a/page_000001.jsonl",
    ) in found
