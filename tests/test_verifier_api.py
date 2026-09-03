"""The HTTP surface, with S3 stubbed out.

These tests must not touch the network, so `S3Browser` is driven by an in-memory object store.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pii_verifier import app as app_module
from pii_verifier.config import Settings
from pii_verifier.s3 import S3Browser


class FakeS3(S3Browser):
    """`S3Browser` over an in-memory store."""

    def __init__(self, objects: dict[tuple[str, str], bytes]):
        super().__init__(Settings(
            bucket="test-bucket", original_root="orig/", redacted_root="red/", region="ap-south-1"
        ))
        self.objects = objects

    def whoami(self) -> dict:
        return {"ok": True, "account": "000000000000", "arn": "arn:aws:iam::000000000000:user/test"}

    def get(self, side: str, relative: str, max_bytes: int | None = None):
        payload = self.objects.get((side, relative))
        if payload is None:
            return b"", False, "not found"
        cap = max_bytes or self.settings.max_bytes
        return payload[:cap], len(payload) > cap, None

    def _list_flat(self, side: str, relative_prefix: str, max_keys: int):
        return [
            key[len(relative_prefix):]
            for (object_side, key) in self.objects
            if object_side == side and key.startswith(relative_prefix)
        ][:max_keys]

    def _list_side(self, side: str, relative_prefix: str, limit: int):
        dirs: dict[str, dict] = {}
        files: dict[str, dict] = {}
        for (object_side, key), payload in self.objects.items():
            if object_side != side or not key.startswith(relative_prefix):
                continue
            tail = key[len(relative_prefix):]
            if not tail:
                continue
            head, _, rest = tail.partition("/")
            if rest:
                dirs[head] = {"Prefix": relative_prefix + head + "/"}
            else:
                files[head] = {"Size": len(payload), "LastModified": None}
        return dirs, files, False


LEAKED_EMAIL = "b@example.com"

OBJECTS = {
    ("original", "slack/general/day.json"): json.dumps(
        {"text": "reach a@example.com or b@example.com"}
    ).encode(),
    ("redacted", "slack/general/day.json"): json.dumps(
        {"text": f"reach x@example.net or {LEAKED_EMAIL}"}
    ).encode(),
    ("original", "slack/general/clean.json"): json.dumps({"text": "reach a@example.com"}).encode(),
    ("redacted", "slack/general/clean.json"): json.dumps({"text": "reach x@example.net"}).encode(),
    # Written by the export but never rewritten - the failed-run case.
    ("original", "slack/general/orphan.json"): json.dumps({"text": "reach c@example.com"}).encode(),
    ("original", "slack/general/logo.png"): b"\x89PNG\r\n\x1a\n\x00\x00binary",
    ("redacted", "slack/general/logo.png"): b"\x89PNG\r\n\x1a\n\x00\x00binary",
    # A renamed identity folder, as `jira/` really is. Neither the folder name
    # nor PII-bearing file names survive; the exporter's own `page_00000N.jsonl`
    # do, and that shared shape is what pairs the two sides.
    ("original", "jira/person.one@example.com/attachments/page_000001.jsonl"):
        json.dumps({"text": "mail a@example.com"}).encode(),
    ("original", "jira/person.one@example.com/attachments/page_000002.jsonl"): b"{}",
    ("original", "jira/person.one@example.com/attachments/page_000003.jsonl"): b"{}",
    # A file name carrying PII is itself rewritten, so it cannot be matched on.
    ("original", "jira/person.one@example.com/attachments/Screenshot 2026-06-22.png"): b"\x89PNG\r\n\x1a\n",
    ("redacted", "jira/surrogate.one@example.net/attachments/page_000001.jsonl"):
        json.dumps({"text": "mail x@example.net"}).encode(),
    ("redacted", "jira/surrogate.one@example.net/attachments/page_000002.jsonl"): b"{}",
    ("redacted", "jira/surrogate.one@example.net/attachments/page_000003.jsonl"): b"{}",
    ("redacted", "jira/surrogate.one@example.net/attachments/Screenshot 2668-06-22.png"): b"\x89PNG\r\n\x1a\n",
    # A schema folder whose ordinary name tripped a detector: versions -> Zephyr.
    ("original", "jira/person.one@example.com/versions/page_000001.jsonl"): b'{"a":1}',
    ("original", "jira/person.one@example.com/versions/page_000002.jsonl"): b'{"a":2}',
    ("original", "jira/person.one@example.com/versions/page_000003.jsonl"): b'{"a":3}',
    ("redacted", "jira/surrogate.one@example.net/Zephyr/page_000001.jsonl"): b'{"a":1}',
    ("redacted", "jira/surrogate.one@example.net/Zephyr/page_000002.jsonl"): b'{"a":2}',
    ("redacted", "jira/surrogate.one@example.net/Zephyr/page_000003.jsonl"): b'{"a":3}',
}


@pytest.fixture
def client(monkeypatch):
    fake = FakeS3(OBJECTS)
    monkeypatch.setattr(app_module, "browser", fake)
    monkeypatch.setattr(app_module, "settings", fake.settings)
    return TestClient(app_module.app)


# --------------------------------------------------------------------------- #
# Navigation
# --------------------------------------------------------------------------- #

def test_config_reports_both_roots_and_identity(client):
    body = client.get("/api/config").json()
    assert body["bucket"] == "test-bucket"
    assert body["original_root"] == "orig/"
    assert body["redacted_root"] == "red/"
    assert body["identity"]["ok"] is True
    assert "EMAIL" in body["pii_types"]


def test_browse_merges_the_two_sides(client):
    entries = client.get("/api/browse", params={"prefix": "slack/general/"}).json()["entries"]
    by_name = {entry["name"]: entry for entry in entries}
    assert by_name["day.json"]["in_original"] and by_name["day.json"]["in_redacted"]
    # The orphan exists only on the original side, and the listing says so.
    assert by_name["orphan.json"]["in_original"] and not by_name["orphan.json"]["in_redacted"]


def test_browse_marks_directories(client):
    entries = client.get("/api/browse").json()["entries"]
    assert [entry["is_dir"] for entry in entries if entry["name"] == "slack"] == [True]


# --------------------------------------------------------------------------- #
# Renamed paths, where nearly all the PDFs, images and spreadsheets live
# --------------------------------------------------------------------------- #

def test_renamed_folder_is_paired_by_its_contents(client):
    body = client.get("/api/browse", params={"prefix": "jira/"}).json()
    row = next(e for e in body["entries"] if e["name"] == "person.one@example.com")
    assert row["in_original"] and row["in_redacted"]
    assert row["matched_by"] == "structure"
    assert row["redacted_name"] == "surrogate.one@example.net"
    assert row["relative"] == "jira/person.one@example.com/"
    assert row["relative_redacted"] == "jira/surrogate.one@example.net/"
    assert body["notes"], "the pairing should be stated, not silent"


def test_pairing_is_reported_as_structural_not_as_a_name_match(client):
    body = client.get("/api/browse", params={"prefix": "slack/general/"}).json()
    assert {e["matched_by"] for e in body["entries"]} == {"name"}


def test_a_renamed_subtree_can_be_walked(client):
    """Inside a renamed folder each step carries both paths.

    Schema folders keep their names, so they pair by name even though their parent did not.
    """
    body = client.get("/api/browse", params={
        "prefix": "jira/person.one@example.com/",
        "prefix_redacted": "jira/surrogate.one@example.net/",
    }).json()
    row = next(e for e in body["entries"] if e["name"] == "attachments")
    assert row["matched_by"] == "name"
    assert row["relative"] == "jira/person.one@example.com/attachments/"
    assert row["relative_redacted"] == "jira/surrogate.one@example.net/attachments/"


def test_an_ordinary_word_that_tripped_a_detector_still_pairs(client):
    """`versions/` came out as `Zephyr/` -- a company surrogate for a schema name."""
    body = client.get("/api/browse", params={
        "prefix": "jira/person.one@example.com/",
        "prefix_redacted": "jira/surrogate.one@example.net/",
    }).json()
    row = next(e for e in body["entries"] if e["name"] == "versions")
    assert row["matched_by"] == "structure"
    assert row["redacted_name"] == "Zephyr"
    assert row["relative_redacted"] == "jira/surrogate.one@example.net/Zephyr/"


def test_compare_across_a_renamed_path(client):
    """The whole point: a file under two different paths still verifies."""
    body = client.get("/api/compare", params={
        "relative": "jira/person.one@example.com/attachments/page_000001.jsonl",
        "relative_redacted": "jira/surrogate.one@example.net/attachments/page_000001.jsonl",
    }).json()
    assert body["verdict"] == "clean"
    assert [row["text"] for row in body["report"]["redacted"]] == ["a@example.com"]
    assert [row["text"] for row in body["report"]["surrogates"]] == ["x@example.net"]


def test_an_ambiguous_rename_is_left_unpaired():
    """Two candidates with the same shape means guessing; guessing is worse."""
    objects = {
        ("original", "root/alpha/f.txt"): b"a",
        ("original", "root/beta/f.txt"): b"b",
        ("redacted", "root/one/f.txt"): b"a",
        ("redacted", "root/two/f.txt"): b"b",
    }
    listing = FakeS3(objects).browse("root/")
    assert all(entry.matched_by == "name" for entry in listing.entries)
    assert all(not (entry.original and entry.redacted) for entry in listing.entries)


def test_unpaired_folders_are_still_listed_once_each():
    objects = {
        ("original", "root/only-left/a.txt"): b"a",
        ("redacted", "root/only-right/b.txt"): b"b",
    }
    listing = FakeS3(objects).browse("root/")
    names = sorted(entry.name for entry in listing.entries)
    assert names == ["only-left", "only-right"]


def test_index_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "PII" in response.text


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

def test_compare_reports_a_leak(client):
    body = client.get("/api/compare", params={"relative": "slack/general/day.json"}).json()
    assert body["verdict"] == "leak"
    assert [row["text"] for row in body["report"]["leaks"]] == [LEAKED_EMAIL]
    assert body["report"]["stats"]["redaction_rate"] == 50.0


def test_compare_reports_clean(client):
    body = client.get("/api/compare", params={"relative": "slack/general/clean.json"}).json()
    assert body["verdict"] == "clean"
    assert body["report"]["leaks"] == []
    assert [row["text"] for row in body["report"]["surrogates"]] == ["x@example.net"]


def test_compare_includes_an_aligned_diff(client):
    body = client.get("/api/compare", params={"relative": "slack/general/day.json"}).json()
    diff = body["diff"]
    assert diff["changed_lines"] >= 1
    assert not diff["identical"]
    replaced = [row for row in diff["rows"] if row["tag"] == "replace"]
    assert replaced and "a@example.com" in replaced[0]["left"]


def test_compare_degrades_to_one_sided_scan_when_unpaired(client):
    body = client.get("/api/compare", params={"relative": "slack/general/orphan.json"}).json()
    assert body["verdict"] == "unpaired"
    assert body["missing"] == "redacted"
    assert [row["text"] for row in body["scan"]["findings"]] == ["c@example.com"]


def test_compare_marks_an_image_renderable_and_compares_bytes(client):
    """An image has no text to diff, but it must still be viewable and compared."""
    body = client.get("/api/compare", params={"relative": "slack/general/logo.png"}).json()
    assert body["verdict"] == "no_text"
    assert body["renderable"] is True
    # Identical bytes on both sides: the redactor did not touch this image.
    assert body["bytes_identical"] is True
    assert body["original"]["meta"]["media_type"] == "image/png"


def test_raw_serves_renderable_bytes(client):
    response = client.get(
        "/api/raw", params={"relative": "slack/general/logo.png", "side": "original"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.content == OBJECTS[("original", "slack/general/logo.png")]


def test_raw_refuses_content_that_is_not_renderable(client):
    response = client.get(
        "/api/raw", params={"relative": "slack/general/day.json", "side": "original"}
    )
    assert response.status_code == 415


def test_raw_reports_a_missing_object(client):
    response = client.get("/api/raw", params={"relative": "nope.png", "side": "redacted"})
    assert response.status_code == 404


def test_compare_honours_the_type_filter(client):
    body = client.get(
        "/api/compare", params={"relative": "slack/general/day.json", "types": "pan"}
    ).json()
    # Restricted to PAN, the leaked email is out of scope and nothing is reported.
    assert body["report"]["leaks"] == []


def test_compare_rejects_a_directory(client):
    response = client.get("/api/compare", params={"relative": "slack/general/"})
    assert response.status_code == 400


# --------------------------------------------------------------------------- #
# Single side
# --------------------------------------------------------------------------- #

def test_file_endpoint_scans_one_side(client):
    body = client.get(
        "/api/file", params={"relative": "slack/general/day.json", "side": "original"}
    ).json()
    assert {row["text"] for row in body["scan"]["findings"]} == {"a@example.com", "b@example.com"}


def test_file_endpoint_reports_a_missing_object(client):
    body = client.get(
        "/api/file", params={"relative": "nope.json", "side": "redacted"}
    ).json()
    assert body["meta"]["exists"] is False
