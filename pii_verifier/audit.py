"""Verify a whole subtree, not one file at a time.

Worst file first, with caps so a wide prefix cannot run away.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from pii_redactor.policy import Policy

from .extract import extract
from .s3 import S3Browser
from .scan import SEVERITY_ORDER, verify

DEFAULT_MAX_FILES = 200
DEFAULT_MAX_DEPTH = 6
WORKERS = 12
# Findings kept per file in the summary; the file view has the rest.
TOP_FINDINGS = 5


@dataclass
class Pair:
    relative: str
    relative_redacted: str


@dataclass
class AuditResult:
    prefix: str
    files: list[dict] = field(default_factory=list)
    checked: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        by_verdict: dict[str, int] = {}
        for row in self.files:
            by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
        flagged = [r for r in self.files if r["verdict"] in ("leak", "partial")]
        return {
            "prefix": self.prefix,
            "checked": self.checked,
            "truncated": self.truncated,
            "notes": self.notes,
            "by_verdict": by_verdict,
            "flagged": len(flagged),
            "files": self.files,
        }


def collect_pairs(
    browser: S3Browser,
    prefix: str,
    prefix_redacted: str | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> tuple[list[Pair], bool, list[str]]:
    """Paired files under `prefix`, breadth-first so a wide tree is sampled evenly."""
    pairs: list[Pair] = []
    notes: list[str] = []
    queue = [(prefix, prefix_redacted or prefix, 0)]
    truncated = False

    while queue and len(pairs) < max_files:
        original, redacted, depth = queue.pop(0)
        listing = browser.browse(original, relative_prefix_redacted=redacted)
        notes.extend(n for n in listing.notes if n not in notes)
        for entry in listing.entries:
            if entry.original is None or entry.redacted is None:
                continue
            row = entry.to_json(listing.prefix, listing.prefix_redacted)
            if entry.is_dir:
                if depth + 1 <= max_depth:
                    queue.append((row["relative"], row["relative_redacted"], depth + 1))
                else:
                    truncated = True
            elif len(pairs) < max_files:
                pairs.append(Pair(row["relative"], row["relative_redacted"]))
            else:
                truncated = True

    if queue:
        truncated = True
    return pairs, truncated, notes


def _check(browser: S3Browser, pair: Pair, policy: Policy | None) -> dict:
    """Fetch, extract and verify one pair. Never raises; errors become rows."""
    row: dict = {"relative": pair.relative, "relative_redacted": pair.relative_redacted}
    try:
        original, original_truncated, original_error = browser.get("original", pair.relative)
        redacted, redacted_truncated, redacted_error = browser.get("redacted", pair.relative_redacted)
        if original_error or redacted_error:
            row.update(verdict="error", error=original_error or redacted_error)
            return row

        before = extract(pair.relative, original, original_truncated)
        after = extract(pair.relative_redacted, redacted, redacted_truncated)
        row["kind"] = before.kind
        if not before.text and not after.text:
            row.update(verdict="no_text", bytes_identical=before.digest == after.digest)
            return row

        report = verify(before.text, after.text, policy)
        # Labelled, because a full leak and a surviving fragment need different
        # responses and a mixed list hides which is which.
        findings = [("leak", f) for f in report.leaks] + [("partial", f) for f in report.partials]
        row.update(
            verdict=report.verdict,
            leaks=len(report.leaks),
            partials=len(report.partials),
            severity=report.stats.get("highest_severity"),
            redaction_rate=report.stats.get("redaction_rate"),
            top=[
                {
                    "kind": kind, "type": f["type"], "severity": f["severity"],
                    "text": f["text"][:120], "detector": f["detector"],
                    "fragments": [x["fragment"] for x in f.get("fragments", [])],
                    "line": (f.get("in_redacted") or [{}])[0].get("line"),
                    "path": (f.get("in_redacted") or [{}])[0].get("path"),
                }
                for kind, f in findings[:TOP_FINDINGS]
            ],
        )
    except Exception as exc:  # noqa: BLE001 - one bad file must not end the audit
        row.update(verdict="error", error=f"{type(exc).__name__}: {exc}")
    return row


def run(
    browser: S3Browser,
    prefix: str = "",
    prefix_redacted: str | None = None,
    policy: Policy | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> AuditResult:
    """Verify every paired file under a prefix, worst first."""
    pairs, truncated, notes = collect_pairs(browser, prefix, prefix_redacted, max_files, max_depth)
    result = AuditResult(prefix=prefix, truncated=truncated, notes=notes)
    if truncated:
        result.notes.append(
            f"Stopped after {len(pairs)} paired file(s) at depth {max_depth}; "
            "narrow the prefix or raise the limits to cover the rest."
        )
    if not pairs:
        return result

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(_check, browser, pair, policy) for pair in pairs]
        for future in as_completed(futures):
            result.files.append(future.result())
    result.checked = len(result.files)

    rank = {"leak": 0, "partial": 1, "error": 2, "clean": 3, "no_pii": 4, "no_text": 5}
    result.files.sort(key=lambda row: (
        rank.get(row["verdict"], 9),
        SEVERITY_ORDER.get(row.get("severity") or "", 9),
        -(row.get("leaks") or 0),
        row["relative"],
    ))
    return result
