"""What was found, and what survived: `leak`, `redacted` or `surrogate`.

A redacted file is meant to look full of PII; only a surviving original leaks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pii_redactor.detectors import PATTERN_DETECTORS
from pii_redactor.entities import GazetteerDetector, build_gazetteer
from pii_redactor.model import PiiType, Span, resolve
from pii_redactor.policy import Policy

from . import locate, noise, partial
from .fields import FIELD_DETECTORS
from .secrets import SECRET_DETECTORS

# Short values collide by accident: a two-letter token or a bare `1.1.1.1` would
# "leak" into any file long enough to contain those characters by chance. Below
# this length a literal-substring match is not evidence of anything.
MIN_LEAK_LENGTH = 5

# A leak's cost depends on what leaked. Direct identifiers re-identify a person
# on their own; an org name or a URL usually does not.
SEVERITY: dict[PiiType, str] = {
    PiiType.SECRET: "critical",
    PiiType.AADHAAR: "critical",
    PiiType.PAN: "critical",
    PiiType.CREDIT_CARD: "critical",
    PiiType.SSN: "critical",
    PiiType.PASSPORT: "critical",
    PiiType.BANK_ACCOUNT: "critical",
    PiiType.EMAIL: "high",
    PiiType.PHONE: "high",
    PiiType.ADDRESS: "high",
    PiiType.DOB: "high",
    PiiType.GSTIN: "high",
    PiiType.CIN: "high",
    PiiType.DIN: "high",
    PiiType.IFSC: "medium",
    PiiType.SEBI_REGN: "medium",
    PiiType.REG_NUMBER: "medium",
    PiiType.ID_DOCUMENT: "medium",
    PiiType.PERSON: "medium",
    PiiType.ORG: "low",
    PiiType.URL: "low",
    PiiType.IP: "low",
    PiiType.LOCATION: "low",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def severity_of(pii_type: PiiType) -> str:
    return SEVERITY.get(pii_type, "medium")


def normalise(value: str) -> str:
    """Collapse whitespace and case. Used to group findings by value."""
    return re.sub(r"\s+", " ", value).strip().lower()


def squeeze(value: str) -> str:
    """Drop whitespace entirely and lowercase, for leak comparison.

    Respacing goes both ways, so comparison happens where it cannot vary.
    """
    return re.sub(r"\s+", "", value).lower()


@dataclass
class Finding:
    type: PiiType
    text: str
    detector: str
    start: int
    end: int

    def to_json(self, **extra) -> dict:
        return {
            "type": self.type.value,
            "text": self.text,
            "detector": self.detector,
            "start": self.start,
            "end": self.end,
            "severity": severity_of(self.type),
            **extra,
        }


def detectors_for(text: str, gazetteer: bool = False) -> list:
    """The detector set to run over one text.

    `gazetteer` is off by default: it over-captures on JSON. See `fields.py`.
    """
    active = [*PATTERN_DETECTORS, *SECRET_DETECTORS, *FIELD_DETECTORS]
    if gazetteer and text:
        gaz = build_gazetteer(text.splitlines())
        if gaz.name_tokens or gaz.orgs:
            active.append(GazetteerDetector(gaz))
    return active


def scan(text: str, policy: Policy | None = None, gazetteer: bool = False) -> list[Finding]:
    """Every accepted, non-overlapping detection in `text`.

    Reuses the redactor's own detectors so the two agree by construction.
    """
    policy = policy or Policy()
    if not text:
        return []
    active = detectors_for(text, gazetteer)
    spans: list[Span] = [span for detector in active for span in detector.find(text)]
    kept = [span for span in resolve(spans) if policy.accepts(span, text)]
    return [Finding(s.type, s.text, s.detector, s.start, s.end) for s in kept]


# Locating a leak for display allows whitespace between every character, which
# is the regex equivalent of the `squeeze` comparison. Capped because the pattern
# grows with the value and an over-captured address can run to a few hundred chars.
_LOCATE_MAX = 200


def flexible_pattern(value: str) -> str:
    """Match `value` however its whitespace was respaced, including not at all."""
    characters = [re.escape(ch) for ch in squeeze(value)]
    return r"\s*".join(characters)


def _locate(needle: str, haystack: str, limit: int = 20) -> list[list[int]]:
    """Case-insensitive offsets of `needle` in `haystack`, for highlighting."""
    if len(needle) > _LOCATE_MAX:
        return []
    try:
        pattern = re.compile(flexible_pattern(needle), re.I)
    except re.error:
        return []
    return [[m.start(), m.end()] for m in list(pattern.finditer(haystack))[:limit]]


@dataclass
class Report:
    verdict: str = "clean"
    leaks: list[dict] = field(default_factory=list)
    partials: list[dict] = field(default_factory=list)
    ignored: list[dict] = field(default_factory=list)
    redacted: list[dict] = field(default_factory=list)
    surrogates: list[dict] = field(default_factory=list)
    before_counts: dict[str, int] = field(default_factory=dict)
    after_counts: dict[str, int] = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "verdict": self.verdict,
            "leaks": self.leaks,
            "partials": self.partials,
            "ignored": self.ignored,
            "redacted": self.redacted,
            "surrogates": self.surrogates,
            "before_counts": self.before_counts,
            "after_counts": self.after_counts,
            "stats": self.stats,
        }


def _counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.type.value] = out.get(finding.type.value, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# Occurrences reported per finding. A value repeated 400 times needs a count,
# not 400 locations.
MAX_SITES = 20


def _downgrade(severity: str) -> str:
    """A fragment is less exposing than the whole value, but never harmless."""
    order = ["critical", "high", "medium", "low"]
    return order[min(order.index(severity) + 1, len(order) - 1)]


def _fragment_sites(fragments: list[dict], text: str, index: locate.LineIndex) -> list[dict]:
    """Where each surviving fragment sits in the redacted text."""
    sites: list[dict] = []
    for item in fragments:
        for start, end in _locate(item["fragment"], text, MAX_SITES):
            site = locate.describe(text, start, end, index)
            site["fragment"] = item["fragment"]
            sites.append(site)
            if len(sites) >= MAX_SITES:
                return sites
    return sites


def verify(
    before_text: str,
    after_text: str,
    policy: Policy | None = None,
    suppress_noise: bool = True,
    gazetteer: bool = False,
) -> Report:
    """Compare a before/after pair and decide whether the redaction held."""
    before = scan(before_text, policy, gazetteer)
    after = scan(after_text, policy, gazetteer)
    report = Report(before_counts=_counts(before), after_counts=_counts(after))

    after_squeezed = squeeze(after_text)
    after_digits = re.sub(r"\D", "", after_text)
    before_index = locate.LineIndex.build(before_text)
    after_index = locate.LineIndex.build(after_text)

    # Group the original's detections by value: the same email appearing eight
    # times is one leak with eight occurrences, not eight findings.
    by_value: dict[str, list[Finding]] = {}
    for finding in before:
        by_value.setdefault(normalise(finding.text), []).append(finding)

    leaked_values: set[str] = set()
    for value, findings in by_value.items():
        first = findings[0]
        row = first.to_json(occurrences=len(findings))
        row["in_original"] = [
            locate.describe(before_text, f.start, f.end, before_index) for f in findings[:MAX_SITES]
        ]
        needle = squeeze(value)
        # Plain containment in whitespace-free space: no regex, no respacing
        # blind spots, and linear in the size of the file.
        present = len(needle) >= MIN_LEAK_LENGTH and needle in after_squeezed
        if not present:
            # The whole value is gone, but a fragment of it may not be.
            fragments = partial.survivors(first.type, first.text, after_squeezed, after_digits)
            if fragments:
                row["fragments"] = fragments
                row["in_redacted"] = _fragment_sites(fragments, after_text, after_index)
                row["severity"] = _downgrade(row["severity"])
                report.partials.append(row)
            else:
                report.redacted.append(row)
            continue

        reason = (
            noise.classify(first.type, first.text, before_text, first.start)
            if suppress_noise
            else None
        )
        if reason:
            # Structure, not content: an unchanged Slack timestamp is not a leak.
            row["ignored_because"] = reason
            report.ignored.append(row)
            continue

        leaked_values.add(value)
        row["in_redacted"] = [
            locate.describe(after_text, start, end, after_index)
            for start, end in _locate(first.text, after_text, MAX_SITES)
        ]
        report.leaks.append(row)

    # Anything the output introduced is a surrogate. Reported for visibility --
    # it is how you confirm the redactor substituted rather than simply deleted.
    seen: set[str] = set()
    for finding in after:
        value = normalise(finding.text)
        if value in by_value or value in seen:
            continue
        seen.add(value)
        report.surrogates.append(finding.to_json())

    # Over-captured spans differ slightly but survive identically, so collapse
    # partials that report the same fragments for the same type.
    unique: dict[tuple, dict] = {}
    for row in report.partials:
        key = (row["type"], tuple(sorted(f["fragment"] for f in row["fragments"])))
        if key in unique:
            unique[key]["occurrences"] += row["occurrences"]
        else:
            unique[key] = row
    report.partials = list(unique.values())

    for bucket in (report.leaks, report.partials, report.ignored):
        bucket.sort(key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), -row["occurrences"]))
    report.surrogates.sort(key=lambda row: row["start"])

    distinct_before = len(by_value)
    # The rate measures what the redactor was actually asked to do, so values
    # written off as structure are excluded from the denominator rather than
    # counted as successes. A partial survivor is not a success either.
    in_scope = distinct_before - len(report.ignored)
    worst = [row["severity"] for row in report.leaks + report.partials]
    report.stats = {
        "distinct_before": distinct_before,
        "in_scope": in_scope,
        "leaked": len(leaked_values),
        "partial": len(report.partials),
        "removed": len(report.redacted),
        "ignored": len(report.ignored),
        "surrogates": len(report.surrogates),
        "redaction_rate": round(100 * len(report.redacted) / in_scope, 1) if in_scope else None,
        "highest_severity": min(worst, key=lambda s: SEVERITY_ORDER.get(s, 9)) if worst else None,
    }
    if report.leaks:
        report.verdict = "leak"
    elif report.partials:
        report.verdict = "partial"
    else:
        report.verdict = "clean" if in_scope else "no_pii"
    return report


def scan_only(
    text: str,
    policy: Policy | None = None,
    suppress_noise: bool = True,
    gazetteer: bool = False,
) -> dict:
    """Single-sided scan, for a file with no counterpart to compare against."""
    findings = scan(text, policy, gazetteer)
    index = locate.LineIndex.build(text)
    grouped: dict[str, dict] = {}
    for finding in findings:
        value = normalise(finding.text)
        if value in grouped:
            grouped[value]["occurrences"] += 1
            if len(grouped[value]["sites"]) < MAX_SITES:
                grouped[value]["sites"].append(
                    locate.describe(text, finding.start, finding.end, index)
                )
            continue
        row = finding.to_json(occurrences=1)
        row["sites"] = [locate.describe(text, finding.start, finding.end, index)]
        reason = (
            noise.classify(finding.type, finding.text, text, finding.start)
            if suppress_noise
            else None
        )
        if reason:
            row["ignored_because"] = reason
        grouped[value] = row

    def order(row: dict) -> tuple:
        return SEVERITY_ORDER.get(row["severity"], 9), -row["occurrences"]

    rows = [row for row in grouped.values() if "ignored_because" not in row]
    ignored = [row for row in grouped.values() if "ignored_because" in row]
    rows.sort(key=order)
    ignored.sort(key=order)
    return {
        "findings": rows,
        "ignored": ignored,
        "counts": _counts(findings),
        "distinct": len(rows),
    }
