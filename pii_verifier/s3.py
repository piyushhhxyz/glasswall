"""S3 access, addressed by relative key -- the part after the root prefix."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import lru_cache

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .config import Settings


@dataclass
class Entry:
    """One row in a merged listing, which may carry a different name per side."""

    name: str
    is_dir: bool
    original: dict | None = None
    redacted: dict | None = None
    redacted_name: str | None = None
    matched_by: str = "name"

    @property
    def other_name(self) -> str:
        return self.redacted_name or self.name

    def to_json(self, parent: str, parent_redacted: str | None = None) -> dict:
        slash = "/" if self.is_dir else ""
        redacted_parent = parent_redacted if parent_redacted is not None else parent
        return {
            "name": self.name,
            "relative": f"{parent}{self.name}{slash}",
            # The path to use on the redacted side, which may differ at any level.
            "relative_redacted": f"{redacted_parent}{self.other_name}{slash}",
            "redacted_name": self.redacted_name,
            "matched_by": self.matched_by,
            "is_dir": self.is_dir,
            "in_original": self.original is not None,
            "in_redacted": self.redacted is not None,
            "original_size": (self.original or {}).get("Size"),
            "redacted_size": (self.redacted or {}).get("Size"),
            "original_modified": _iso((self.original or {}).get("LastModified")),
            "redacted_modified": _iso((self.redacted or {}).get("LastModified")),
        }


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


@dataclass
class Listing:
    prefix: str
    prefix_redacted: str = ""
    entries: list[Entry] = field(default_factory=list)
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# One listing per unmatched folder. `google_chat/` holds ~420 per side, where
# most images and PDFs live, so the cap clears ~840 -- hence the concurrency.
MAX_STRUCTURAL_PROBES = 1000
FINGERPRINT_WORKERS = 16

# Keys sampled per folder to build its shape. One listing call each.
FINGERPRINT_KEYS = 400

# Below this many shared machine names, an overlap score is not evidence: two
# folders each holding a single `page_000001.jsonl` would otherwise score 1.0.
MIN_SHARED_NAMES = 3

# Exporter-generated names (`page_000001.jsonl`) hold no PII, so redaction
# leaves them alone -- the only stable thing to match renamed folders on.
_MACHINE_NAME = re.compile(r"[a-z_\-]*[_\-]?\d+\.[a-z0-9]+", re.I)

# How alike two folders must be before they are called the same folder, and how
# far ahead of the runner-up. Both apply, so a near-tie is left unpaired.
MIN_SHAPE_OVERLAP = 0.55
MIN_SHAPE_MARGIN = 0.15


class S3Browser:
    def __init__(self, settings: Settings | None = None, client=None):
        self.settings = settings or Settings.from_env()
        self._client = client

    @property
    def client(self):
        if self._client is None:
            # Retries matter: a folder render fires two list calls, and a scan
            # fires two gets. A single blip should not surface as a UI error.
            self._client = boto3.client(
                "s3",
                region_name=self.settings.region,
                config=Config(retries={"max_attempts": 3, "mode": "standard"}),
            )
        return self._client

    # -- identity ---------------------------------------------------------- #

    def whoami(self) -> dict:
        """Prove the credentials work before the UI offers to browse anything."""
        try:
            identity = boto3.client("sts", region_name=self.settings.region).get_caller_identity()
            return {"ok": True, "account": identity["Account"], "arn": identity["Arn"]}
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim in the UI banner
            return {"ok": False, "error": str(exc)}

    # -- listing ----------------------------------------------------------- #

    def _list_flat(self, side: str, relative_prefix: str, max_keys: int) -> list[str]:
        """Object keys under a prefix, relative to it, ignoring directory structure."""
        prefix = self.settings.key(side, relative_prefix)
        response = self.client.list_objects_v2(
            Bucket=self.settings.bucket, Prefix=prefix, MaxKeys=max_keys
        )
        return [obj["Key"][len(prefix):] for obj in response.get("Contents", [])]

    def _fingerprint(self, side: str, relative_prefix: str) -> frozenset[str]:
        """A shape to match a folder on, invariant under renaming."""
        try:
            keys = self._list_flat(side, relative_prefix, FINGERPRINT_KEYS)
        except ClientError:
            return frozenset()
        names = (key.rsplit("/", 1)[-1] for key in keys if not key.endswith("/"))
        return frozenset(name for name in names if _MACHINE_NAME.fullmatch(name))

    def _pair_structurally(
        self, listing: Listing, orphan_original: dict, orphan_redacted: dict
    ) -> list[Entry]:
        """Tie together folders that were renamed rather than added or dropped."""
        if not orphan_original or not orphan_redacted:
            return []
        if len(orphan_original) + len(orphan_redacted) > MAX_STRUCTURAL_PROBES:
            listing.notes.append(
                f"{len(orphan_original)} unmatched folder(s) on the original side and "
                f"{len(orphan_redacted)} on the redacted side: too many to pair structurally, "
                "so any renamed folders here are shown as one-sided."
            )
            return []

        base = listing.prefix
        base_redacted = listing.prefix_redacted
        # Concurrent because there can be ~840 of these and they are pure I/O;
        # boto3 clients are thread-safe for calls made on a shared client.
        jobs = [("original", name, f"{base}{name}/") for name in orphan_original]
        jobs += [("redacted", name, f"{base_redacted}{name}/") for name in orphan_redacted]
        shapes: dict[tuple[str, str], frozenset[str]] = {}
        with ThreadPoolExecutor(max_workers=FINGERPRINT_WORKERS) as pool:
            futures = {
                pool.submit(self._fingerprint, side, prefix): (side, name)
                for side, name, prefix in jobs
            }
            for future in as_completed(futures):
                side, name = futures[future]
                try:
                    shapes[(side, name)] = future.result()
                except Exception:  # noqa: BLE001 - an unreadable folder simply cannot pair
                    shapes[(side, name)] = frozenset()

        left = {name: shapes[("original", name)] for name in orphan_original}
        right = {name: shapes[("redacted", name)] for name in orphan_redacted}

        paired: list[Entry] = []
        used: set[str] = set()
        for name, shape in left.items():
            if not shape:
                continue
            # Exact equality is too strict: the two listings are capped, and a
            # failed rewrite leaves one side short. Score the overlap instead.
            ranked = sorted(
                ((_overlap(shape, other_shape), other) for other, other_shape in right.items()
                 if other not in used and other_shape),
                reverse=True,
            )
            if not ranked:
                continue
            best_score, best = ranked[0]
            runner_up = ranked[1][0] if len(ranked) > 1 else 0.0
            # Ambiguity is a reason to stop, not to guess: a wrong pairing would
            # silently diff two unrelated subtrees and report nonsense.
            if best_score < MIN_SHAPE_OVERLAP or best_score - runner_up < MIN_SHAPE_MARGIN:
                continue
            if len(shape & right[best]) < MIN_SHARED_NAMES:
                continue
            used.add(best)
            paired.append(Entry(
                name, True, orphan_original[name], orphan_redacted[best],
                redacted_name=best, matched_by="structure",
            ))
        if paired:
            listing.notes.append(
                f"{len(paired)} folder(s) were renamed by the redaction and are paired here by "
                "matching their contents, not their names."
            )
        unpaired = len(orphan_original) - len(paired)
        if unpaired > 0 and len(orphan_original) > 1:
            # These are renamed on both sides and shaped identically, so nothing
            # in the bucket distinguishes them and the export carries no name
            # mapping. Guessing is the only alternative to declining.
            listing.notes.append(
                f"{unpaired} folder(s) here are renamed on both sides but hold the same file "
                "layout as each other, so which pairs with which cannot be told apart. Set the "
                "two paths by hand above to compare a specific pair."
            )
        return paired

    def _list_side(self, side: str, relative_prefix: str, limit: int) -> tuple[dict, dict, bool]:
        """One page of a single side, split into subdirectories and objects."""
        prefix = self.settings.key(side, relative_prefix)
        dirs: dict[str, dict] = {}
        files: dict[str, dict] = {}
        response = self.client.list_objects_v2(
            Bucket=self.settings.bucket, Prefix=prefix, Delimiter="/", MaxKeys=limit
        )
        for common in response.get("CommonPrefixes", []):
            name = common["Prefix"][len(prefix):].rstrip("/")
            if name:
                dirs[name] = {"Prefix": common["Prefix"]}
        for obj in response.get("Contents", []):
            name = obj["Key"][len(prefix):]
            # A zero-length "directory marker" object is not a file worth showing.
            if not name or name.endswith("/"):
                continue
            files[name] = obj
        return dirs, files, bool(response.get("IsTruncated"))

    def browse(
        self,
        relative_prefix: str = "",
        limit: int = 1000,
        relative_prefix_redacted: str | None = None,
    ) -> Listing:
        """Merge a prefix on both sides into one listing."""
        if relative_prefix and not relative_prefix.endswith("/"):
            relative_prefix += "/"
        redacted_prefix = relative_prefix if relative_prefix_redacted is None else relative_prefix_redacted
        if redacted_prefix and not redacted_prefix.endswith("/"):
            redacted_prefix += "/"
        listing = Listing(prefix=relative_prefix, prefix_redacted=redacted_prefix)

        sides: dict[str, tuple[dict, dict]] = {}
        for side, prefix in (("original", relative_prefix), ("redacted", redacted_prefix)):
            try:
                dirs, files, truncated = self._list_side(side, prefix, limit)
                sides[side] = (dirs, files)
                listing.truncated = listing.truncated or truncated
            except ClientError as exc:
                sides[side] = ({}, {})
                listing.errors.append(f"{side}: {exc.response['Error'].get('Message', str(exc))}")

        o_dirs, o_files = sides.get("original", ({}, {}))
        r_dirs, r_files = sides.get("redacted", ({}, {}))

        shared_dirs = set(o_dirs) & set(r_dirs)
        entries = [Entry(name, True, o_dirs.get(name), r_dirs.get(name)) for name in shared_dirs]

        # Whatever is left on both sides may be the same folder under two names.
        orphan_original = {n: o_dirs[n] for n in set(o_dirs) - shared_dirs}
        orphan_redacted = {n: r_dirs[n] for n in set(r_dirs) - shared_dirs}
        paired = self._pair_structurally(listing, orphan_original, orphan_redacted)
        entries += paired
        claimed_left = {entry.name for entry in paired}
        claimed_right = {entry.other_name for entry in paired}
        entries += [Entry(n, True, o_dirs[n], None) for n in orphan_original if n not in claimed_left]
        entries += [Entry(n, True, None, r_dirs[n]) for n in orphan_redacted if n not in claimed_right]

        listing.entries = sorted(entries, key=lambda e: e.name.lower())
        listing.entries += [
            Entry(name, False, o_files.get(name), r_files.get(name))
            for name in sorted(set(o_files) | set(r_files), key=str.lower)
        ]
        return listing

    # -- objects ----------------------------------------------------------- #

    def head(self, side: str, relative: str) -> dict | None:
        try:
            return self.client.head_object(Bucket=self.settings.bucket, Key=self.settings.key(side, relative))
        except ClientError:
            return None

    def get(self, side: str, relative: str, max_bytes: int | None = None) -> tuple[bytes, bool, str | None]:
        """Fetch an object, capped. Returns (payload, was_truncated, error)."""
        cap = max_bytes or self.settings.max_bytes
        key = self.settings.key(side, relative)
        try:
            response = self.client.get_object(
                Bucket=self.settings.bucket, Key=key, Range=f"bytes=0-{cap - 1}"
            )
            payload = response["Body"].read()
            total = _range_total(response.get("ContentRange"), len(payload))
            return payload, total > len(payload), None
        except ClientError as exc:
            code = exc.response["Error"].get("Code", "")
            if code in ("NoSuchKey", "404"):
                return b"", False, "not found"
            # An empty object cannot satisfy a range request; that is not an error.
            if code == "InvalidRange":
                return b"", False, None
            return b"", False, exc.response["Error"].get("Message", str(exc))


def _overlap(left: frozenset[str], right: frozenset[str]) -> float:
    """How completely the smaller folder shape sits inside the larger, 0.0-1.0."""
    if not left or not right:
        return 0.0
    return len(left & right) / min(len(left), len(right))


def _range_total(content_range: str | None, fallback: int) -> int:
    """Total object size out of a `bytes 0-N/TOTAL` header."""
    if content_range and "/" in content_range:
        tail = content_range.rsplit("/", 1)[1]
        if tail.isdigit():
            return int(tail)
    return fallback


@lru_cache(maxsize=1)
def default_browser() -> S3Browser:
    return S3Browser()
