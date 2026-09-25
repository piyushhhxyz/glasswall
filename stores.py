#!/usr/bin/env python3
"""Read-only backends for the two sides of a review.

A side is anything that can list relative paths and hand back bytes: a local
directory, a zip, or an S3 prefix. Everything above this file works against
``Store`` alone, so adding a backend does not touch the pairing or the UI.
"""
from __future__ import annotations

import concurrent.futures as cf
import functools
import io
import random
import re
import subprocess
import threading
import urllib.parse
import zipfile
from collections import OrderedDict
from pathlib import Path

#: Extensions worth putting in front of a reviewer. Everything else in a
#: deliverable (databases, logs, manifests) is bookkeeping.
DOC_EXTS = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".csv", ".tsv",
    ".txt", ".md", ".json", ".jsonl", ".xml", ".html", ".htm", ".eml",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg",
    # Plain-text carriers the renderer already handles. Listing lagged behind
    # it, so a leak in a .sql dump or a .env was invisible in review.
    ".log", ".yaml", ".yml", ".ini", ".cfg", ".sql", ".vcf", ".ics", ".env",
}

#: macOS zip cruft and VCS. Pipeline bookkeeping is caught by the underscore
#: rule below rather than listed, because every stage names its own.
NOISE_DIRS = {"__MACOSX", ".git", "__pycache__", ".DS_Store", "node_modules"}


def is_doc(path: str) -> bool:
    """True for something worth putting in front of a reviewer.

    A leading underscore on ANY segment means pipeline bookkeeping, not a
    document: ``_pii/`` and ``_profile/`` hold the run's own state, ``_state/``
    holds the exporter's checkpoints, and the VLM writes ``_<name>`` beside the
    image it redacted. Excluding them by shape rather than by a list means a
    stage that invents a new one is covered without a code change.

    Pointing a side AT such a folder still works — an s3:// prefix or a folder
    path is stripped before these relative paths are formed, so
    ``s3://bucket/_pii/output`` lists ``github/x.pdf``, not ``_pii/...``.
    """
    parts = Path(path).parts
    if any(p in NOISE_DIRS for p in parts):
        return False
    if any(p.startswith("_") or p.startswith(".") for p in parts):
        return False
    return Path(parts[-1] if parts else "").suffix.lower() in DOC_EXTS


class Store:
    """A listable, readable location. Subclasses implement _list and read."""

    kind = "?"
    #: Read-through cache. An S3 read is a network round trip and the viewer
    #: asks for the same bytes again every time you step back one document.
    CACHE_MAX = 16

    def __init__(self, spec: str):
        self.spec = spec
        self._cache: "OrderedDict[str, bytes]" = OrderedDict()
        self._cache_lock = threading.Lock()

    def cached_read(self, path: str) -> bytes:
        with self._cache_lock:
            hit = self._cache.get(path)
            if hit is not None:
                self._cache.move_to_end(path)
                return hit
        data = self.read(path)
        with self._cache_lock:
            self._cache[path] = data
            while len(self._cache) > self.CACHE_MAX:
                self._cache.popitem(last=False)
        return data

    def prefetch(self, path: str) -> None:
        """Warm the cache off-thread. Failures are ignored on purpose."""
        def _run():
            try:
                self.cached_read(path)
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=_run, daemon=True).start()

    @functools.cached_property
    def paths(self) -> list[str]:
        """Everything listed, minus obvious junk. No document filtering.

        Kept separate from :attr:`docs` because a side can be SELECTED by a
        folder the document filter would reject: an in-place run writes its
        output to ``_pii/output``, and filtering before the selector is applied
        left that side empty.
        """
        return sorted(
            p for p in self._list()
            if not any(seg in NOISE_DIRS for seg in Path(p).parts)
        )

    @functools.cached_property
    def docs(self) -> list[str]:
        return sorted(p for p in self.paths if is_doc(p))

    def _list(self) -> list[str]:
        raise NotImplementedError

    def read(self, path: str) -> bytes:
        raise NotImplementedError

    def size(self, path: str) -> int:
        """Bytes, for the size-order pairing pass. 0 when unknown."""
        return 0

    def __repr__(self) -> str:
        # The s3:// scheme already names the backend; prefixing it again read
        # as "s3:s3://bucket" in the header.
        return self.spec if self.kind == "s3" else f"{self.kind}:{self.spec}"


class DirStore(Store):
    kind = "dir"

    def __init__(self, spec: str):
        super().__init__(spec)
        self.root = Path(spec).expanduser().resolve()

    def _list(self):
        return [
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
            if p.is_file()
        ]

    def read(self, path: str) -> bytes:
        target = (self.root / path).resolve()
        # A listed path is always under root; resolve() then compare so a
        # crafted request cannot walk out of the tree being reviewed.
        if not target.is_relative_to(self.root):
            raise PermissionError(path)
        return target.read_bytes()

    def size(self, path: str) -> int:
        return (self.root / path).stat().st_size


class ZipStore(Store):
    kind = "zip"

    def __init__(self, spec: str):
        super().__init__(spec)
        self.path = Path(spec).expanduser().resolve()

    def _list(self):
        with zipfile.ZipFile(self.path) as z:
            return [n for n in z.namelist() if not n.endswith("/")]

    def read(self, path: str) -> bytes:
        # Opened per read rather than held: a ZipFile handle is not safe to
        # share across the server's threads.
        with zipfile.ZipFile(self.path) as z:
            return z.read(path)

    @functools.cached_property
    def _sizes(self) -> dict[str, int]:
        with zipfile.ZipFile(self.path) as z:
            return {i.filename: i.file_size for i in z.infolist()}

    def size(self, path: str) -> int:
        return self._sizes.get(path, 0)


#: The host forms AWS actually serves a bucket under. Virtual-hosted puts the
#: bucket in the host (``bucket.s3.ap-south-1.amazonaws.com``); path-style puts
#: it first in the path (``s3.ap-south-1.amazonaws.com/bucket/key``). Both
#: spell the region with a dot or, on older links, a dash.
_S3_VHOST = re.compile(
    r"^(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"\.s3(?:[.-](?:dualstack\.)?(?P<region>[a-z]{2}-[a-z]+-\d))?"
    r"\.amazonaws\.com(?:\.cn)?$")
_S3_PATH = re.compile(
    r"^s3(?:[.-](?:dualstack\.)?(?P<region>[a-z]{2}-[a-z]+-\d))?"
    r"\.amazonaws\.com(?:\.cn)?$")
#: The global console host (``s3.console...``), the per-region one it now
#: redirects to (``ap-south-1.console...``), and the bare form.
_S3_CONSOLE = re.compile(
    r"^(?:(?P<region>[a-z]{2}-[a-z]+-\d)\.|s3\.)?console\.aws\.amazon\.com$")
_S3_ARN = re.compile(r"^arn:aws[a-z\-]*:s3:[a-z0-9\-]*:[0-9]*:(?P<rest>.+)$")


def parse_s3(spec: str):
    """``(s3://bucket/prefix, region)`` for anything that names an S3 location.

    ``None`` when it names something else, so the caller can go on to try a
    folder or a zip.

    Nobody types ``s3://``. What a person has in their clipboard is whatever
    the console put in the address bar, and that is one of five shapes -- the
    console URL, the two REST endpoints, an ARN off an IAM policy, or the
    ``s3://`` URI the CLI prints. Rejecting four of the five with "not a
    folder, a .zip, or an s3:// URI" made the tool look broken at the exact
    moment a reviewer had the right location in hand.

    The region comes back because a console URL carries the one fact a profile
    often lacks. These buckets are ap-south-1 and the SSO profile sets no
    default region; a client built without one answers a cross-region bucket
    with PermanentRedirect, which surfaces as an empty file list rather than
    as an error about regions.
    """
    spec = (spec or "").strip().strip("\u200b")
    if not spec:
        return None

    if spec.startswith("s3://"):
        return _s3_uri(spec[5:]), None

    m = _S3_ARN.match(spec)
    if m:
        # arn:aws:s3:::bucket/prefix -- account and region are empty for S3.
        return _s3_uri(m.group("rest")), None

    if not spec.startswith(("http://", "https://")):
        return None

    u = urllib.parse.urlparse(spec)
    host = u.netloc.split("@")[-1].split(":")[0].lower()
    qs = urllib.parse.parse_qs(u.query)
    region = (qs.get("region") or [None])[0]

    m = _S3_CONSOLE.match(host)
    if m:
        # /s3/buckets/<bucket> for a folder, /s3/object/<bucket> for a file.
        # Either way the part of the location the user is looking at is in
        # ?prefix=, percent-encoded, and the path holds only the bucket.
        bits = [b for b in u.path.split("/") if b]
        if len(bits) < 3 or bits[0] != "s3" or bits[1] not in ("buckets", "object"):
            return None
        bucket = urllib.parse.unquote(bits[2])
        prefix = urllib.parse.unquote((qs.get("prefix") or [""])[0])
        if bits[1] == "object":
            # An object URL names one file. The path says so, so this is not a
            # guess: back up to the folder holding it, which is the thing a
            # reviewer looking at that file actually wants opened.
            prefix = prefix.rsplit("/", 1)[0] if "/" in prefix else ""
        return _s3_uri(f"{bucket}/{prefix}"), region or m.group("region")

    m = _S3_VHOST.match(host)
    if m:
        key = urllib.parse.unquote(u.path)
        return _s3_uri(f"{m.group('bucket')}/{key}"), region or m.group("region")

    m = _S3_PATH.match(host)
    if m:
        rest = urllib.parse.unquote(u.path)
        if not rest.strip("/"):
            return None
        return _s3_uri(rest), region or m.group("region")

    return None


def _s3_uri(rest: str) -> str:
    """``bucket/a//b/`` -> ``s3://bucket/a/b``. Collapses the empty segments a
    hand-pasted prefix picks up, and drops the trailing slash the console
    always appends -- the two spellings are the same prefix, and leaving both
    in circulation gives one run two entries in the recents list and two
    unrelated sets of verdicts in marks.json."""
    parts = [p for p in rest.split("/") if p]
    return "s3://" + "/".join(parts)


class S3Store(Store):
    """An S3 prefix. Uses boto3 when importable, else the aws CLI.

    The CLI fallback exists so the tool runs under a bare system python with
    nothing installed — which is the interpreter most people will reach for.
    """

    kind = "s3"

    #: Pages read per branch. A thousand keys a page. Bounded because a full
    #: walk of a real export is ~120 sequential round trips PER SIDE -- minutes
    #: of blank screen before the first document appears -- and nobody reviews
    #: 121,538 documents. Five pages a branch is read in parallel and lands in
    #: seconds.
    SCAN_PAGES = 5
    DEFAULT_CAP = 1  # any truthy value: the bound is SCAN_PAGES, not a count

    #: How far the delimited descent goes looking for the level to budget at,
    #: how wide a fork it will step through, and how many branches it will
    #: carry in total. See ``_branches`` -- the three together are what make
    #: the key cap survivable.
    BRANCH_DEPTH = 4
    WIDE = 12
    MAX_BRANCHES = 64

    def __init__(self, spec: str, profile: str | None = None,
                 region: str | None = None, cap: int | None = -1):
        uri = parse_s3(spec)
        spec = uri[0] if uri else spec
        region = region or (uri[1] if uri else None)
        super().__init__(spec)
        rest = spec[len("s3://"):].strip("/")
        self.bucket, _, self.prefix = rest.partition("/")
        self.profile = profile or None
        self.region = region or None
        self.cap = self.DEFAULT_CAP if cap == -1 else (cap or 0)
        self.capped = False
        self._client = None
        self._size_map: dict[str, int] = {}
        try:
            import boto3  # noqa: PLC0415 -- optional, probed at construction

            session = boto3.Session(profile_name=self.profile) if self.profile \
                else boto3.Session()
            self._client = session.client("s3", region_name=self.region)
        except Exception:  # noqa: BLE001 -- fall back to the CLI
            self._client = None

    def _aws(self, *args: str) -> bytes:
        cmd = ["aws"] + (["--profile", self.profile] if self.profile else []) \
            + (["--region", self.region] if self.region else []) + list(args)
        done = subprocess.run(cmd, capture_output=True)
        if done.returncode != 0:
            raise RuntimeError(done.stderr.decode()[:400] or "aws failed")
        return done.stdout

    def _walk(self, prefix: str):
        """Keys under one prefix, paginated, stopping at ``self.cap``.

        The cap is why this tool opens at all on a real export. S3 returns a
        thousand keys per request and will not say how many there are, so a
        full walk of a 121,538-document run is ~120 sequential round trips per
        side -- minutes of blank screen. Nobody reviews 121,538 documents.
        The job is to look at a few per app and to search for the handful
        somebody reported, so take a sample of each branch and get out.

        Per BRANCH, not per run: capping the total would spend the whole
        budget inside whichever app sorts first and show none of the rest.
        """
        keys, sizes, token, pages = [], {}, None, 0
        while True:
            kw = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            page = self._client.list_objects_v2(**kw)
            for o in page.get("Contents", []):
                keys.append(o["Key"])
                sizes[o["Key"]] = o.get("Size", 0)
            token = page.get("NextContinuationToken")
            pages += 1
            if not token or (self.cap and pages >= self.SCAN_PAGES):
                break
        # Deliberately NOT sampled here. Sampling keys is what a first attempt
        # did, and it cost 99% of the pairs: each side drew its own hundred at
        # random, the two draws barely overlapped, and 1,269 pairs became 10.
        # The two halves have to be listed whole for anything to pair at all.
        # Thinning happens once, on the PAIRS, in open_review.
        self.capped = self.capped or bool(token)
        return keys, sizes

    def _walk_shallow(self, prefix: str):
        """Keys directly under ``prefix``, skipping the folders the threads
        already covered. Without this, a run with loose files at its root
        loses them."""
        keys, sizes, token = [], {}, None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": prefix, "Delimiter": "/"}
            if token:
                kw["ContinuationToken"] = token
            page = self._client.list_objects_v2(**kw)
            for o in page.get("Contents", []):
                keys.append(o["Key"])
                sizes[o["Key"]] = o.get("Size", 0)
            token = page.get("NextContinuationToken")
            if not token:
                return keys, sizes

    def _branches(self, base: str, depth: int | None = None):
        """The level to spend the key budget at, and the parents above it.

        The budget is per branch, so WHERE the branches are decided is what
        the reviewer actually sees. Stopping one level too high is not a
        smaller sample, it is a broken review: ``gmail/`` holds six people in
        both halves, and one shared budget of five thousand keys reached three
        of them on the source side and one on the output side. The two slices
        barely overlapped, 4,861 source documents paired 2, and the sidebar
        said gmail had two files in it.

        So descend until the branches are the smallest units that still fit in
        one parallel sweep. Then each person is budgeted separately, both
        halves cut their subtree at the same relative depth, and the keys line
        up because an export lists in the same order on both sides.

        Returns the leaves to walk and every prefix descended through, which
        the caller shallow-walks: a file sitting directly in ``slack/`` is
        under none of the leaves and would otherwise vanish the moment the
        descent stepped past it.
        """
        depth = self.BRANCH_DEPTH if depth is None else depth
        frontier, done, parents = self._children(base), [], [base]
        for _ in range(max(0, depth - 1)):
            if not frontier:
                break
            kids = self._map(self._children, frontier)
            # Per branch, not per level. ``slack/`` forks a hundred ways and a
            # flat walk across it already samples every channel; ``gmail/``
            # forks six ways and each fork is a person with thirty thousand
            # keys, so one shared budget reaches one person. Letting the wide
            # fork stop the narrow ones from descending is exactly the bug:
            # the source stayed at connector level because of slack while the
            # output, which has no slack, went a level deeper, and the two
            # halves then sampled different parts of the same tree.
            wide = {b for b, k in zip(frontier, kids) if not k or len(k) > self.WIDE}
            grew = [b for b in frontier if b not in wide]
            if not grew:
                break
            nxt = [c for b, k in zip(frontier, kids) if b not in wide for c in k]
            stay = [b for b in frontier if b in wide]
            # Past the bound the sweep stops being parallel and starts being a
            # few hundred round trips, which is the blank screen this whole
            # scheme exists to avoid.
            if len(done) + len(stay) + len(nxt) > self.MAX_BRANCHES:
                break
            parents += grew
            done += stay
            frontier = nxt
        return done + frontier, parents

    def _map(self, fn, items):
        """``fn`` over ``items``, in parallel. Each call is one round trip and
        there are a few dozen of them; sequentially that is the descent taking
        longer than the walk it is setting up."""
        if len(items) <= 1:
            return [fn(i) for i in items]
        with cf.ThreadPoolExecutor(max_workers=min(16, len(items))) as ex:
            return list(ex.map(fn, items))

    def _children(self, base: str) -> list[str]:
        """Immediate child folders of ``base``, one cheap delimited call."""
        out, token = [], None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": base, "Delimiter": "/"}
            if token:
                kw["ContinuationToken"] = token
            page = self._client.list_objects_v2(**kw)
            out += [c["Prefix"] for c in page.get("CommonPrefixes", [])]
            token = page.get("NextContinuationToken")
            if not token:
                return out

    def _list(self):
        base = f"{self.prefix}/" if self.prefix else ""
        if self._client is not None:
            # S3 paginates a thousand keys at a time and will not tell you how
            # many there are, so a flat walk of a large export is a few hundred
            # sequential round trips -- minutes of blank screen before the
            # first document appears. Split the walk by top-level folder and
            # run the branches at once. Nothing is downloaded either way: this
            # is the key listing, and document bytes are still read one at a
            # time, on demand, as the reviewer arrives at them.
            keys = []
            branches, parents = self._branches(base)
            if branches:
                parts = self._map(self._walk, branches)
                # Keys sitting directly in a folder the descent stepped past,
                # alongside its subfolders. One delimited call each.
                parts += self._map(self._walk_shallow, parents)
                for k, sz in parts:
                    keys += k
                    self._size_map.update(sz)
            else:
                keys, sizes = self._walk(base)
                self._size_map.update(sizes)
        else:
            out = self._aws("s3", "ls", f"s3://{self.bucket}/{base}", "--recursive")
            keys = []
            for line in out.decode().splitlines():
                bits = line.split(None, 3)
                if len(bits) == 4:
                    keys.append(bits[3])
                    self._size_map[bits[3]] = int(bits[2]) if bits[2].isdigit() else 0
        n = len(base)
        self._size_map = {k[n:]: v for k, v in self._size_map.items()}
        return [k[n:] for k in keys if k != base and not k.endswith("/")]

    def size(self, path: str) -> int:
        return self._size_map.get(path, 0)

    def read(self, path: str) -> bytes:
        key = f"{self.prefix}/{path}" if self.prefix else path
        if self._client is not None:
            buf = io.BytesIO()
            self._client.download_fileobj(self.bucket, key, buf)
            return buf.getvalue()
        return self._aws("s3", "cp", f"s3://{self.bucket}/{key}", "-")


class GcsStore(S3Store):
    """A GCS prefix, over the ``gcloud storage`` CLI.

    Google's client library is not a dependency here and its credentials are a
    separate login from the CLI's, so the CLI is the only backend that works
    wherever gcloud already does. Everything else - pairing, the branch
    descent, the key cap - is S3Store's; only the two shell calls differ.
    """

    kind = "gcs"

    def __init__(self, spec: str, profile: str | None = None,
                 region: str | None = None, cap: int | None = -1):
        Store.__init__(self, spec)
        rest = spec[len("gs://"):].strip("/")
        self.bucket, _, self.prefix = rest.partition("/")
        self.profile = self.region = None
        self.cap = self.DEFAULT_CAP if cap == -1 else (cap or 0)
        self.capped = False
        self._client = None          # forces S3Store onto its CLI paths
        self._size_map: dict[str, int] = {}

    def _aws(self, *args: str) -> bytes:
        """Answer S3Store's two CLI shapes with gcloud."""
        if args[:2] == ("s3", "ls"):
            uri = args[2].replace("s3://", "gs://", 1).rstrip("/") + "/**"
            done = subprocess.run(["gcloud", "storage", "ls", "-l", uri],
                                  capture_output=True)
            if done.returncode != 0:
                raise RuntimeError(done.stderr.decode()[:400] or "gcloud failed")
            lines = []
            for raw in done.stdout.decode("utf-8", "replace").splitlines():
                bits = raw.split(None, 2)
                if len(bits) != 3 or not bits[2].startswith("gs://"):
                    continue
                key = bits[2][len(f"gs://{self.bucket}/"):]
                size = bits[0] if bits[0].isdigit() else "0"
                # S3Store's parser wants "date time size key".
                lines.append(f"2026-01-01 00:00:00 {size} {key}")
            return ("\n".join(lines) + "\n").encode()
        if args[:2] == ("s3", "cp"):
            uri = args[2].replace("s3://", "gs://", 1)
            done = subprocess.run(["gcloud", "storage", "cat", uri],
                                  capture_output=True)
            if done.returncode != 0:
                raise RuntimeError(done.stderr.decode()[:400] or "gcloud failed")
            return done.stdout
        raise RuntimeError(f"unsupported CLI shape: {args[:2]}")


def open_store(spec: str, profile: str | None = None,
               cap: int | None = -1) -> Store:
    """Pick a backend from the shape of ``spec``. Raises with a usable message."""
    spec = (spec or "").strip()
    if not spec:
        raise ValueError("give a folder, a .zip, or an S3 location")
    if spec.startswith("gs://"):
        return GcsStore(spec, profile, None, cap)
    s3 = parse_s3(spec)
    if s3:
        return S3Store(s3[0], profile, s3[1], cap)
    p = Path(spec).expanduser()
    if p.is_dir():
        return DirStore(str(p))
    if p.is_file() and p.suffix.lower() == ".zip":
        return ZipStore(str(p))
    if not p.exists():
        raise FileNotFoundError(f"no such folder or file: {spec}")
    raise ValueError(f"not a folder, a .zip, or an S3 location: {spec}")
