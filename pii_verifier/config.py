"""Where the two trees live and how we reach them."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The export tree is a sibling pair: the same relative keys under two roots. The
# redacted side is the one under test, the original side is the reference.
DEFAULT_BUCKET = "your-bucket"
DEFAULT_ORIGINAL_ROOT = "export/"
DEFAULT_REDACTED_ROOT = "export-pii/"
# The bucket is regional; guessing wrong costs a redirect on every call.
DEFAULT_REGION = "ap-south-1"

# Fetching a whole object to scan a preview of it is wasteful, and a 2 GB Parquet
# part would take the browser down with it.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024


def load_dotenv(path: Path | None = None) -> None:
    """Minimal `.env` loader. Existing environment variables always win."""
    path = path or REPO_ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # Quotes are how a secret containing `#` or spaces survives the file.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def normalise_root(value: str) -> str:
    """`s3://bucket/a/b`, `/a/b/`, `a/b` -> `a/b/`. Empty means the bucket root."""
    value = re.sub(r"^s3://[^/]+/?", "", value.strip())
    value = value.strip("/")
    return f"{value}/" if value else ""


def bucket_from_uri(value: str) -> str | None:
    match = re.match(r"^s3://([^/]+)", value.strip())
    return match.group(1) if match else None


@dataclass
class Settings:
    bucket: str = DEFAULT_BUCKET
    original_root: str = DEFAULT_ORIGINAL_ROOT
    redacted_root: str = DEFAULT_REDACTED_ROOT
    region: str = DEFAULT_REGION
    max_bytes: int = DEFAULT_MAX_BYTES

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        original = os.environ.get("ORIGINAL_DATA_URI", DEFAULT_ORIGINAL_ROOT)
        redacted = os.environ.get("PII_DATA_URI", DEFAULT_REDACTED_ROOT)
        # A full s3:// URI carries the bucket with it, so honour that over the default.
        bucket = (
            os.environ.get("S3_BUCKET")
            or bucket_from_uri(redacted)
            or bucket_from_uri(original)
            or DEFAULT_BUCKET
        )
        return cls(
            bucket=bucket,
            original_root=normalise_root(original),
            redacted_root=normalise_root(redacted),
            region=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_REGION,
            max_bytes=int(os.environ.get("MAX_OBJECT_BYTES", DEFAULT_MAX_BYTES)),
        )

    def root(self, side: str) -> str:
        if side not in ("original", "redacted"):
            raise ValueError(f"side must be 'original' or 'redacted', got {side!r}")
        return self.original_root if side == "original" else self.redacted_root

    def key(self, side: str, relative: str) -> str:
        return f"{self.root(side)}{relative.lstrip('/')}"
