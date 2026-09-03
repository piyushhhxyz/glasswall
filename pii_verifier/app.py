"""HTTP surface for the verifier UI, each endpoint a wrapper over one module."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Query, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from pii_redactor.policy import Policy

from . import diff as diff_module
from . import extract as extract_module
from . import scan as scan_module
from .config import Settings
from .s3 import S3Browser

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="PII Verifier", docs_url="/api/docs")
settings = Settings.from_env()
browser = S3Browser(settings)


def _policy(types: str | None) -> Policy:
    """Build a policy from a comma-separated type filter, ignoring unknown names."""
    if not types:
        return Policy()
    names = [name.strip() for name in types.split(",") if name.strip()]
    try:
        return Policy.from_names(names)
    except KeyError:
        return Policy()


@app.get("/api/config")
def get_config() -> dict:
    """What the UI is pointed at, and whether the credentials actually work."""
    return {
        "bucket": settings.bucket,
        "original_root": settings.original_root,
        "redacted_root": settings.redacted_root,
        "region": settings.region,
        "max_bytes": settings.max_bytes,
        "identity": browser.whoami(),
        "pii_types": sorted(t.value for t in scan_module.PiiType),
    }


@app.get("/api/browse")
def browse(
    prefix: str = "",
    limit: int = Query(1000, ge=1, le=5000),
    prefix_redacted: str | None = None,
) -> dict:
    """One merged folder of the two trees."""
    listing = browser.browse(prefix, limit=limit, relative_prefix_redacted=prefix_redacted)
    return {
        "prefix": listing.prefix,
        "prefix_redacted": listing.prefix_redacted,
        "entries": [entry.to_json(listing.prefix, listing.prefix_redacted) for entry in listing.entries],
        "truncated": listing.truncated,
        "errors": listing.errors,
        "notes": listing.notes,
    }


def _load(side: str, relative: str) -> tuple[extract_module.Extracted, dict]:
    """Fetch and extract one side, returning the text plus its metadata."""
    payload, truncated, error = browser.get(side, relative)
    meta = {
        "side": side,
        "key": settings.key(side, relative),
        "bytes": len(payload),
        "error": error,
        "exists": error != "not found",
    }
    if error:
        return extract_module.EMPTY, meta
    extracted = extract_module.extract(relative, payload, truncated)
    meta.update({
        "kind": extracted.kind,
        "note": extracted.note,
        "truncated": extracted.truncated,
        "media_type": extracted.media_type,
        "digest": extracted.digest,
        **extracted.extras,
    })
    return extracted, meta


@app.get("/api/file")
def get_file(
    relative: str,
    side: str = Query("redacted", pattern="^(original|redacted)$"),
    types: str | None = None,
) -> JSONResponse:
    """A single file with a one-sided scan, for when no counterpart exists."""
    if not relative or relative.endswith("/"):
        return JSONResponse({"error": "relative must name a file"}, status_code=400)
    extracted, meta = _load(side, relative)
    return JSONResponse({
        "relative": relative,
        "meta": meta,
        "text": extracted.text,
        "scan": scan_module.scan_only(extracted.text, _policy(types)),
    })


@app.get("/api/compare")
def compare(
    relative: str,
    types: str | None = None,
    collapse: bool = True,
    relative_redacted: str | None = None,
) -> JSONResponse:
    """Fetch both sides of one key, verify, and align for display.

    `relative_redacted` differs only inside a renamed subtree, and defaults to the same path.
    """
    if not relative or relative.endswith("/"):
        return JSONResponse({"error": "relative must name a file"}, status_code=400)
    redacted_relative = relative_redacted or relative

    before, before_meta = _load("original", relative)
    after, after_meta = _load("redacted", redacted_relative)

    response: dict = {
        "relative": relative,
        "relative_redacted": redacted_relative,
        "original": {"meta": before_meta, "text": before.text},
        "redacted": {"meta": after_meta, "text": after.text},
        # Whether the browser can render this content is a property of the file,
        # not of the pairing -- a one-sided image is still worth looking at.
        "renderable": bool(before.media_type or after.media_type),
        "bytes_identical": bool(before.digest and before.digest == after.digest),
    }

    # A pair needs both sides. Missing counterparts are common in this export --
    # the run that produced it failed partway through the rewrite phase -- so the
    # UI degrades to a one-sided scan instead of an error.
    if not before_meta["exists"] or not after_meta["exists"]:
        missing = "original" if not before_meta["exists"] else "redacted"
        present = after if missing == "original" else before
        response["verdict"] = "unpaired"
        response["missing"] = missing
        response["scan"] = scan_module.scan_only(present.text, _policy(types))
        return JSONResponse(response)

    # Images and opaque media carry no text to align. The two sides are still
    # compared -- by digest, and visually in the browser via /api/raw -- and any
    # OCR'd text is verified below like any other text.
    if before.kind == "opaque" or after.kind == "opaque":
        response["verdict"] = "opaque"
        return JSONResponse(response)
    if not before.text and not after.text:
        response["verdict"] = "no_text"
        return JSONResponse(response)

    report = scan_module.verify(before.text, after.text, _policy(types))
    response["report"] = report.to_json()
    response["verdict"] = report.verdict
    response["diff"] = diff_module.align(before.text, after.text, collapse=collapse)
    return JSONResponse(response)


@app.get("/api/raw")
def raw(
    relative: str,
    side: str = Query("redacted", pattern="^(original|redacted)$"),
) -> Response:
    """The object's bytes, so the browser can render an image side by side."""
    if not relative or relative.endswith("/"):
        return JSONResponse({"error": "relative must name a file"}, status_code=400)
    payload, _, error = browser.get(side, relative)
    if error:
        return JSONResponse({"error": error}, status_code=404)

    media_type = extract_module.extract(relative, payload).media_type
    if not media_type:
        return JSONResponse({"error": "not renderable"}, status_code=415)
    # SVG can carry script, so it is handed over as inert text rather than markup.
    if media_type == "image/svg+xml":
        media_type = "text/plain; charset=utf-8"
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"},
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
