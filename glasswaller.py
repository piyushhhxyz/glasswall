#!/usr/bin/env python3
"""Side-by-side review of a redaction run: source on the left, output on the right.

    python3 glasswaller.py                       # asks for the two locations in the browser
    python3 glasswaller.py --left A --right B    # skips the setup screen

Either side may be a folder, a .zip, or an s3:// prefix. Verdicts persist to
marks.json keyed by the pair of locations, so closing the tab and coming back
tomorrow resumes where you stopped.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import io
import json
import mimetypes
import os
import random
import collections
import concurrent.futures
import re
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter
from pathlib import Path

import pairing
import render
import stores

HERE = Path(__file__).resolve().parent
MARKS = HERE / "marks.json"
RECENT = HERE / "recent.json"

S: dict = {"ready": False}
RENDER = render.Renderer()
_LOCK = threading.Lock()


def _read_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:  # noqa: BLE001 -- a damaged sidecar must not lose a session
        return default


def _write_json(p: Path, data) -> None:
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(p)


#: Tokens too generic for "what changed" to be interesting.
_SKIP_TOKEN = re.compile(r"^(?:\d{1,2}|[A-Za-z]{1,2})$")


#: What counts as one token, everywhere. Shared so a change to the character
#: class cannot land in one tokeniser and not the other.
_SPLIT = re.compile(r"[^A-Za-z0-9@._+-]+")
PII_MIN = 3


def _tokens(text: str) -> set[str]:
    return {t for t in _SPLIT.split(text)
            if len(t) >= PII_MIN and not _SKIP_TOKEN.match(t)}


def _doc_text(side: str, sid: str, key: str, store) -> str:
    data = store.cached_read(key)
    if key.lower().endswith(".pdf") and RENDER.available:
        return RENDER.text(f"{side}:{sid}", data)
    return data.decode("utf-8", "replace")


def metrics(sid: str) -> dict:
    """What actually changed between the two sides of one pair.

    Removed and added token sets are the whole job in two numbers: a redaction
    that removed nothing did not run, and one that added nothing substituted
    nothing. Computed on demand, for the open document only — extracting text
    from both sides of a whole batch up front would cost minutes and be thrown
    away.
    """
    row = S["rows"][int(sid)]
    ls, rs = S["left_store"], S["right_store"]
    out = {"how": row["how"], "label": row["label"]}

    src = ls.cached_read(row["left"])
    out["left_bytes"] = len(src)
    if not row["right"]:
        out["missing"] = True
        return out

    dst = rs.cached_read(row["right"])
    out["right_bytes"] = len(dst)
    # Byte-identical output is reported as a fact here, not as a verdict: a
    # document with no PII in it is legitimately unchanged.
    out["identical"] = src == dst

    try:
        a = _doc_text("left", sid, row["left"], ls)
        b = _doc_text("right", sid, row["right"], rs)
    except Exception as exc:  # noqa: BLE001
        out["text_error"] = str(exc)[:200]
        return out

    ta, tb = _tokens(a), _tokens(b)
    removed, added = sorted(ta - tb), sorted(tb - ta)
    out.update(
        left_chars=len(a), right_chars=len(b),
        removed=len(removed), added=len(added),
        removed_sample=removed[:14], added_sample=added[:14],
    )
    if RENDER.available and row["left"].lower().endswith(".pdf"):
        try:
            out["left_pages"] = len(RENDER.pages(f"left:{sid}", src))
            out["right_pages"] = len(RENDER.pages(f"right:{sid}", dst))
        except Exception:  # noqa: BLE001
            pass
    return out


def _migrate(marks: dict) -> dict:
    """Bring older mark files up to the current record shape.

    Verdicts were a bare string, then ``{"v": ..., "note": ...}``. Both become
    a reviewed record with the note kept as the first comment, so nobody loses
    a session to a format change.
    """
    out = {}
    for k, v in marks.items():
        if isinstance(v, str):
            out[k] = {"viewed": True, "reviewed": True, "comments": []}
        elif isinstance(v, dict) and "v" in v:
            note = v.get("note") or ""
            out[k] = {"viewed": True, "reviewed": True,
                      "comments": [note] if note else []}
        elif isinstance(v, dict):
            out[k] = {"viewed": bool(v.get("viewed")),
                      "reviewed": bool(v.get("reviewed")),
                      "comments": list(v.get("comments") or [])}
    return out


# --- rendering a document the browser would otherwise DOWNLOAD ---------------
# A browser saves ``text/csv`` and every spreadsheet type instead of showing
# them, so an iframe pointed at one pops a download dialog and leaves the pane
# blank -- on every refresh, twice, once per side. Rendering them here also
# means they are ordinary DOM, so the two panes scroll together like PDFs do.
_MAX_ROWS = 3000
_TABLE_EXTS = {".csv", ".tsv"}
_SHEET_EXTS = {".xlsx", ".xlsm"}
_WORD_EXTS = {".docx", ".docm"}
_SLIDE_EXTS = {".pptx", ".pptm"}
_JSON_EXTS = {".json", ".geojson", ".ipynb"}
_JSONL_EXTS = {".jsonl", ".ndjson"}
_XML_EXTS = {".xml", ".rss", ".atom", ".svg.xml"}
_TEXT_EXTS = {".txt", ".md", ".html", ".htm",
              ".eml", ".log", ".yaml", ".yml", ".ini", ".cfg",
              ".sql", ".vcf", ".ics", ".env"}
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}


#: Below this a column is too narrow to read, so the table is given a
#: min-width and the pane scrolls sideways instead of crushing every column.
#: A 40-column takeout sheet at table-layout:fixed gave each one about 15px.
_MIN_COL_PX = 150


def _table_html(rows) -> str:
    import html as _html
    head = rows[0] if rows else []
    cols = max((len(r) for r in rows), default=0)
    # Only widen when it is actually needed. A three-column sheet should fill
    # the pane, not sit in a 450px strip with the rest of the pane blank.
    style = f' style="min-width:{cols * _MIN_COL_PX}px"' if cols > 6 else ""
    out = [f"<table{style}><thead><tr><th class=n></th>"]
    out += [f"<th>{_html.escape(str(c))}</th>" for c in head]
    out.append("</tr></thead><tbody>")
    for n, row in enumerate(rows[1:_MAX_ROWS], 1):
        out.append(f"<tr><td class=n>{n}</td>")
        out += [f"<td>{_html.escape(str(c))}</td>" for c in row]
        out.append("</tr>")
    out.append("</tbody></table>")
    if len(rows) - 1 > _MAX_ROWS:
        out.append(f"<p class=more>{len(rows) - 1 - _MAX_ROWS} more rows not shown</p>")
    return "".join(out)


#: Longest cell the table renderer will print in full. A Discord or Google
#: takeout row carries an entire JSON blob in one field -- 302 KB in one cell
#: in the demo corpus -- and pasting that into a <td> makes a pane no reviewer
#: can scroll. The tail is dropped for display only; nothing here is written
#: back, and the metrics panel still reads the untouched bytes.
_MAX_CELL = 4000


# --- structured text, formatted so the two panes line up --------------------
# The pipeline reserialises what it rewrites. A source line reads
# ``{"self":"...","id":"10022"`` and its own output reads
# ``{"self": "https://...", "id": "10022"`` -- same data, different spacing,
# so the panes wrapped differently and scroll sync compared unrelated lines.
# Formatting BOTH sides with one formatter is what makes them comparable; the
# highlighting is the part that makes a wall of JSON readable at all.

_JSON_MAX_CHARS = 900_000
#: Records of a .jsonl shown in full. Past this the file is a shard dump, and
#: the reviewer wants the shape, not all of it.
_JSONL_MAX_RECORDS = 400


def _jhtml(obj, indent: int = 0, out=None) -> list:
    """Pretty JSON as highlighted HTML, walked rather than regexed.

    Emitting from the parsed object means the classes cannot land on the wrong
    span: a colon inside a string value is a colon inside a string value, not
    a key separator, which is exactly where a regex highlighter gives up on
    the ``"content":"https://...?a=b:c"`` URLs all over this corpus.
    """
    import html as _html
    out = [] if out is None else out
    pad, pad2 = "  " * indent, "  " * (indent + 1)
    if isinstance(obj, dict):
        if not obj:
            out.append('<span class=jp>{}</span>')
            return out
        out.append('<span class=jp>{</span>\n')
        for n, (k, v) in enumerate(obj.items()):
            out.append(pad2)
            out.append(f'<span class=jk>"{_html.escape(str(k))}"</span>'
                       '<span class=jp>: </span>')
            _jhtml(v, indent + 1, out)
            out.append('<span class=jp>,</span>\n' if n < len(obj) - 1 else "\n")
        out.append(pad + '<span class=jp>}</span>')
    elif isinstance(obj, list):
        if not obj:
            out.append('<span class=jp>[]</span>')
            return out
        out.append('<span class=jp>[</span>\n')
        for n, v in enumerate(obj):
            out.append(pad2)
            _jhtml(v, indent + 1, out)
            out.append('<span class=jp>,</span>\n' if n < len(obj) - 1 else "\n")
        out.append(pad + '<span class=jp>]</span>')
    elif isinstance(obj, str):
        out.append(f'<span class=js>"{_html.escape(obj)}"</span>')
    elif isinstance(obj, bool) or obj is None:
        out.append(f'<span class=jb>{"null" if obj is None else str(obj).lower()}</span>')
    else:
        out.append(f'<span class=jn>{_html.escape(str(obj))}</span>')
    return out


def _json_html(data: bytes) -> str:
    import json as _json
    text = data.decode("utf8", "replace")
    if len(text) > _JSON_MAX_CHARS:
        raise ValueError("too large to format")
    return "<pre>" + "".join(_jhtml(_json.loads(text))) + "</pre>"


def _jsonl_html(data: bytes) -> str:
    """One numbered, formatted record per row.

    Numbered because a comment on a shard is always "record 12", and because
    the number is the anchor that keeps the eye on the same record in both
    panes when the rewritten side is a different length.
    """
    import html as _html
    import json as _json
    lines = data.decode("utf8", "replace").splitlines()
    rows, n = [], 0
    for raw in lines:
        if not raw.strip():
            continue
        n += 1
        if n > _JSONL_MAX_RECORDS:
            break
        try:
            body = "".join(_jhtml(_json.loads(raw)))
        except Exception:  # noqa: BLE001 -- a bad line is itself worth seeing
            body = f'<span class=jbad>{_html.escape(raw)}</span>'
        rows.append(f'<div class=rec><div class=recn>{n}</div>'
                    f'<pre class=recb>{body}</pre></div>')
    kept = sum(1 for r in lines if r.strip())
    if kept > _JSONL_MAX_RECORDS:
        rows.append(f'<p class=more>{kept - _JSONL_MAX_RECORDS} more records '
                    f'not shown</p>')
    return "".join(rows)


def _xml_html(data: bytes) -> str:
    """Indented XML. Same bargain as the JSON: both sides get one shape."""
    import html as _html
    import xml.dom.minidom as _md
    text = data.decode("utf8", "replace")
    if len(text) > _JSON_MAX_CHARS:
        raise ValueError("too large to format")
    pretty = _md.parseString(text).toprettyxml(indent="  ")
    # minidom leaves a blank line wherever the input already had whitespace.
    pretty = "\n".join(l for l in pretty.splitlines() if l.strip())
    return f"<pre>{_html.escape(pretty)}</pre>"


def _rows_from_csv(data: bytes):
    import csv, io as _io
    text = data.decode("utf8", errors="replace")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except Exception:  # noqa: BLE001
        dialect = csv.excel
    # csv defaults to a 128 KB field cap and raises past it. That exception was
    # the download bug: the table route failed, view() fell through to the raw
    # byte route, and the browser saved users.csv to disk instead of showing
    # it. Lift the cap for this parse only -- it is process-global state, so it
    # is restored even when the read raises.
    was = csv.field_size_limit()
    try:
        csv.field_size_limit(max(was, len(text) + 1))
        rows = list(csv.reader(_io.StringIO(text), dialect))
    finally:
        csv.field_size_limit(was)
    return [[c if len(c) <= _MAX_CELL else c[:_MAX_CELL] + " …" for c in r]
            for r in rows]


def _col_index(ref: str) -> int:
    """``C7`` -> 2. Sheet XML omits empty cells, so a row has to be placed by
    its column letters or every value after a gap shifts left."""
    n = 0
    for ch in ref:
        if not ch.isalpha():
            break
        n = n * 26 + (ord(ch.upper()) - 64)
    return max(0, n - 1)


_DOCX_CHROME = re.compile(r"word/(?:header|footer)\d*\.xml$")


def _text_from_docx(data: bytes) -> str:
    """Paragraph and table text of a .docx, using only the standard library.

    Same bargain as _rows_from_xlsx: a docx is a zip of XML, so the no-
    dependency rule costs nothing. Without this every Word document fell
    through to the raw byte route and the browser SAVED it instead of showing
    it -- which in a redaction review means the one format most likely to
    carry an offer letter or a contract could not be eyeballed at all.

    Paragraph splits are what matter here. A run boundary lands mid-sentence
    wherever the author changed formatting, and the rewriter frequently
    replaces a name that spans two runs, so joining runs without a separator
    is the only way the two panes stay comparable line for line.
    """
    import zipfile
    import xml.etree.ElementTree as ET

    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        have = set(z.namelist())
        body = next((n for n in ("word/document.xml", "word/document2.xml")
                     if n in have), None)
        if body is None:
            raise ValueError("no word/document.xml")
        # Headers and footers carry running contact blocks -- the offer letter
        # in the eval corpus keeps its author's email only in footer1. Reading
        # the body alone would show that address as absent from BOTH panes,
        # which reads as "clean" when it is really "not looked at".
        chrome = sorted(n for n in have
                        if _DOCX_CHROME.match(n))
        parts = [z.read(n) for n in [body, *chrome]]

    roots = []
    for raw in parts:
        try:
            roots.append(ET.fromstring(raw))
        except ET.ParseError:
            continue

    out: list[str] = []
    for para in (p for r in roots for p in r.iter(f"{W}p")):
        buf: list[str] = []
        for node in para.iter():
            tag = node.tag
            if tag == f"{W}t":
                buf.append(node.text or "")
            elif tag in (f"{W}tab",):
                buf.append("\t")
            elif tag in (f"{W}br", f"{W}cr"):
                buf.append("\n")
        line = "".join(buf)
        if line.strip() or (out and out[-1].strip()):
            out.append(line)
        if len(out) > _MAX_ROWS:
            out.append("... more paragraphs not shown")
            break
    return "\n".join(out).strip()


def _text_from_pptx(data: bytes) -> str:
    """Slide text of a .pptx, in slide order, standard library only.

    Decks reach a redaction review as customer-facing collateral -- the QBR
    with the account contacts on slide 2 -- and every one of them used to end
    at the raw byte route, which is to say at a download. Slides are numbered
    rather than sorted as strings so slide10 does not land between slide1 and
    slide2, and the number is printed because "which slide" is the first thing
    a reviewer writes in a comment.
    """
    import zipfile
    import xml.etree.ElementTree as ET

    A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [n for n in z.namelist()
                 if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)]
        if not names:
            raise ValueError("no ppt/slides")
        names.sort(key=lambda n: int(re.search(r"(\d+)", n.rsplit("/", 1)[1]).group(1)))
        parts = [(n, z.read(n)) for n in names]

    out: list[str] = []
    for name, raw in parts:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue
        n = re.search(r"(\d+)", name.rsplit("/", 1)[1]).group(1)
        out.append(f"--- slide {n} ---")
        for para in root.iter(f"{A}p"):
            line = "".join(t.text or "" for t in para.iter(f"{A}t"))
            out.append(line)
        out.append("")
        if len(out) > _MAX_ROWS:
            out.append("... more slides not shown")
            break
    return "\n".join(out).strip()


def _rows_from_xlsx(data: bytes):
    """First sheet of an xlsx, using only the standard library.

    This tool has no third-party dependencies on purpose -- it is a stdlib
    http.server and shells out to a separate interpreter for PDF rendering --
    and an xlsx is a zip of XML, so reading one needs no exception to that.
    Without this the 138 spreadsheets in a finance batch fell through to the
    raw byte route, and the browser SAVED each one instead of showing it.
    """
    import zipfile
    import xml.etree.ElementTree as ET

    NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in si.iter(f"{NS}t"))
                      for si in root.findall(f"{NS}si")]
        sheets = sorted(n for n in z.namelist()
                        if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
        if not sheets:
            return []
        rows: list[list[str]] = []
        for row in ET.fromstring(z.read(sheets[0])).iter(f"{NS}row"):
            cells: list[str] = []
            for c in row.findall(f"{NS}c"):
                at = _col_index(c.get("r", ""))
                while len(cells) < at:
                    cells.append("")
                v = c.find(f"{NS}v")
                if c.get("t") == "s" and v is not None and v.text is not None:
                    cells.append(shared[int(v.text)] if int(v.text) < len(shared) else "")
                elif c.get("t") == "inlineStr":
                    cells.append("".join(t.text or "" for t in c.iter(f"{NS}t")))
                else:
                    cells.append(v.text if v is not None and v.text else "")
            rows.append(cells)
            if len(rows) > _MAX_ROWS:
                break
        width = max((len(r) for r in rows), default=0)
        for r in rows:
            r.extend([""] * (width - len(r)))
        return rows


def _looks_textual(data: bytes) -> str | None:
    """The decoded text if these bytes are readable, else None.

    The extension lists will always trail the corpus -- every batch turns up
    some ``.ndjson`` or ``.properties`` nobody listed. Sniffing catches those
    without a new release, which matters because the alternative was not "a
    plainer view", it was a save dialog.
    """
    head = data[:8192]
    if b"\x00" in head:
        return None
    try:
        text = data.decode("utf8")
    except UnicodeDecodeError:
        return None
    # Control characters other than tab/newline/return mean binary that merely
    # happens to decode.
    if sum(c < 32 and c not in (9, 10, 13) for c in head) > len(head) // 100:
        return None
    return text


def view(key: str, data: bytes) -> dict:
    """How this document should be shown, and the payload to show it with.

    Never returns a shape the browser would download. Every branch ends at
    something the page draws itself, at the PDF plugin, or at an explicit
    "cannot show this" card -- because an iframe pointed at a document Chrome
    will not render does not fail visibly, it silently saves the file and
    leaves the pane blank.
    """
    import html as _html
    ext = Path(key).suffix.lower()
    if ext == ".pdf":
        return {"kind": "pdf"}
    try:
        if ext in _TABLE_EXTS:
            return {"kind": "table", "html": _table_html(_rows_from_csv(data))}
        if ext in _SHEET_EXTS:
            return {"kind": "table", "html": _table_html(_rows_from_xlsx(data))}
        if ext in _WORD_EXTS:
            return {"kind": "text",
                    "html": f"<pre>{_html.escape(_text_from_docx(data))}</pre>"}
        if ext in _SLIDE_EXTS:
            return {"kind": "text",
                    "html": f"<pre>{_html.escape(_text_from_pptx(data))}</pre>"}
        # Formatting is best-effort on purpose. A file that does not parse is
        # still a file the reviewer has to look at -- and "the rewriter emitted
        # broken JSON" is itself the finding -- so a failure here drops to the
        # raw text below rather than to a card saying it could not be shown.
        if ext in _JSONL_EXTS:
            try:
                return {"kind": "records", "html": _jsonl_html(data)}
            except Exception:  # noqa: BLE001
                pass
        if ext in _JSON_EXTS:
            try:
                return {"kind": "text", "html": _json_html(data)}
            except Exception:  # noqa: BLE001
                pass
        if ext in _XML_EXTS:
            try:
                return {"kind": "text", "html": _xml_html(data)}
            except Exception:  # noqa: BLE001
                pass
        if ext in _JSON_EXTS | _JSONL_EXTS | _XML_EXTS:
            return {"kind": "text",
                    "html": f"<pre>{_html.escape(data.decode('utf8', 'replace'))}</pre>"}
        if ext in _TEXT_EXTS:
            return {"kind": "text",
                    "html": f"<pre>{_html.escape(data.decode('utf8', 'replace'))}</pre>"}
        if ext in _IMAGE_EXTS:
            return {"kind": "image"}
        sniffed = _looks_textual(data)
        if sniffed is not None:
            return {"kind": "text", "html": f"<pre>{_html.escape(sniffed)}</pre>"}
    except Exception as exc:  # noqa: BLE001 -- shown on the card, not swallowed
        return {"kind": "other", "ext": ext,
                "why": f"{type(exc).__name__}: {exc}"[:200]}
    return {"kind": "other", "ext": ext,
            "why": _CANNOT.get(ext, "no viewer for this file type")}


#: Formats with no standard-library reader. Saying so on the card beats the
#: old behaviour, which was to hand the bytes to the browser and hope.
_CANNOT = {
    ".doc": "legacy binary Word — re-export as .docx to review it here",
    ".xls": "legacy binary Excel — re-export as .xlsx to review it here",
    ".ppt": "legacy binary PowerPoint — re-export as .pptx to review it here",
}


# --- the mapping table the pipeline built ------------------------------------
# Reviewing the output tells you a name was replaced. It does not tell you
# WHAT it was replaced with everywhere else, or whether one person got two
# fake identities, or whether a company name was mapped to something that
# reads like a real company. That is all in pii_mappings.db, and until now the
# only way to look was to download it and open a sqlite shell.

MAP_NAMES = ("pii_mappings.db", "mappings.db")


def find_mappings(store) -> str | None:
    """The run's mapping database inside an output location, if it shipped one.

    Often it did not -- the file is written beside the run and not always
    uploaded -- so this returns None rather than raising, and ``--mappings``
    exists for pointing at one by hand.
    """
    try:
        for path in store.paths:
            if Path(path).name in MAP_NAMES:
                return path
    except Exception:  # noqa: BLE001
        pass
    return None


def read_mappings(spec: str, profile: str | None = None, store=None,
                  inner: str | None = None) -> dict:
    """Rows of the mappings table, plus what the run replaced things with.

    sqlite needs a real file and cannot read from a bucket, so an S3 database
    is fetched once to a temp file and kept for the life of the process. These
    are a few megabytes at most -- the mappings for a whole export are tens of
    thousands of short strings.
    """
    import sqlite3
    import tempfile

    key = f"{spec}::{inner}"
    hit = _MAP_CACHE.get(key)
    if hit is None:
        if store is not None and inner is not None:
            data = store.read(inner)
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.write(data)
            tmp.close()
            hit = tmp.name
        elif stores.parse_s3(spec):
            # A database named directly by URI. Split off the filename and
            # read that one key -- no listing, so pointing at a database in a
            # bucket costs one request.
            base, _, name = stores.parse_s3(spec)[0].rstrip("/").rpartition("/")
            data = stores.S3Store(base, profile=profile).read(name)
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.write(data)
            tmp.close()
            hit = tmp.name
        else:
            local = Path(spec).expanduser()
            if not local.exists():
                raise FileNotFoundError(f"no mapping database at {spec}")
            hit = str(local)
        _MAP_CACHE[key] = hit

    con = sqlite3.connect(f"file:{hit}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    cols = {r[1] for r in con.execute("pragma table_info(mappings)")}
    if not cols:
        raise ValueError("no mappings table in this database")
    want = [c for c in ("original", "attribute_type", "replacement", "source",
                        "confidence", "generated_by", "deleted") if c in cols]
    rows = [dict(r) for r in con.execute(
        f"select {', '.join(want)} from mappings order by attribute_type, original")]
    con.close()
    return {"rows": rows, "count": len(rows), "path": spec}


_MAP_CACHE: dict[str, str] = {}

#: Comments left on a mapping. Separate from marks.json on purpose: that file
#: is verdicts on DOCUMENTS, and a note about a substitution belongs to the
#: run's mapping table, which several document reviews share.
NOTES = HERE / "map_notes.json"

#: Mappings on screen at once. Enough that scrolling is the normal way to move
#: through a type and the pager is for jumping, not for reading.
PAGE_ROWS = 200


_PII_IDX: dict[str, dict] = {}


def _vocab_split(s: str) -> list[str]:
    """Lowercased tokens, by the same rule on a mapping and on a document.

    Deliberately not ``_tokens``: that one drops anything three characters or
    shorter, and a first name is the anchor a whole mapping is found by.
    """
    return [t for t in _SPLIT.split(s.lower()) if t]


def pii_index(src, profile=None, store=None, inner=None) -> dict:
    """Every mapping the run made, indexed by the first token of its value.

    The panes are highlighted by shipping the client a list of values to look
    for, and a real run has far too many to ship all of them -- the 95-user MSL
    run has 392,811 mappings, and a regex of 392k alternatives is neither
    sendable nor runnable in a browser.

    Capping that list is what broke highlighting outright: the cap kept the
    LONGEST values, and the longest values in a mail export are all tracking
    URLs, so the 6,000 that were sent were 6,000 links and every name, email
    and phone number fell off the end. 260k of the 392k rows are 3-20
    characters long -- the entire readable vocabulary was the part discarded,
    which is why a pane full of substituted names showed no marks at all.

    So the cap is gone and the vocabulary is scoped to the document instead:
    index every value by its first token once, then intersect that index with
    the tokens of the document actually on screen. What reaches the client is
    a few hundred strings that are genuinely in front of the reviewer.
    """
    key = f"{src}::{inner}"
    hit = _PII_IDX.get(key)
    if hit is not None:
        return hit
    out = read_mappings(src, profile, store, inner)
    orig: dict[str, list[str]] = {}
    repl: dict[str, list[str]] = {}
    leak: dict[str, list[str]] = {}
    for row in out["rows"]:
        if row.get("deleted"):
            continue
        a = (row.get("original") or "").strip()
        b = (row.get("replacement") or "").strip()
        # Two characters matches half the corpus.
        if len(a) < 3:
            continue
        ta = _vocab_split(a)
        if not ta:
            continue
        if b:
            orig.setdefault(ta[0], []).append(a)
            tb = _vocab_split(b)
            if len(b) >= 3 and tb:
                repl.setdefault(tb[0], []).append(b)
        else:
            # Detected and left alone: the value is still in the deliverable
            # verbatim, so it is marked on both panes and in red.
            leak.setdefault(ta[0], []).append(a)
    hit = {"orig": orig, "repl": repl, "leak": leak, "count": out["count"]}
    _PII_IDX[key] = hit
    while len(_PII_IDX) > PII_IDX_KEEP:
        _PII_IDX.pop(next(iter(_PII_IDX)))
    return hit


#: How many runs' indexes to keep. A 95-user run's mapping databases are ~99 MB
#: on disk between them, and an index of every user at once is not something a
#: laptop should be asked to hold. Reviewing walks through one user at a time,
#: so the last few are the only ones that get asked for again.
PII_IDX_KEEP = 4

_MAP_PICK: dict[tuple, str | None] = {}

#: Where one user's mapping database sits under a run-wide location. Both
#: layouts this run produced: flat, one file per user, and a folder per user
#: with the pipeline's own filename inside it.
MAP_PER_USER = ("{base}/{user}.db", "{base}/{user}/pii_mappings.db",
                "{base}/{user}/mappings.db")


def resolve_map(spec: str, profile: str | None, user: str | None) -> str | None:
    """The mapping database for one user's documents.

    A multi-user run does not have one mapping table, it has one PER USER --
    every user is processed on its own cluster with its own mapping database,
    and two users' tables are not interchangeable. Pointing the reviewer at a
    single database silently gives no marks on every user that database does
    not cover, which reads exactly like highlighting being broken. So a
    ``--mappings`` that names a FOLDER (or an S3 prefix) is resolved per
    document instead, and one that names a .db is used as given.
    """
    if not spec:
        return None
    if spec.lower().endswith((".db", ".sqlite", ".sqlite3")):
        return spec
    if not user:
        return None
    key = (spec, user)
    if key in _MAP_PICK:
        return _MAP_PICK[key]
    base = spec.rstrip("/")
    pick = None
    for tmpl in MAP_PER_USER:
        cand = tmpl.format(base=base, user=user)
        if stores.parse_s3(cand):
            # No HEAD on the store, so the read IS the test -- and it is
            # cached, so a hit costs one request rather than two.
            try:
                read_mappings(cand, profile)
            except Exception:  # noqa: BLE001 -- absence is the expected answer
                continue
            pick = cand
            break
        if Path(cand).expanduser().exists():
            pick = cand
            break
    _MAP_PICK[key] = pick
    return pick


#: Values sent to the client for one document. Scoped per document this is
#: never reached in practice; it is here so that one pathological file cannot
#: hand the browser a regex it will not finish.
PII_MAX = 4000


def pii_for(idx: dict, name: str, text: str) -> list[str]:
    """The indexed values that really occur in ``text``.

    Two passes, because 392k substring tests against a document is far too
    slow to run on every keypress: the token set prunes the candidates down to
    the handful that could possibly match, and only those are checked in full.
    Case-insensitively -- the rewriter preserves the source cell's casing, so a
    mapping stored as "Optory Labs" is written out as "OPTORY LABS".
    """
    if not text:
        return []
    book = idx.get(name) or {}
    low = text.lower()
    seen: set[str] = set()
    for t in set(_vocab_split(text)):
        for v in book.get(t, ()):
            if v not in seen and v.lower() in low:
                seen.add(v)
    return _rank(seen)


#: How many pairs to learn from before the reviewer arrives. Enough that the
#: first document has signal, small enough to finish while it renders.
DERIVE_WARM = 60

#: A token is one of this run's values when the run rewrites it more often
#: than it leaves it alone. Prose the generator touched once sits far below.
DERIVE_RATE = 0.25

#: ...and one observation is not evidence. An over-scrubbing run rewrites an
#: ordinary word somewhere, which alone scores a perfect ratio; requiring a
#: second occurrence is what separates a value from an accident.
DERIVE_MIN = 2

#: Learned per user, because a multi-user run rewrites each user on its own
#: cluster -- see resolve_map. One shared vocabulary would make user A's
#: originals user B's leak marks.
_DERIVE: dict[str, dict] = {}
_DERIVE_LOCK = threading.Lock()


def _bucket(user: str) -> dict:
    with _DERIVE_LOCK:
        return _DERIVE.setdefault(user, {"rewrote": collections.Counter(),
                                         "kept": collections.Counter(),
                                         "seen": set(), "warm": False})


def reset_derived() -> None:
    """A new review is a new run; nothing carries over."""
    with _DERIVE_LOCK:
        _DERIVE.clear()


def _rank(values) -> list:
    """Longest first, so a surname is not eaten by a match on the first name,
    and never more than the client regex can hold."""
    return sorted({v for v in values if len(v) >= PII_MIN}, key=len, reverse=True)[:PII_MAX]


def _learn(user: str, sid: str, left: set, right: set) -> None:
    """Fold one pair's evidence into what this run does with each token.

    No pattern list and no dictionary. A token gone from the right pane was
    rewritten here; a token in both was left alone here. Across pairs the
    ratio separates a value the run redacts from a word it happened to touch
    once -- in any script, with nothing to install.
    """
    st = _bucket(user)
    with _DERIVE_LOCK:
        if sid in st["seen"]:
            return
        st["seen"].add(sid)
        st["rewrote"].update(t for t in left - right if len(t) >= PII_MIN)
        st["kept"].update(t for t in left & right if len(t) >= PII_MIN)


def warm_derived(user: str) -> None:
    """Learn from a bounded sample in the background, once per user.

    A leak is 'this run rewrites that token elsewhere', so the evidence has to
    come from more than the document on screen. Reads go straight to the store
    rather than through its 16-entry cache, which the reviewer's own panes
    depend on.
    """
    st = _bucket(user)
    with _DERIVE_LOCK:
        if st["warm"]:
            return
        st["warm"] = True

    def one(job):
        i, row = job
        sid = str(i)
        try:
            lt = S["left_store"].read(row["left"]).decode("utf-8", "replace")
            rt = S["right_store"].read(row["right"]).decode("utf-8", "replace")
        except Exception:              # noqa: BLE001 - a warm-up miss is not fatal
            return
        _learn(user, sid, set(_vocab_split(lt)), set(_vocab_split(rt)))

    def run():
        rows = [(i, r) for i, r in enumerate(S["rows"])
                if r.get("left") and r.get("right")
                and (r.get("label") or "").split("/")[0] == user][:DERIVE_WARM]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(one, rows))

    threading.Thread(target=run, daemon=True).start()


def derive_pii(user: str, sid: str, lt: str, rt: str) -> dict:
    """Highlights with no mapping database, from the run's own behaviour.

      left-only    a value the run rewrote in this document
      right-only   the surrogate it wrote in
      both panes, and rewritten often elsewhere -> a leak

    The third is the one worth having: it catches inconsistent redaction, an
    org name substituted in one file and left verbatim in the next, which no
    pattern can see because the value reads as ordinary text.

    Weaker than a mapping table and honest about it: marks are tokens rather
    than whole values, and a token the run never rewrote anywhere is invisible
    to it.
    """
    left = set(_vocab_split(lt or ""))
    right = set(_vocab_split(rt or ""))
    pair = bool(lt and rt)
    if pair:
        _learn(user, sid, left, right)
    here = (left & right) if pair else (left or right)
    st = _bucket(user)
    with _DERIVE_LOCK:
        rewrote, kept = st["rewrote"], st["kept"]
        leak = [t for t in here
                if rewrote[t] >= DERIVE_MIN
                and rewrote[t] >= DERIVE_RATE * (rewrote[t] + kept[t])]
        learned = len(rewrote)
    return {"orig": _rank(left - right) if pair else [],
            "repl": _rank(right - left) if pair else [],
            "leak": _rank(leak), "derived": True, "learned": learned}


def map_key(row: dict) -> str:
    """Stable id for one mapping, independent of its rowid.

    Not the primary key: a re-run renumbers those, and a comment that came
    loose from its mapping is worse than no comment.
    """
    # Hashed rather than "type\x00original": the raw pair carries a NUL and
    # whatever punctuation the original had, which survives JSON but makes
    # every log line, URL and shell test a small argument about quoting.
    raw = f"{row.get('attribute_type') or '?'}\x00{row.get('original')}"
    return hashlib.sha1(raw.encode("utf8", "replace")).hexdigest()[:16]


def browse_mappings(rows, kind: str | None = None, look: str = "",
                    offset: int = 0, limit: int = PAGE_ROWS) -> dict:
    """One page of the mappings table, exactly as the run wrote it.

    No sampling. An earlier version showed a seeded handful per type, which is
    right for documents -- nobody reads 34,000 of them -- and wrong here: this
    is the run's substitution table and the reviewer is checking it, so a row
    that exists has to be reachable. Types come back with their real counts so
    the sidebar can show what the run actually did, and the rows themselves
    are paged in the order the database holds them.
    """
    look = (look or "").strip().lower()

    def hit(r):
        if not look:
            return True
        return look in " ".join(str(r.get(f) or "") for f in
                                ("original", "replacement", "attribute_type")).lower()

    matched = [r for r in rows if hit(r)]
    tally = Counter(str(r.get("attribute_type") or "?") for r in matched)
    sel = [r for r in matched
           if not kind or str(r.get("attribute_type") or "?") == kind]
    offset = max(0, min(offset, max(0, len(sel) - 1)))
    return {"types": [{"type": k, "total": tally[k]} for k in sorted(tally)],
            "rows": sel[offset:offset + limit], "total": len(sel),
            "matched": len(matched), "offset": offset, "limit": limit,
            "type": kind or ""}


def session_id(left: str, right: str) -> str:
    """Stable id for a (left, right) pair, so verdicts survive a re-open."""
    h = hashlib.sha256(f"{left}\x00{right}".encode()).hexdigest()[:12]
    return f"{Path(right.rstrip('/')).name or right}-{h}"


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Review</title><style>
.doc{background:#fff;padding:10px 12px}
/* A wide sheet scrolls sideways rather than squeezing 40 columns into the
   pane. Both panes do it independently -- the sync mirrors vertical position,
   which is the axis a reviewer moves down. */
.doc.table{overflow-x:auto}
/* Fixed layout, not auto. One takeout row carries a multi-kilobyte JSON blob,
   and auto layout hands that column the whole pane -- every other heading
   collapses to one letter per line and the two sides stop lining up. Fixed
   gives each column an equal share and lets the long one wrap. */
.doc table{border-collapse:collapse;font-size:12.5px;width:100%;table-layout:fixed}
/* break-word, not anywhere. "anywhere" split "Galih Eka Putra" across two
   lines as "G / alih Eka Putra" -- and a person's name is the single thing a
   reviewer is scanning these cells for. break-word keeps words whole and
   still breaks the base64 blobs that have no break opportunity at all. */
.doc th,.doc td{border:1px solid #e3e6ea;padding:3px 6px;text-align:left;
  vertical-align:top;white-space:pre-wrap;word-break:normal;overflow-wrap:break-word}
.doc thead th{position:sticky;top:0;background:#f5f6f8;font-weight:600;z-index:1;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.doc th.n,.doc td.n{color:#999;text-align:right;font-variant-numeric:tabular-nums;
  background:#fafbfc;width:42px;white-space:nowrap}
.doc pre{margin:0;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
  white-space:pre-wrap;word-break:normal;overflow-wrap:break-word}
.doc .more{color:#888;font-size:12px;padding:6px 2px}

/* Formatted JSON. Keys carry the colour because a reviewer scanning for a
   leak is scanning field names first -- emailAddress, displayName, phone --
   and only then reading the value beside it. */
.doc .jk{color:#1a4f8a}
.doc .js{color:#0b6b5e}
.doc .jn{color:#a15c00}
.doc .jb{color:#7a3ea1}
.doc .jp{color:#9aa0a6}
.doc .jbad{color:var(--bad)}

/* One record of a .jsonl. The number is a gutter, not content: it stays put
   while the record beside it wraps, so the same record sits at the same mark
   in both panes even when the rewritten side is a different length. */
.doc.records{padding:0}
.rec{display:flex;gap:0;border-bottom:1px solid #eef0f2;align-items:stretch}
.rec:last-child{border-bottom:0}
.recn{flex:0 0 44px;padding:8px 8px 8px 0;text-align:right;color:#b0b5ba;
  background:#fafbfc;border-right:1px solid #eef0f2;font:11.5px/1.5 ui-monospace,
  SFMono-Regular,Menlo,monospace;font-variant-numeric:tabular-nums;
  position:sticky;left:0}
.recb{flex:1;min-width:0;padding:8px 10px}
.opt{color:var(--mut);font-weight:400;font-size:11px}
.loc{font-weight:600;font-size:13px;padding:2px 8px;border-radius:5px;background:#eef1f5;
     color:#333;white-space:nowrap;max-width:22ch;overflow:hidden;text-overflow:ellipsis}
:root{--fg:#1a1d21;--mut:#6b7076;--line:#e4e7ea;--soft:#f7f8f9;--ok:#0b6b5e;--warn:#a15c00;--bad:#b3261e;--sel:#eef4f3}
html{color-scheme:light}*{box-sizing:border-box}
body{margin:0;height:100vh;display:flex;flex-direction:column;background:#fff;color:var(--fg);
 font:14px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,sans-serif}
button{font:inherit}

/* popup */
#veil{position:fixed;inset:0;background:rgba(26,29,33,.34);display:none;place-items:center;z-index:60;padding:20px}
#veil.on{display:grid}
.pop{width:100%;max-width:430px;background:#fff;border-radius:13px;padding:20px 22px 18px;box-shadow:0 18px 50px rgba(0,0,0,.24)}
.pop h1{font-size:16.5px;margin:0 0 3px}.pop p.sub{color:var(--mut);font-size:12.5px;margin:0 0 15px}
.pop label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:600;margin:0 0 5px}
.pop input[type=text],.pop select{width:100%;font:12.5px ui-monospace,Menlo,monospace;padding:8px 10px;
 border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--fg)}
.pop input:focus,.pop select:focus{outline:2px solid #cfe3df;border-color:#9ccec5}
.grow{display:flex;gap:7px}.grow input{flex:1;min-width:0}
.mini{padding:8px 11px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--fg);cursor:pointer;font-size:12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:9px}.row{margin:0 0 13px}
.note{font-size:12px;color:var(--mut);margin:8px 0 0}.note.err{color:var(--bad)}.note.warn{color:var(--warn)}
.recent{font:11.5px ui-monospace,Menlo,monospace;color:var(--mut);cursor:pointer;padding:3px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recent:hover{color:var(--fg);text-decoration:underline}
.acts{display:flex;gap:8px;align-items:center;margin:16px 0 0}
.go{font-weight:600;padding:8px 18px;border-radius:7px;border:1px solid var(--fg);background:var(--fg);color:#fff;cursor:pointer}
.link{margin-left:auto;font-size:12px;color:var(--mut);cursor:pointer}

/* app */
#app{flex:1;display:none;flex-direction:column;min-height:0}
#banner{display:none;background:#fff5e6;border-bottom:1px solid #e8c893;color:var(--warn);padding:9px 14px;font-size:13px;align-items:center;gap:12px}
#banner.on{display:flex}
#banner button{font-weight:600;font-size:12px;padding:5px 12px;border-radius:6px;border:1px solid var(--warn);background:var(--warn);color:#fff;cursor:pointer}
#banner .x{margin-left:auto;cursor:pointer;opacity:.6;font-size:16px}

header{border-bottom:1px solid var(--line);padding:7px 12px;display:flex;gap:10px;align-items:center;flex:0 0 auto}
/* Hidden rather than disabled when the run shipped no mapping database. A
   button that does nothing is worse than no button: it reads as broken.
   Always present, dimmed when the run shipped no database -- hiding it left a
   reviewer with no button, no explanation and no way in, which is what the QA
   pass reported as "cannot open mappings". */
#mapbtn{font:600 11px/1 ui-sans-serif,-apple-system,sans-serif;
  letter-spacing:.02em;text-transform:uppercase;padding:5px 9px}
.icobtn{border:1px solid var(--line);background:#fff;border-radius:6px;cursor:pointer;padding:4px 7px;color:var(--mut);line-height:1;display:flex;align-items:center}
.icobtn:hover{color:var(--fg);border-color:var(--mut)}
.pos{font-variant-numeric:tabular-nums;font-weight:600;white-space:nowrap;font-size:13px}
.name.peek{color:var(--ok,#2f855a)}
.name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:12.5px ui-monospace,Menlo,monospace}
.tag{font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:2px 6px;border-radius:4px;
 background:var(--soft);border:1px solid var(--line);color:var(--mut);white-space:nowrap}
.tag.size,.tag.sole,.tag.name{background:#fff5e6;border-color:#e8c893;color:var(--warn)}
.tag.missing{background:#fdecea;border-color:#eab6b1;color:var(--bad)}
#rev{display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:7px;border:1px solid var(--line);
 background:#fff;color:var(--mut);cursor:pointer;font-size:12.5px;font-weight:600;white-space:nowrap}
#rev:hover{border-color:var(--mut);color:var(--fg)}
#rev.on{background:var(--sel);border-color:#9ccec5;color:var(--ok)}
#cbox{font:12.5px inherit;border:1px solid var(--line);border-radius:7px;padding:5px 10px;width:190px;background:#fff;color:var(--fg)}
#cbox:focus{outline:2px solid #cfe3df;border-color:#9ccec5}
.count{font-size:12px;color:var(--mut);white-space:nowrap;font-variant-numeric:tabular-nums}
#split{font:11px ui-monospace,Menlo,monospace;color:var(--mut);cursor:pointer;border:1px solid var(--line);
 border-radius:5px;padding:3px 8px;white-space:nowrap}
#split:hover{color:var(--fg);border-color:var(--mut)}

#cbar{display:none;gap:7px;flex-wrap:wrap;padding:7px 12px;border-bottom:1px solid var(--line);background:var(--soft)}
#cbar.on{display:flex}
.chip{display:flex;align-items:center;gap:7px;background:#fff;border:1px solid var(--line);border-radius:14px;
 padding:3px 6px 3px 11px;font-size:12.5px;max-width:100%}
.chip span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip b{cursor:pointer;color:var(--mut);font-weight:400;padding:0 4px;border-radius:50%}
.chip b:hover{color:var(--bad);background:#fdecea}

/* The list width is a variable so it can be dragged: file names here are full
   relative paths and 250px truncated almost all of them. Persisted, because
   re-dragging it on every run is the kind of small tax nobody reports. */
#body{flex:1;display:grid;grid-template-columns:var(--sw,250px) 1fr;min-height:0}
#body.narrow{grid-template-columns:1fr}
#body.narrow #side{display:none}
#body.info{grid-template-columns:var(--sw,250px) 1fr 268px}
#body.narrow.info{grid-template-columns:1fr 268px}
/* right:0 matters. With neither left nor right the box falls back to its
   STATIC position -- the top-left of the sidebar -- so the handle was
   invisible and unreachable at the wrong edge. */
#grip{position:absolute;top:0;bottom:0;right:-4px;width:9px;cursor:col-resize;z-index:6}
#grip:hover::after,#grip.on::after{content:"";position:absolute;left:3px;top:0;bottom:0;
  width:2px;background:var(--ok,#2f855a);opacity:.55}
body.rz{cursor:col-resize;user-select:none}
/* The mapping table, over the panes. A modal because verifying a substitution
   is a detour from reviewing documents, not a thing you do beside it. */
#mveil{position:fixed;inset:0;background:rgba(26,29,33,.34);display:none;z-index:70;padding:34px}
#mveil.on{display:grid;place-items:center}
#mbox,#fbox{background:#fff;border-radius:10px;width:min(980px,96vw);max-height:86vh;
  display:flex;flex-direction:column;box-shadow:0 12px 40px rgba(0,0,0,.22)}
.mhead{display:flex;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--line)}
.mhead input{flex:1;font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
  padding:5px 8px;border:1px solid var(--line);border-radius:6px}
/* A database browser, because that is what this is: the run's substitution
   table, every attribute type down the side and the real rows in the middle.
   Grouping it into sampled sections showed the shape of the run and hid the
   row you were actually looking for. */
.mmain{flex:1;display:grid;grid-template-columns:206px 1fr;min-height:0}
#mtypes{overflow:auto;border-right:1px solid var(--line);background:#fcfcfd;
  padding:6px 0 14px}
#mwrap{display:flex;flex-direction:column;min-width:0;min-height:0}
.mtype{display:flex;gap:8px;align-items:baseline;padding:5px 12px;cursor:pointer;
  font-size:12px;border-left:2px solid transparent}
.mtype:hover{background:var(--soft)}
.mtype[aria-current=true]{background:var(--soft);border-left-color:var(--fg);font-weight:600}
.mtype .n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
.mtype .c{color:var(--mut);font-variant-numeric:tabular-nums;font-size:11px}
#mpage{flex:0 0 auto;border-top:1px solid var(--line);padding:7px 14px;
  display:flex;gap:10px;align-items:center;font-size:12px;color:var(--mut)}
#mpage button{margin:0}
#mbody th{position:sticky;top:0;background:#fff;text-align:left;z-index:2;
  padding:7px 6px;border-bottom:1px solid var(--line);font-size:10px;
  text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600}
#mbody,#fbody{overflow:auto;padding:0 14px 14px}
#mbody table,#fbody table{border-collapse:collapse;width:100%;font-size:12.5px;table-layout:fixed}
#mbody td,#fbody td{padding:4px 6px;border-bottom:1px solid #f0f2f4;vertical-align:top;
  word-break:normal;overflow-wrap:break-word;
  font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
#mbody td.o{color:var(--bad);width:36%}
#mbody td.r{color:var(--ok);width:36%}
#mbody td.t{color:var(--mut);font-size:11.5px}
#mbody td.cmt{width:84px;text-align:right;white-space:nowrap}
/* One section per attribute type, its heading sticky, so scrolling through
   twelve thousand emails never loses which type you are in. */
.mgrp{margin:0 0 18px}
.mgrp h4{position:sticky;top:0;background:#fff;margin:0;padding:9px 0 5px;
  font-size:12px;text-transform:uppercase;letter-spacing:.04em;z-index:2;
  border-bottom:1px solid var(--line);display:flex;justify-content:space-between}
.mgrp h4 .opt{text-transform:none;letter-spacing:0}
.lnk{border:0;background:none;color:var(--mut);cursor:pointer;font:inherit;
  padding:2px 4px;border-radius:4px}
.lnk:hover{color:var(--fg);background:var(--soft)}
.mmore{margin:6px 0 0;font-size:12px;text-decoration:underline}
.askmap{display:flex;gap:8px;margin:10px 0}
.askmap input{flex:1;font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;
  padding:6px 8px;border:1px solid var(--line);border-radius:6px}
.more.bad{color:var(--bad)}
.icobtn.off{opacity:.5}
.mnotes{margin-top:3px;display:flex;flex-wrap:wrap;gap:4px}
.mnote{background:#fff8e6;border:1px solid #f0e2bd;color:#6b5a2a;border-radius:4px;
  padding:1px 6px;font:11.5px/1.5 ui-sans-serif,-apple-system,sans-serif}
#info .paths{font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
  margin:0 0 7px;word-break:break-all}
#info .paths b{color:var(--mut);font-weight:400;margin-right:6px}
/* The folder audit. Same modal, different question: not "what did this value
   become" but "what did this FOLDER become", which is the half of the
   deliverable that never appears in either pane. */
#fbody th{position:sticky;top:0;background:#fff;text-align:left;z-index:2;
  padding:7px 6px;border-bottom:1px solid var(--line);font-size:10px;
  text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600}
#fbody td.fn{width:30%}
#fbody td.fo{color:var(--ok);width:30%}
#fbody td.fk{color:var(--mut);width:30%}
#fbody td.fp{color:var(--mut);font-size:11.5px}
#fbody tr.risk td.fn,#fbody tr.risk td.fk{color:var(--bad)}
.why{display:block;color:#8a6d1f;font:11.5px/1.5 ui-sans-serif,-apple-system,sans-serif}
#info{display:none;border-left:1px solid var(--line);background:#fcfcfd;overflow:auto;min-height:0;padding:12px 13px 26px}
#body.info #info{display:block}
#info h3{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);
 margin:16px 0 7px;font-weight:600}
#info h3:first-child{margin-top:0}
#info dl{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;margin:0;font-size:12px}
#info dt{color:var(--mut)}
#info dd{margin:0;text-align:right;font-variant-numeric:tabular-nums}
#info .vals{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
#info .v{font:10.5px ui-monospace,Menlo,monospace;background:#fff;border:1px solid var(--line);
 border-radius:4px;padding:2px 5px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#info .v.rm{border-color:#cfe0dc;color:var(--ok)}
#info .v.ad{border-color:#e8d5b8;color:var(--warn)}
#info .warnrow{color:var(--warn)} #info .badrow{color:var(--bad)}
#side{position:relative;border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;background:#fcfcfd}
.tw{flex:0 0 auto;display:inline-block;width:10px;color:var(--mut);
  transition:transform .12s ease;font-size:9px;line-height:1}
.fold.open .tw{transform:rotate(90deg)}
.crumb{padding:7px 10px 6px;border-bottom:1px solid var(--line);font-size:11.5px;
  color:var(--mut);display:flex;flex-wrap:wrap;align-items:center;gap:3px;background:#fafbfc}
.cseg{cursor:pointer;padding:1px 4px;border-radius:4px;max-width:100%;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.cseg:hover{background:#eceff2;color:var(--fg)}
.csep{opacity:.45}
.fold.up .n{font:12.5px ui-monospace,Menlo,monospace}
.none{padding:16px 12px;font-size:12px;color:var(--mut)}
#side .top{padding:8px 9px;border-bottom:1px solid var(--line);display:flex;gap:6px;align-items:center}
#side input{flex:1;min-width:0;font-size:12.5px;padding:5px 9px;border:1px solid var(--line);border-radius:6px;background:#fff;color:var(--fg)}
#list{flex:1;overflow:auto;padding:3px 0 24px}
.fold{padding:6px 9px;cursor:pointer;display:flex;gap:7px;align-items:center;border-left:2px solid transparent}
.fold:hover{background:var(--soft)}
.fold[aria-current=true]{background:var(--sel);border-left-color:var(--ok)}
.fold .ic{flex:0 0 auto;display:flex;color:var(--mut)}
.fold .tx{min-width:0;flex:1}
.fold .n{font:11.5px ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fold .m{font-size:10.5px;color:var(--mut);margin-top:1px}
.fold .m .w{color:var(--warn)}
.file{padding:4px 9px 4px 26px;font:11px ui-monospace,Menlo,monospace;cursor:pointer;display:flex;gap:6px;align-items:center;color:var(--mut)}
.file:hover{background:var(--soft);color:var(--fg)}
.file[aria-current=true]{background:var(--sel);color:var(--fg);font-weight:600}
.file .ic{flex:0 0 auto;display:flex;opacity:.55}
.file .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.dot{flex:0 0 auto;width:6px;height:6px;border-radius:50%;background:var(--line)}
.dot.viewed{background:#c9ced3}.dot.reviewed{background:var(--ok)}.dot.missing{background:#e8c893}
/* A hit from outside the sample. It reviews and marks like any other row --
   the only thing worth saying is that it is not part of the hundred this
   machine was dealt, so finding it again means searching for it again. */
.file.extra .t{color:#7a5cc4}
#snote{display:none;padding:5px 10px 7px;font-size:11px;color:var(--mut);
 border-bottom:1px solid var(--line);line-height:1.45}
#snote.on{display:block}

main{flex:1;display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);min-height:0}
/* One-pane mode: reviewing a TRANSFORMED tree on its own, where there is no
   source half to compare against. The right section leaves the grid entirely
   rather than collapsing, so the left pane gets the full width. */
main.solo{grid-template-columns:1fr}
main.solo>section:nth-child(2){display:none}
section{background:#fff;display:flex;flex-direction:column;min-width:0;min-height:0}
h2{margin:0;padding:5px 12px;font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--mut);
 background:var(--soft);border-bottom:1px solid var(--line);font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
h2.r{color:var(--ok)}
/* The heading carries the folder the document is sitting in, because a folder
   name is itself part of what the pipeline had to redact and it appears
   nowhere else on the screen. */
h2{display:flex;align-items:baseline;gap:9px}
h2 .hl{flex:0 0 auto}
h2 .hp{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;
 font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
 text-transform:none;letter-spacing:0;color:var(--mut)}
h2 .keep{flex:0 0 auto;background:#fff8e6;border:1px solid #f0e2bd;color:#6b5a2a;
 border-radius:4px;padding:0 6px;text-transform:none;letter-spacing:0;
 font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
.pane{flex:1;display:flex;min-height:0;overflow:hidden}
.pane iframe{flex:1;width:100%;border:0;min-height:0}
.scroll{flex:1;overflow:auto;background:#eef0f2;padding:10px 0;min-height:0}
.scroll img,.scroll .ph{display:block;margin:0 auto 10px;background:#fff;box-shadow:0 1px 5px rgba(0,0,0,.15)}
mark.pii{border-radius:3px;padding:0 1px;background:#ffe9b8;color:inherit;
  box-shadow:inset 0 -1px 0 #e0bd6a}
mark.pii.right{background:#cdebd8;box-shadow:inset 0 -1px 0 #7fb894}
/* Detected and NOT replaced -- still in the deliverable. */
mark.pii.leak{background:#fbd5d0;box-shadow:inset 0 -1px 0 #d99086}
.empty{flex:1;display:grid;place-items:center;color:var(--mut);font-size:13px;text-align:center;padding:26px}
/* Loading state. Without it the PREVIOUS document stays on screen while the
   next one is fetched, so pressing Enter looks like nothing happened -- the
   reviewer cannot tell a slow load from a repeated file. */
.shim{flex:1;overflow:hidden;background:#eef0f2;padding:14px 16px}
.shim i{display:block;height:11px;border-radius:5px;margin:0 0 9px;
  background:linear-gradient(90deg,#e3e6ea 25%,#f2f4f6 37%,#e3e6ea 63%);
  background-size:400% 100%;animation:sh 1.1s ease-in-out infinite}
.shim i:nth-child(3n){width:72%}.shim i:nth-child(3n+1){width:93%}
.shim i:nth-child(4n){width:58%}
.shim b{display:block;height:15px;width:38%;border-radius:5px;margin:0 0 14px;
  background:linear-gradient(90deg,#dde1e6 25%,#eef0f3 37%,#dde1e6 63%);
  background-size:400% 100%;animation:sh 1.1s ease-in-out infinite}
@keyframes sh{0%{background-position:100% 50%}100%{background-position:0 50%}}
@media (prefers-reduced-motion:reduce){.shim i,.shim b{animation:none}}
/* A long export is thousands of rows and the whole document is one innerHTML.
   content-visibility lets the browser skip layout and paint for the parts that
   are off screen, so the first screenful appears without waiting for the rest.
   The intrinsic size keeps the scrollbar honest while they are skipped. */
.scroll.doc .rec{content-visibility:auto;contain-intrinsic-size:auto 42px}
.empty .why{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;opacity:.8}
.empty .raw{display:inline-block;margin-top:10px;color:var(--fg);text-decoration:underline}

.clik{cursor:pointer}
.clik:hover{color:var(--fg)}
footer{border-top:1px solid var(--line);padding:6px 12px;font-size:11.5px;color:var(--mut);
 display:flex;gap:14px;align-items:center;flex-wrap:wrap;flex:0 0 auto}
kbd{font:11px ui-monospace,Menlo,monospace;background:var(--soft);border:1px solid var(--line);
 border-bottom-width:2px;border-radius:4px;padding:1px 5px}
#jump{margin-left:auto;font:11.5px ui-monospace,Menlo,monospace;border:1px solid var(--line);border-radius:5px;padding:3px 7px;width:120px}
@media(max-width:820px){main{grid-template-columns:1fr}}
</style></head><body>

<div id="veil" class="on"><div class="pop">
  <h1>Compare a run</h1>
  <p class="sub">Point at the folder, zip or bucket holding it. Both halves are found inside.</p>
  <div class="row"><label for="label">Name <span class="opt">optional</span></label>
    <div class="grow"><input type="text" id="label" spellcheck="false"
      placeholder="finance 28th — defaults to the folder name"></div></div>
  <div class="row"><label for="root">Location</label>
    <div class="grow"><input type="text" id="root" spellcheck="false" placeholder="s3://bucket/export   or a folder">
      <button class="mini" id="browse">Choose…</button></div>
    <div id="recent"></div></div>
  <div class="row" id="profrow" style="display:none"><label for="profile">AWS profile</label>
    <input type="text" id="profile" spellcheck="false" placeholder="default"></div>
  <div class="row two" id="splitrow" style="display:none">
    <div><label for="src">Source</label><select id="src"></select></div>
    <div><label for="out">Output</label><select id="out"></select></div></div>
  <div id="msg"></div>
  <div class="acts"><button class="go" id="go">Open</button>
    <span class="link" id="twoway">two separate locations →</span></div>
  <div id="pair" style="display:none">
    <div class="row" style="margin-top:14px"><label for="left">Source location</label>
      <div class="grow"><input type="text" id="left" spellcheck="false"><button class="mini" id="bl">Choose…</button></div></div>
    <div class="row"><label for="right">Output location</label>
      <div class="grow"><input type="text" id="right" spellcheck="false"><button class="mini" id="br">Choose…</button></div></div></div>
</div></div>

<div id="app">
<div id="banner"><span id="btext"></span><button id="bfix"></button><span class="x" id="bx">&times;</span></div>
<header>
  <button class="icobtn" id="showside" title="show the list  (s)" style="display:none">&#187;</button>
  <span class="loc" id="loc" title=""></span>
  <span class="pos" id="pos">–</span>
  <span class="name" id="name"></span>
  <span class="tag" id="how"></span>
  <button id="rev"><span id="revic"></span><span id="revtx">Review</span></button>
  <input id="cbox" placeholder="add a comment…" spellcheck="false">
  <span class="count" id="count"></span>
  <button class="icobtn" id="mapbtn" title="the run&#39;s PII mapping table  (m)">PII-mappings</button>
  <button class="icobtn" id="infobtn" title="details  (i)">i</button>
  <span id="split" title="change what is compared"></span>
</header>
<div id="cbar"></div>
<div id="body">
  <aside id="side">
    <div id="grip" title="drag to resize the list"></div>
    <div class="top"><input id="q" placeholder="search every file in the run" spellcheck="false">
      <button class="icobtn" id="hideside" title="hide the list  (s)">&#171;</button></div>
    <div id="snote"></div>
    <div id="list"></div>
  </aside>
  <main>
    <section><h2><span class="hl" id="lh">Source</span><span class="hp" id="lhp"></span></h2>
      <div class="pane" id="lp"></div></section>
    <section><h2 class="r"><span class="hl" id="rh">Output</span><span class="hp" id="rhp"></span></h2>
      <div class="pane" id="rp"></div></section>
  </main>
  <aside id="info"></aside>
</div>
<div id="mveil"><div id="mbox">
  <div class="mhead"><b>PII-mappings</b><span id="mcount" class="opt"></span>
    <input id="mq" placeholder="search every mapping &#8212; original, replacement or type" spellcheck="false">
    <span class="x" id="mx">&times;</span></div>
  <div class="mmain"><div id="mtypes"></div><div id="mwrap"><div id="mbody"></div>
    <div id="mpage"></div></div></div>
</div></div>
<footer>
  <span><kbd>enter</kbd> review + next · <kbd>r</kbd> review · <kbd>c</kbd> comment</span>
  <span><kbd>&uarr;</kbd><kbd>&darr;</kbd> file · <kbd>&larr;</kbd><kbd>&rarr;</kbd> folder · <kbd>[</kbd><kbd>]</kbd> page</span>
  <span><kbd>a</kbd> <span id="mode">unreviewed only</span></span>
  <span id="mapfoot" class="clik"><kbd>m</kbd> PII-mappings</span>
  <span><kbd>s</kbd> list · <kbd>i</kbd> details · <kbd>y</kbd> <span id="hil" title="highlight PII  (h)">pii on</span>
  <span id="syn">sync on</span> · <kbd>?</kbd> keys</span>
  <input id="jump" placeholder="jump # or name">
</footer>
</div>

<script>
const el=id=>document.getElementById(id);
const ICON={
 folder:'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M1.9 12.6V3.9c0-.6.4-1 1-1h3l1.3 1.7h6c.5 0 1 .4 1 1v7c0 .5-.5 1-1 1H2.9c-.6 0-1-.5-1-1z"/></svg>',
 open:'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M1.9 12.6V3.9c0-.6.4-1 1-1h3l1.3 1.7h6c.5 0 1 .4 1 1v1.2"/><path d="M1.9 12.6l1.8-5.1h11l-1.8 5.1a1 1 0 01-1 .7H2.9a1 1 0 01-1-.7z"/></svg>',
 done:'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="6.2"/><path d="M5.3 8.2l1.9 1.9 3.6-4"/></svg>',
 all:'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2" y="2.4" width="12" height="4.6" rx="1"/><rect x="2" y="9" width="12" height="4.6" rx="1"/></svg>',
 doc:'<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M9.3 1.9H4.3c-.6 0-1 .4-1 1v10.2c0 .6.4 1 1 1h7.4c.6 0 1-.4 1-1V5.2L9.3 1.9z"/><path d="M9.1 2.1v3.3h3.4"/></svg>',
 sheet:'<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2.3" y="2.7" width="11.4" height="10.6" rx="1"/><path d="M2.3 6.2h11.4M6.3 6.2v7.1"/></svg>',
 img:'<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2.3" y="3" width="11.4" height="10" rx="1"/><circle cx="6" cy="6.4" r="1"/><path d="M2.7 11.4l3.2-2.9 3 2.5 1.9-1.6 2.5 2.1"/></svg>',
 tick:'<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3.4 8.4l3 3 6.2-6.6"/></svg>',
};
function fileIcon(n){const e=(n.split(".").pop()||"").toLowerCase();
 if(["csv","tsv","xlsx","xls","parquet"].includes(e))return ICON.sheet;
 if(["png","jpg","jpeg","gif","webp","bmp","svg"].includes(e))return ICON.img;
 return ICON.doc;}
function esc(t){const d=document.createElement("div");d.textContent=t;return d.innerHTML;}

let ALL=[],VIEW=[],i=0,marks={},onlyNew=true,SYNC=true,CAN=false;
//: Folder paths currently expanded. The list is a tree you open in place,
//: not a location you navigate to -- collapsing the siblings out of view to
//: see one folder's contents is the thing that made it feel like a different
//: screen every click.
let OPENP=new Set();
let inspected=null,twoWay=false;

/* ---------- record: viewed / reviewed / comments ---------- */
const key=p=>p.left;
function rec(p){let m=marks[key(p)];
 if(!m) return {viewed:false,reviewed:false,comments:[]};
 return {viewed:!!m.viewed,reviewed:!!m.reviewed,comments:m.comments||[]};}
function save(p,r){
  if(!r.viewed&&!r.reviewed&&!r.comments.length) delete marks[key(p)]; else marks[key(p)]=r;
  fetch("/api/mark",{method:"POST",body:JSON.stringify({key:key(p),rec:r})});
}

/* ---------- popup ---------- */
function note(h,c){el("msg").innerHTML=h?`<p class="note ${c||""}">${h}</p>`:"";}
// The profile box appears for anything that names S3, not just a typed
// "s3://". Keyed on that literal alone, a pasted console URL or an ARN left
// the field hidden -- so the one credential the request needed could not be
// entered, and Open came back with an unhelpful access error.
// Note the two different hosts: the REST endpoints are *.amazonaws.com, but
// the console is console.aws.amazon.com -- which does not contain the string
// "amazonaws.com" at all. Matching only the first spelling left the field
// hidden for exactly the URL people actually paste.
const NAMES_S3=/s3:\/\/|amazonaws\.com|aws\.amazon\.com\/s3|arn:aws[a-z-]*:s3:/i;
function syncProf(){el("profrow").style.display=
  NAMES_S3.test(el("root").value+" "+el("left").value+" "+el("right").value)?"":"none";}
["root","left","right"].forEach(id=>el(id).addEventListener("input",()=>{syncProf();
 if(id==="root"){el("splitrow").style.display="none";inspected=null;note("");}}));
async function choose(t){note("Opening the picker…");
 const r=await(await fetch("/api/browse",{method:"POST",body:"{}"})).json();
 note(r.error||"",r.error?"err":""); if(r.path){el(t).value=r.path;syncProf();if(t==="root")inspect();}}
el("browse").onclick=()=>choose("root");el("bl").onclick=()=>choose("left");el("br").onclick=()=>choose("right");
el("twoway").onclick=()=>{twoWay=!twoWay;el("pair").style.display=twoWay?"":"none";
 el("splitrow").style.display="none";el("twoway").textContent=twoWay?"← one location instead":"two separate locations →";
 document.querySelectorAll(".pop .row")[0].style.display=twoWay?"none":"";note("");};
async function inspect(){
  const root=el("root").value.trim(); if(!root)return;
  note("Looking inside…");
  const r=await(await fetch("/api/inspect",{method:"POST",
    body:JSON.stringify({root,profile:el("profile").value})})).json();
  if(r.error){note(r.error,"err");return;}
  inspected=r;
  const fill=(sel,val,blank)=>{sel.innerHTML="";
    (blank?[{name:"",files:0}]:[]).concat(r.options).forEach(o=>{
      const op=document.createElement("option");op.value=o.name;
      op.textContent=o.name?`${o.name}/  (${o.files})`:"everything else";
      if(o.name===val)op.selected=true;sel.appendChild(op);});};
  fill(el("src"),r.source||"",true); fill(el("out"),r.output||"",false);
  el("splitrow").style.display="grid";
  // Show what was actually opened. A pasted console URL becomes the s3:// URI
  // here, which is both the confirmation that the paste was understood and
  // the string the recents list and marks.json will be keyed by.
  let msg=r.warn||"Found both halves. Change either if this is not right.";
  if(r.root&&r.root!==root){ el("root").value=r.root;
    msg=r.warn||("Opening "+r.root+" — change either half if this is not right."); }
  note(msg,r.warn?"warn":"");
}
el("root").addEventListener("keydown",e=>{if(e.key==="Enter"){inspected?open_():inspect();}});
async function open_(){
  el("go").disabled=true;note("Reading both sides…");
  const lbl=el("label")?el("label").value.trim():"";
  const body=twoWay?{left:el("left").value,right:el("right").value,profile:el("profile").value,label:lbl}
                   :{root:el("root").value,profile:el("profile").value,source:el("src").value,output:el("out").value,label:lbl};
  let r; try{r=await(await fetch("/api/open",{method:"POST",body:JSON.stringify(body)})).json();}
  catch(e){note("could not reach the server: "+e,"err");el("go").disabled=false;return;}
  el("go").disabled=false;
  if(r.error){note(r.error,"err");return;}
  if(!r.pairs.length){note("nothing paired up — try a different source or output","err");return;}
  start(r);
}
el("go").onclick=()=>{ if(!twoWay&&!inspected) inspect(); else open_(); };

let SOLO=false, HOVER=null;
function start(r){
  DOCC.clear();
  ALL=r.pairs; marks=r.marks||{};
  el("veil").classList.remove("on"); el("app").style.display="flex";
  SOLO=!!r.solo;
  document.querySelector("main").classList.toggle("solo",SOLO);
  el("lh").textContent=(SOLO?(r.solo_label||"Transformed")+" · ":"Source · ")+(r.left_short||"source");
  el("lh").title=r.left||"";
  el("rh").textContent="Output · "+(r.right_short||"output"); el("rh").title=r.right||"";
  el("split").textContent=(r.source||"everything else")+" → "+(r.output||"?");
  // Two tabs on two batches look identical without this.
  const where=(r.label||"").trim()
    || (r.root||"").replace(/\/+$/,"").split("/").pop() || r.root || "review";
  el("loc").textContent=where; el("loc").title=r.root||"";
  document.title=where+" · "+(r.pairs?r.pairs.length:0)+" docs";
  THIN=r.thinned||{};
  TOTB=(r.pairs||[]).reduce((a,p)=>a+(p.lb||0),0);
  HASMAP=!!r.has_map;
  // Always present. Hiding it meant a reviewer whose run shipped no database
  // saw no button, no explanation and no way in -- which is exactly what the
  // QA pass reported as "cannot open mappings".
  el("mapbtn").classList.toggle("off",!HASMAP);
  el("mapfoot").style.display=HASMAP?"":"none";
  if(r.hint){el("btext").textContent=r.hint.text;el("bfix").textContent="use "+r.hint.output+"/";
    el("bfix").onclick=()=>{el("out").value=r.hint.output;el("banner").classList.remove("on");open_();};
    el("bfix").style.display=""; el("banner").classList.add("on");}
  else el("banner").classList.remove("on");
  OPENP=new Set();i=0;
  build(); list();
  const w=parseInt(location.hash.slice(1),10);
  if(!isNaN(w)){const at=VIEW.findIndex(p=>p.id===w); if(at>=0) i=at;}
  render();
}
el("bx").onclick=()=>el("banner").classList.remove("on");
el("split").onclick=()=>{el("app").style.display="none";el("veil").classList.add("on");note("");
  if(!twoWay&&el("root").value.trim())inspect();};

/* ---------- list ---------- */
let EXTRA=[], SMORE=0, SSEQ=0, SQ=null, TOTAL=0;
/* What the list is drawn from. Normally the sample -- the hundred per app
   this machine was dealt. While a search is running it is the sample plus
   every pair in the run that matched, because "find the file they reported"
   is a different job from "review your share", and answering it out of a
   hundred rows per app would miss it almost every time. */
function pool(){return q()? ALL.concat(EXTRA) : ALL;}
const entOf=p=>p.label.split("/")[0];
function q(){return el("q").value.trim().toLowerCase();}
function matches(p){const s=q(); return !s || p.label.toLowerCase().includes(s);}
//: The visible tree, flattened to rows: a folder, then its contents if it is
//: open, then the next folder. Depth drives the indent.
function treeRows(){
  const items=pool().filter(matches);
  const rows=[];
  const walk=(prefix,depth)=>{
    const dirs=new Map(), files=[];
    const cut=prefix.length+1;
    items.forEach(p=>{
      if(prefix && !(p.label===prefix || p.label.startsWith(prefix+"/"))) return;
      const rest = prefix ? p.label.slice(cut) : p.label;
      const ix=rest.indexOf("/");
      if(ix<0){files.push(p);return;}
      const d=rest.slice(0,ix);
      if(!dirs.has(d)) dirs.set(d,[]);
      dirs.get(d).push(p);
    });
    [...dirs.keys()].sort().forEach(name=>{
      const path=prefix?prefix+"/"+name:name;
      const open=OPENP.has(path);
      rows.push({dir:true,path,name,depth,arr:dirs.get(name),open});
      if(open) walk(path,depth+1);
    });
    files.sort((a,b)=>a.label<b.label?-1:1)
         .forEach(p=>rows.push({dir:false,p,depth}));
  };
  walk("",0);
  return rows;
}
function build(){
  // j/k walk every file in the run, in the order the tree shows them, so
  // Enter never stops dead at a folder boundary.
  let v = pool().filter(matches);
  VIEW = onlyNew ? v.filter(p=>!rec(p).reviewed) : v;
  if(i>=VIEW.length) i=Math.max(0,VIEW.length-1);
}
//: One file row. Shared by the folder view and the search results, which
//: differ only in how much of the path the row shows.
function fileRow(p,text){
  const r=rec(p);
  const cls=r.reviewed?"reviewed":(p.how==="missing"?"missing":(r.viewed?"viewed":""));
  const f=document.createElement("div");
  f.className="file"+(p.sampled===false?" extra":"");
  f.setAttribute("aria-current", !!(VIEW[i]&&VIEW[i].id===p.id));
  f.innerHTML=`<span class="dot ${cls}"></span><span class="ic">${fileIcon(text)}</span>`+
              `<span class="t">${esc(text)}</span>`;
  f.title=p.label;
  // The list truncates and the header shows only the current file, so hovering
  // writes the full path into the header instead of waiting on a tooltip.
  f.onmouseenter=()=>{const n=el("name");
    if(HOVER===null) HOVER=n.textContent;
    n.textContent=p.label; n.title=p.label; n.classList.add("peek");};
  f.onmouseleave=()=>{const n=el("name");
    if(HOVER!==null){n.textContent=HOVER; n.title=HOVER; HOVER=null;}
    n.classList.remove("peek");};
  f.onclick=ev=>{ev.stopPropagation();
    if(onlyNew && rec(p).reviewed){onlyNew=false;el("mode").textContent="all files";}
    build();
    const at=VIEW.findIndex(x=>x.id===p.id); if(at>=0){i=at;list();render();}};
  return f;
}
//: One folder row -- name, then what is in it. Shared by the folder browser
//: and the grouped search results so both report a folder the same way.
function folderRow(name,arr,go){
  let done=0,miss=0,note=0,bytes=0;
  arr.forEach(p=>{const x=rec(p); if(x.reviewed)done++; note+=x.comments.length;
    bytes+=p.lb||0; if(p.how==="missing")miss++;});
  const base=name.split("/").length ? name : name;
  const sub=new Set();
  arr.forEach(p=>{const r=p.label.slice(name.length+1); const ix=r.indexOf("/");
    if(ix>0) sub.add(r.slice(0,ix));});
  const bits=[`${arr.length} file${arr.length===1?"":"s"}`];
  if(done) bits.push(done===arr.length?"all reviewed":`${done} reviewed`);
  else if(arr.length) bits.push(`${arr.length} to go`);
  if(bytes) bits.push(kb(bytes)+(TOTB?` · ${Math.round(bytes*100/TOTB)}%`:""));
  if(sub.size) bits.push(`${sub.size} folder${sub.size===1?"":"s"}`);
  if(note) bits.push(`${note} comment${note===1?"":"s"}`);
  if(miss) bits.push(`<span class="w">${miss} missing</span>`);
  const d=document.createElement("div"); d.className="fold";
  d.innerHTML=`<span class="tw">&#9656;</span>
    <span class="ic">${done>=arr.length&&arr.length?ICON.done:ICON.folder}</span>
    <span class="tx"><div class="n">${esc(name.split("/").pop())}</div>
    <div class="m">${bits.join(" · ")}</div></span>`;
  d.onclick=go;
  return d;
}
function list(){
  const box=el("list"); box.innerHTML="";
  // A search opens every folder on the way to a hit, so matches are visible
  // in place instead of behind a click.
  if(q()){
    pool().filter(matches).forEach(p=>{
      const seg=p.label.split("/");
      for(let n=1;n<seg.length;n++) OPENP.add(seg.slice(0,n).join("/"));
    });
  }
  const rows=treeRows();
  const pad=d=>`padding-left:${8+d*15}px`;

  rows.forEach(r=>{
    if(r.dir){
      const d=folderRow(r.path,r.arr,()=>{
        OPENP.has(r.path)?OPENP.delete(r.path):OPENP.add(r.path);
        list();
      });
      d.classList.toggle("open",r.open);
      d.style.cssText=pad(r.depth);
      box.appendChild(d);
    }else{
      const f=fileRow(r.p,r.p.label.split("/").pop());
      f.style.cssText=pad(r.depth+1);
      box.appendChild(f);
    }
  });

  if(!rows.length){
    const e=document.createElement("div"); e.className="none";
    e.textContent = q()?"nothing matches that search":"nothing here";
    box.appendChild(e);
  }
}
el("q").addEventListener("input",()=>{
  i=0;build();list();render();
  clearTimeout(SQ); SQ=setTimeout(search,200);
});
async function search(){
  const s=q();
  if(!s){EXTRA=[];SMORE=0;snote();build();list();render();return;}
  const seq=++SSEQ;
  let r; try{ r=await(await fetch("/api/search?q="+encodeURIComponent(s))).json(); }
  catch(e){ return; }
  // A slow response for a query that has since been retyped would replace the
  // list under the cursor with the wrong run of files.
  if(seq!==SSEQ || q()!==s) return;
  const have=new Set(ALL.map(p=>p.id));
  EXTRA=(r.rows||[]).filter(p=>!have.has(p.id));
  SMORE=Math.max(0,(r.matched||0)-(r.rows||[]).length);
  snote(r);
  build(); list(); render();
}

function stepFolder(d){
  // Top-level folder to top-level folder, opening the one it lands on and
  // parking the cursor on its first file. The tree is expanded in place, so
  // "next folder" is a jump within one list rather than a change of screen.
  const tops=[...new Set(pool().filter(matches).map(entOf))].sort();
  if(!tops.length)return;
  const cur=VIEW[i]?entOf(VIEW[i]):tops[0];
  const at=tops.indexOf(cur);
  const n=at<0?(d>0?0:tops.length-1):Math.min(tops.length-1,Math.max(0,at+d));
  OPENP.add(tops[n]);
  const first=VIEW.findIndex(p=>entOf(p)===tops[n]);
  if(first>=0) i=first;
  list(); render();
  const row=el("list").querySelector('.file[aria-current=true]');
  if(row) row.scrollIntoView({block:"nearest"});
}
function toggleSide(force){
  const on = force===undefined ? !el("body").classList.contains("narrow") : !force;
  el("body").classList.toggle("narrow",on);
  el("showside").style.display = on?"":"none";
}
el("hideside").onclick=()=>toggleSide(false);
el("showside").onclick=()=>toggleSide(true);

/* ---------- panes ---------- */
let PAGE=1,LS=null,RS=null,BUSY=false,SEQ=0,INFO=false,MSEQ=0,THIN={},TOTB=0,HASMAP=false;
function iframeFor(side,id){const f=document.createElement("iframe");
 f.src="/doc/"+side+"/"+id+(PAGE>1?"#page="+PAGE:""); return f;}
function build_pane(box,side,id,meta){
  box.innerHTML="";
  // Rendered here rather than handed to the browser: it SAVES a csv/xlsx
  // instead of showing one. Rendering also makes them ordinary DOM, so these
  // panes scroll in step exactly like the PDF ones.
  if(meta.kind==="table"||meta.kind==="text"||meta.kind==="records"){
    const sc=document.createElement("div");
    sc.className="scroll doc "+meta.kind;
    sc.innerHTML=meta.html||"";
    box.appendChild(sc); return sc;
  }
  if(meta.kind==="image"){
    const sc=document.createElement("div"); sc.className="scroll";
    const img=new Image(); img.src="/doc/"+side+"/"+id; img.style.width="100%";
    sc.appendChild(img); box.appendChild(sc); return sc;
  }
  if(meta.kind==="other"){
    // Never an iframe. Chrome does not "fail to render" a .doc or a broken
    // xlsx -- it saves it, silently, once per pane per refresh, and leaves
    // the reviewer looking at a blank box wondering why Downloads is full.
    // Say what it is, and make the download something they choose.
    const why=meta.why?("<br><span class=why>"+esc(meta.why)+"</span>"):"";
    box.innerHTML="<div class='empty'><b>Can't show this one here.</b>"+why+
      "<br><a class='raw' href='/doc/"+side+"/"+id+"' download>Download the raw file</a></div>";
    return null;
  }
  if(meta.kind==="raw"){box.appendChild(iframeFor(side,id));return null;}
  if(meta.kind!=="pdf"||!meta.pages){
    // "none", or any shape a future server sends that this page predates.
    // The old catch-all was the iframe, i.e. a download; this one is a
    // sentence.
    box.innerHTML="<div class='empty'>Nothing to show for this side.</div>";
    return null;
  }
  const sc=document.createElement("div"); sc.className="scroll";
  const W=Math.max(280,(box.clientWidth||600)-24);
  meta.pages.forEach((sz,n)=>{
    const h=Math.round(W*sz[1]/Math.max(1,sz[0]));
    // The image goes into the DOM immediately, sized from the page's real
    // aspect so it holds its space before it loads — which is what keeps the
    // other pane from drifting out of step, and what lets loading="lazy"
    // work at all. Building it detached and swapping it in on load was a
    // deadlock: the browser will not load a lazy image that is not in the
    // document, so a 28-page report rendered as two blank panes.
    const img=new Image(W,h);
    img.style.width=W+"px"; img.style.height=h+"px";
    img.loading = n<2 ? "eager" : "lazy";
    img.decoding="async"; img.alt="";
    img.src="/page/"+side+"/"+id+"/"+n+".png";
    sc.appendChild(img);
  });
  box.appendChild(sc);
  return sc;
}
function linkScroll(a,b){
  if(!a||!b)return;
  const mirror=(from,to)=>()=>{
    if(!SYNC||BUSY)return; BUSY=true;
    const r=Math.max(1,from.scrollHeight-from.clientHeight);
    to.scrollTop=(from.scrollTop/r)*Math.max(1,to.scrollHeight-to.clientHeight);
    // Sideways too. A wide table is the case where the panes are hardest to
    // compare -- scrolling one to column 20 and leaving the other at column 1
    // is exactly when you need them level.
    const rx=Math.max(1,from.scrollWidth-from.clientWidth);
    to.scrollLeft=(from.scrollLeft/rx)*Math.max(1,to.scrollWidth-to.clientWidth);
    requestAnimationFrame(()=>{BUSY=false;});
  };
  a.addEventListener("scroll",mirror(a,b),{passive:true});
  b.addEventListener("scroll",mirror(b,a),{passive:true});
}
function step_page(d){
  const p=VIEW[i]; if(!p)return;
  if(LS){const kids=[...LS.children];
    const n=Math.max(0,Math.min(kids.length-1,PAGE-1+d));
    if(n===PAGE-1)return; PAGE=n+1;
    if(kids[n]) LS.scrollTop=kids[n].offsetTop-LS.offsetTop;
    return;}
  PAGE=Math.max(1,PAGE+d);
  el("lp").innerHTML="";el("lp").appendChild(iframeFor("left",p.id));
  if(p.right){el("rp").innerHTML="";el("rp").appendChild(iframeFor("right",p.id));}
}
/* Documents already fetched, and the ones we expect to want next.
   Keyed side/id, values are the in-flight PROMISE so two requests for the same
   document collapse into one. Bounded, oldest evicted -- a run is thousands of
   files and every payload is the whole rendered document. */
//: Documents fetched or in flight, keyed side/id. The entry carries its own
//: resolution flag: DOCC membership alone means "requested", and using that as
//: "ready" is what made the shimmer skip while the old pane was still up.
//: Small on purpose -- prefetch only ever reaches i-1..i+2, and each entry
//: retains a whole rendered document.
const DOCC=new Map(), DOCMAX=8;
function dkey(side,id){return side+"/"+id;}
function docFetch(side,id){
  const k=dkey(side,id);
  // Re-insert on a hit so eviction is by recency, not first-seen -- otherwise
  // the document on screen can be dropped while a stale prefetch survives.
  if(DOCC.has(k)){const e=DOCC.get(k); DOCC.delete(k); DOCC.set(k,e); return e.p;}
  const e={ready:false};
  e.p=fetch("/api/doc/"+side+"/"+id).then(r=>r.json())
    .then(m=>{e.ready=true;return m;})
    .catch(err=>{DOCC.delete(k);throw err;});
  if(DOCC.size>=DOCMAX) DOCC.delete(DOCC.keys().next().value);
  DOCC.set(k,e);
  return e.p;
}
/* Fetch what the reviewer is about to ask for. j/Enter walks forward, so the
   next two are the high-value guesses; the previous one covers a k. Fired on
   idle so it never competes with painting the document actually on screen. */
function prefetch(){
  // Reads i when it RUNS, not when it was scheduled: an idle callback that
  // fires after two more j presses would otherwise warm the neighbours of a
  // document already left behind. One document ahead only -- server-side
  // rendering is serialised behind a single lock, so a wider window queues
  // ahead of the document actually on screen and makes the wait longer.
  const run=()=>{const p=VIEW[i+1]; if(!p)return;
    docFetch("left",p.id).catch(()=>{});
    if(p.right&&!SOLO) docFetch("right",p.id).catch(()=>{});};
  (window.requestIdleCallback||(f=>setTimeout(f,120)))(run);
}
/* Highlighting. A redaction is obvious -- the value is gone. A REPLACEMENT is
   not: "makhubocalvin@gmail.com" became "zoravinadorncombe@gmail.com" and
   nothing on screen says which cell that was. So the originals are marked in
   the source pane and the replacements in the output pane, and the two tints
   line up cell for cell. */
let PIIRX={orig:null,repl:null,leak:null}, HILITE=true;
function rxOf(list){
  if(!list||!list.length) return null;
  const esc=t=>t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
  // Longest first so a name is not eaten by its own surname.
  const body=list.map(esc).join("|");
  // Case-insensitive: the rewriter preserves the SOURCE cell's casing, so a
  // mapping stored as "Optory Labs" is written into the output as
  // "OPTORY LABS" and an exact match silently never fires.
  try{ return new RegExp("("+body+")","gi"); }catch(e){ return null; }
}
async function loadPii(id){
  // Per document, not once at startup: the run-wide vocabulary is hundreds of
  // thousands of values and only the ones in this document can ever match.
  resetPii();
  if(!HILITE) return;        // mark() would throw the answer away
  if(PIISID===id) return;    // same document, same marks
  PIISID=id;
  try{
    const d=await (await fetch("/api/pii?sid="+encodeURIComponent(id))).json();
    PIIRX.orig=rxOf(d.orig); PIIRX.repl=rxOf(d.repl); PIIRX.leak=rxOf(d.leak);
    PIIDERIVED=!!d.derived;
  }catch(e){}
  hilLabel();
}
var PIIDERIVED=false, PIISID=null;
function resetPii(){ PIIRX={orig:null,repl:null,leak:null}; PIIDERIVED=false; }
function hilLabel(){
  // Derived marks come from diffing the panes, not from the run's own mapping
  // table. Say which, every time -- a reviewer treating a guess as authority
  // is the one failure this feature could introduce.
  const e=el("hil"); if(!e) return;
  e.textContent = !HILITE ? "pii off" : (PIIDERIVED ? "pii derived" : "pii on");
  e.title = PIIDERIVED
    ? "No pii_mappings.db for this user \u2014 marks are derived by diffing the two panes: left-only = replaced, right-only = surrogate, red = PII-shaped and present in BOTH  (h)"
    : "highlight PII  (h)";
}
function mark(root,side){
  if(!root||!HILITE) return;
  // Leaks are marked on BOTH panes: the value was detected and NOT replaced,
  // so it is sitting in the output unchanged, and seeing it red on the right
  // is the whole point.
  paint(root, PIIRX.leak, "leak");
  if(SOLO){
    // One pane, and it can be either half of a run: an input tree where the
    // originals are expected, or a delivered output where a surviving
    // original IS the finding. Mark both vocabularies and let the colours say
    // which it is -- green means a value was substituted here, amber means an
    // original is present. Reviewing a delivery whose "before" is not
    // readable is the case this exists for.
    paint(root, PIIRX.repl, "right");
    paint(root, PIIRX.orig, "left");
    return;
  }
  paint(root, side==="left" ? PIIRX.orig : PIIRX.repl, side);
}
function paint(root,rx,cls){
  if(!root||!rx) return;
  const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,{
    acceptNode:n=>(n.parentNode&&n.parentNode.nodeName==="MARK")
      ?NodeFilter.FILTER_REJECT
      :(n.nodeValue&&n.nodeValue.length>2?NodeFilter.FILTER_ACCEPT:NodeFilter.FILTER_REJECT)});
  const todo=[]; let n;
  while((n=w.nextNode())) todo.push(n);
  todo.forEach(t=>{
    const v=t.nodeValue;
    // Whole values only. A mapping for "auto" was lighting up "automatically",
    // "fica" lit "identification" and "084" lit the tail of an id -- the marks
    // said PII where there was none, which is worse than saying nothing.
    // Checked either side of the match rather than with \\b in the pattern,
    // because a value can start or end with punctuation (an email, "& Retail")
    // and \\b would then refuse the match outright.
    const W=/[A-Za-z0-9_]/;
    const hits=[]; let m;
    rx.lastIndex=0;
    while((m=rx.exec(v))){
      if(!m[0].length){rx.lastIndex++;continue;}
      const a=m.index, b=a+m[0].length;
      const lOK = !W.test(m[0][0])            || a===0        || !W.test(v[a-1]);
      const rOK = !W.test(m[0][m[0].length-1]) || b>=v.length || !W.test(v[b]);
      if(lOK&&rOK) hits.push([a,b]);
    }
    if(!hits.length) return;
    const frag=document.createDocumentFragment();
    let last=0;
    hits.forEach(([a,b])=>{
      if(a<last) return;                        // overlapping longer match won
      if(a>last) frag.appendChild(document.createTextNode(v.slice(last,a)));
      const el2=document.createElement("mark");
      el2.className="pii "+cls; el2.textContent=v.slice(a,b);
      frag.appendChild(el2); last=b;
    });
    if(last<v.length) frag.appendChild(document.createTextNode(v.slice(last)));
    t.parentNode.replaceChild(frag,t);
  });
}
function shimmer(box){
  box.innerHTML="<div class='shim'><b></b>"+"<i></i>".repeat(14)+"</div>";
}
async function panes(p){
  const seq=++SEQ; LS=RS=null; PAGE=1;
  PIIRX={orig:null,repl:null,leak:null};   // never inherit the last document's
  // Clear FIRST. The old pane used to stay up for the whole round trip, which
  // read as "Enter did nothing" or, worse, as the same file twice.
  // A prefetched document is already here: paint it without the shimmer, so a
  // hit is indistinguishable from instant.
  // DOCC.has() is true the moment a PREFETCH STARTS, not when it lands. Using
  // it to decide meant an in-flight prefetch counted as warm, the shimmer was
  // skipped, and the previous document stayed on screen until the fetch
  // finished -- which is exactly the "loader sometimes does not come" report.
  // Only a RESOLVED document is warm.
  // One predicate for "is there a second pane", used by the shimmer, the fetch
  // and the paint alike. Solo pairs a tree with itself, so p.right is always
  // truthy and every document was being fetched, rendered and cached TWICE for
  // a section CSS hides.
  const wantRight = !!p.right && !SOLO;
  const warm=(DOCC.get(dkey("left",p.id))||{}).ready===true;
  if(!warm){ shimmer(el("lp")); if(wantRight) shimmer(el("rp")); }
  let lm={kind:"other",why:"could not ask the server about this document"},rm={kind:"none"};
  if(CAN){ try{
    // Both sides at once. Sequential awaits made every document cost two round
    // trips end to end.
    const [lr,rr]=await Promise.all([
      docFetch("left",p.id),
      wantRight?docFetch("right",p.id):Promise.resolve({kind:"none"}),
      // Which values to look for depends on which document this is, so it
      // rides along with the document rather than costing a second wait.
      loadPii(p.id),
    ]);
    lm=lr; rm=rr;
  }catch(e){} }
  if(seq!==SEQ) return;                 // a slower answer for a document already left behind
  LS=build_pane(el("lp"),"left",p.id,lm);
  if(wantRight) RS=build_pane(el("rp"),"right",p.id,rm);
  else if(!SOLO) el("rp").innerHTML="<div class='empty'><b>Nothing in the output for this document.</b><br>"+
        "Either the run withheld it, or it was never processed.</div>";
  mark(LS,"left"); if(RS) mark(RS,"right");
  if(lm.kind==="records"&&rm.kind==="records") alignRecords(LS,RS);
  linkScroll(LS,RS);
  prefetch();
}

/* Record N starts at the same height on both sides.
   Proportional scroll sync is the right answer for a PDF, where the two sides
   are the same length. It is the wrong one here: the rewriter replaces a long
   gravatar URL with "https://example.com", so the source record is taller,
   and by record 20 the panes are showing different records. Pad the shorter
   of each pair instead and the numbers stay level all the way down. */
function alignRecords(a,b){
  if(!a||!b)return;
  const la=[...a.querySelectorAll(".rec")], lb=[...b.querySelectorAll(".rec")];
  const n=Math.min(la.length,lb.length);
  // Clear first, or a re-align after a resize measures the previous padding
  // and every record grows a little taller each time.
  for(const r of la.concat(lb)) r.style.minHeight="";
  requestAnimationFrame(()=>{
    const h=[];
    for(let i=0;i<n;i++) h.push(Math.max(la[i].offsetHeight,lb[i].offsetHeight));
    for(let i=0;i<n;i++){ la[i].style.minHeight=h[i]+"px"; lb[i].style.minHeight=h[i]+"px"; }
  });
}

/* ---------- details ---------- */
const kb=n=>n==null?"–":(n<1024?n+" B":(n<1048576?(n/1024).toFixed(0)+" KB":(n/1048576).toFixed(1)+" MB"));
const num=n=>n==null?"–":n.toLocaleString();
function dl(rows){return `<dl>${rows.map(([k,v,c])=>
  `<dt>${k}</dt><dd class="${c||""}">${v}</dd>`).join("")}</dl>`;}

function folderStats(name){
  const f=pool().filter(p=>entOf(p)===name);
  let r=0,c=0,v=0,m=0;
  f.forEach(p=>{const x=rec(p); if(x.reviewed)r++; if(x.viewed||x.reviewed)v++;
    c+=x.comments.length; if(p.how==="missing")m++;});
  return {n:f.length,r,c,v,m};
}
async function details(){
  if(!INFO) return;
  const box=el("info"), p=VIEW[i];
  if(!p){ box.innerHTML="<h3>Nothing selected</h3>"; return; }

  const fs = folderStats(entOf(p));
  let run={n:ALL.length,r:0,c:0,v:0,m:0,f:new Set()};
  ALL.forEach(x=>{const y=rec(x); if(y.reviewed)run.r++; if(y.viewed||y.reviewed)run.v++;
    run.c+=y.comments.length; if(x.how==="missing")run.m++; run.f.add(entOf(x));});

  const kept=(p.kept||[]);
  const tail =
    `<h3>Folder</h3>`+
    `<div class="paths"><div><b>src</b> ${esc(dirOf(p.left)||"/")}</div>`+
    `<div class="${kept.length?"badrow":""}"><b>out</b> `+
      `${p.right?esc(dirOf(p.right)||"/"):"nothing paired"}</div></div>`+
    (kept.length?`<div class="why">${esc(kept.join(", "))} unchanged in the output</div>`:"")+
    `${dl([["files",num(fs.n)],["reviewed",num(fs.r)],
      ["viewed",num(fs.v)],["comments",num(fs.c)],
      ["missing",num(fs.m),fs.m?"warnrow":""]])}` +
    `<h3>Run</h3>${dl([["folders",num(run.f.size)],["files",num(run.n)],
      ["viewed",num(run.v)],["reviewed",num(run.r)],["comments",num(run.c)],
      ["missing",num(run.m),run.m?"warnrow":""]])}`;

  box.innerHTML = `<h3>Document</h3><div style="color:var(--mut);font-size:12px">loading…</div>` + tail;

  const seq=++MSEQ;
  let m; try{ m=await (await fetch("/api/metrics/"+p.id)).json(); }catch(e){ m={error:String(e)}; }
  if(seq!==MSEQ || !INFO) return;

  let head;
  if(m.error) head = `<div class="badrow" style="font-size:12px">${esc(m.error)}</div>`;
  else if(m.missing) head = dl([["pairing",esc(m.how)],["source",kb(m.left_bytes)],
                                ["output","nothing",'badrow']]);
  else {
    head = dl([
      ["pairing", esc(m.how), (["size","sole","name"].includes(m.how)?"warnrow":"")],
      ["pages", (m.left_pages!=null?`${m.left_pages} → ${m.right_pages}`:"–")],
      ["size", `${kb(m.left_bytes)} → ${kb(m.right_bytes)}`],
      ["text", (m.left_chars!=null?`${num(m.left_chars)} → ${num(m.right_chars)}`:"–")],
      ["identical", m.identical?"yes":"no", m.identical?"warnrow":""],
      ["removed", num(m.removed)],
      ["added", num(m.added)],
    ]);
    if(m.removed_sample&&m.removed_sample.length)
      head += `<h3>Removed from the output</h3><div class="vals">`+
        m.removed_sample.map(v=>`<span class="v rm">${esc(v)}</span>`).join("")+`</div>`;
    if(m.added_sample&&m.added_sample.length)
      head += `<h3>Only in the output</h3><div class="vals">`+
        m.added_sample.map(v=>`<span class="v ad">${esc(v)}</span>`).join("")+`</div>`;
  }
  box.innerHTML = `<h3>Document</h3>${head}` + tail;
}
function toggleInfo(force){
  INFO = force===undefined ? !INFO : !!force;
  el("body").classList.toggle("info",INFO);
  details();
}
el("infobtn").onclick=()=>toggleInfo();
el("mapbtn").onclick=()=>maps();
el("mapfoot").onclick=()=>maps();

/* ---------- render ---------- */
function counters(){
  let v=0,r=0,c=0;
  ALL.forEach(p=>{const m=rec(p); if(m.viewed||m.reviewed)v++; if(m.reviewed)r++; c+=m.comments.length;});
  el("count").textContent=`${v} viewed · ${r} reviewed · ${ALL.length} files${c?` · ${c} comments`:""}`;
}
function comments(p){
  const r=rec(p), bar=el("cbar");
  bar.innerHTML=""; bar.classList.toggle("on", r.comments.length>0);
  r.comments.forEach((t,n)=>{
    const c=document.createElement("span"); c.className="chip";
    c.innerHTML=`<span>${esc(t)}</span><b title="remove">&times;</b>`;
    c.querySelector("b").onclick=()=>{const q=rec(p); q.comments.splice(n,1); save(p,q); comments(p); counters(); list();};
    bar.appendChild(c);
  });
}
function head(){
  if(!VIEW.length){
    el("pos").textContent="0 / 0"; el("name").textContent="nothing matches";
    el("how").textContent=""; el("rev").classList.remove("on");
    el("cbar").classList.remove("on"); counters(); return false;
  }
  const p=VIEW[i], r=rec(p);
  el("pos").textContent=`${i+1} / ${VIEW.length}`;
  el("name").textContent=p.label; el("name").title=p.label;
  el("how").textContent=p.how; el("how").className="tag "+p.how;
  el("rev").classList.toggle("on",r.reviewed);
  el("revic").innerHTML=r.reviewed?ICON.tick:"";
  el("revtx").textContent=r.reviewed?"Reviewed":"Review";
  paneHeads(p);
  comments(p); counters();
  return true;
}
/* The folder a document sits in, above the document -- neither pane ever
   shows it, and gmail/<someone>@<employer>/messages/page_000001.jsonl names a
   person in the object key whatever the bytes underneath look like. */
function dirOf(k){const b=(k||"").split("/"); b.pop(); return b.join("/");}
function paneHeads(p){
  el("lhp").textContent=dirOf(p.left); el("lhp").title=p.left||"";
  el("rhp").textContent=p.right?dirOf(p.right):"";
  el("rhp").title=p.right||"";
}
function render(){
  if(!head()){ el("lp").innerHTML=el("rp").innerHTML=
    "<div class='empty'>Nothing here. Press <b>a</b> for all files, or clear the search."+
    (q()?"<br><span class='why'>The search covered all "+num(TOTAL)+" pairs in the run, not just your sample.</span>":"")+
    "</div>"; return; }
  const p=VIEW[i];
  const r=rec(p);
  // Opening a document is what "viewed" means; nothing to press.
  if(!r.viewed){ r.viewed=true; save(p,r); }
  panes(p);
  details();
  location.hash=p.id;
}
let TICK=null;
function go(d){
  if(!VIEW.length)return;
  i=Math.min(VIEW.length-1,Math.max(0,i+d));
  head();                                  // header keeps up with the key
  clearTimeout(TICK);
  // Holding the key used to load every document it passed through. Only the
  // one you stop on is fetched.
  TICK=setTimeout(()=>{ render(); list();
    const cur=el("list").querySelector('.file[aria-current=true]');
    if(cur) cur.scrollIntoView({block:"nearest"});
  },90);
}
function toggleReview(){
  const p=VIEW[i]; if(!p)return;
  const r=rec(p); r.reviewed=!r.reviewed; if(r.reviewed) r.viewed=true;
  save(p,r);
  if(onlyNew && r.reviewed){ build(); list(); render(); } else { head(); list(); details(); }
}
// Review and move on in one key: the same deliberate act, at the cost of just
// stepping past. j/down stays a pure skip for anything you want to come back to.
function reviewNext(){
  const p=VIEW[i]; if(!p) return;
  const r=rec(p); r.reviewed=true; r.viewed=true; save(p,r);
  if(onlyNew){ build(); list(); render(); } else { go(1); list(); }
}
function reviewFolder(){
  const p=VIEW[i]; if(!p) return;
  const name=entOf(p);
  ALL.filter(x=>entOf(x)===name).forEach(x=>{
    const r=rec(x); if(!r.reviewed){ r.reviewed=true; r.viewed=true; save(x,r); }
  });
  build(); list(); render();
}
el("rev").onclick=toggleReview;
el("cbox").addEventListener("keydown",e=>{
  if(e.key!=="Enter")return;
  const p=VIEW[i], t=e.target.value.trim(); if(!p||!t)return;
  const r=rec(p); r.comments=r.comments.concat([t]); r.viewed=true;
  save(p,r); e.target.value=""; comments(p); counters(); list();
});
function jump(s){
  s=(s||"").trim(); if(!s)return;
  const n=parseInt(s,10);
  if(!isNaN(n)&&String(n)===s){i=Math.min(VIEW.length-1,Math.max(0,n-1));render();list();return;}
  const at=VIEW.findIndex(p=>p.label.toLowerCase().includes(s.toLowerCase()));
  if(at>=0){i=at;render();list();}
}
el("jump").addEventListener("keydown",e=>{if(e.key==="Enter"){jump(e.target.value);e.target.blur();}});

let MAPQ=null;
function maps(){
  el("mveil").classList.add("on");
  // No database is the common case -- it is written beside the pipeline and
  // often never uploaded -- so the panel asks for one rather than refusing to
  // open. An alert saying "use --mappings" is useless to somebody who started
  // the tool from a preset and cannot restart it.
  if(!HASMAP){ el("mcount").textContent=""; askMap(); return; }
  el("mq").focus(); loadMaps();
}
function askMap(err){
  el("mbody").innerHTML=
    `<p class="more">This run did not ship a mapping database. The pipeline `+
    `writes <code>pii_mappings.db</code> beside the run and it is often not `+
    `uploaded with the output \u2014 point at one and it opens here.</p>`+
    `<div class="askmap"><input id="mspec" spellcheck="false" `+
    `placeholder="~/runs/_pii/pii_mappings.db   or   s3://bucket/prefix/pii_mappings.db">`+
    `<button class="mini" id="mgo">Open</button></div>`+
    (err?`<p class="more bad">${esc(err)}</p>`:"");
  const go=async()=>{
    const spec=el("mspec").value.trim(); if(!spec)return;
    el("mbody").innerHTML=`<p class="more">reading \u2026</p>`;
    const r=await(await fetch("/api/usemap",{method:"POST",
      body:JSON.stringify({spec})})).json();
    if(r.error){askMap(r.error);return;}
    HASMAP=true; el("mapbtn").classList.remove("off");
    el("mq").focus(); loadMaps();
  };
  el("mgo").onclick=go;
  el("mspec").addEventListener("keydown",e=>{if(e.key==="Enter")go();});
  el("mspec").focus();
}
let MTYPE="", MOFF=0, MTOTAL=0, MLIM=200;
async function loadMaps(){
  const q=el("mq").value.trim();
  const seq=++MSEQ;
  const r=await(await fetch("/api/mappings?q="+encodeURIComponent(q)+
    "&type="+encodeURIComponent(MTYPE)+"&offset="+MOFF)).json();
  if(seq!==MSEQ)return;
  if(r.error){el("mbody").innerHTML=`<p class="more">${esc(r.error)}</p>`;
    el("mtypes").innerHTML=""; el("mpage").innerHTML="";
    el("mcount").textContent=""; return;}
  MTOTAL=r.total; MLIM=r.limit;
  el("mcount").textContent = q
    ? `${num(r.matched)} of ${num(r.count)} match`
    : `${num(r.count)} mappings`;

  // Every attribute type, always, with its real count. This is the index into
  // a hundred thousand rows and the only way to see what the run did to each
  // kind of thing it found.
  const all=r.types.reduce((a,t)=>a+t.total,0);
  el("mtypes").innerHTML =
    `<div class="mtype" data-t="" aria-current="${MTYPE===""}">`+
      `<span class=n>All types</span><span class=c>${num(all)}</span></div>`+
    r.types.map(t=>`<div class="mtype" data-t="${esc(t.type)}" `+
      `aria-current="${MTYPE===t.type}"><span class=n>${esc(t.type)}</span>`+
      `<span class=c>${num(t.total)}</span></div>`).join("");

  if(!r.rows.length){
    el("mbody").innerHTML=`<p class="more">Nothing here.</p>`;
    el("mpage").innerHTML=""; return;}
  el("mbody").innerHTML=`<table><thead><tr><th>original</th><th>replacement</th>`+
    `<th>type</th><th></th></tr></thead><tbody>`+
    r.rows.map(m=>{
      const notes=(m.notes||[]).map(n=>`<span class=mnote>${esc(n)}</span>`).join("");
      return `<tr data-key="${esc(m.key)}">`+
        `<td class=o>${esc(m.original==null?"":String(m.original))}</td>`+
        `<td class=r>${m.replacement==null?"<i>not replaced</i>":esc(String(m.replacement))}`+
          (notes?`<div class=mnotes>${notes}</div>`:"")+`</td>`+
        `<td class=t>${esc(m.attribute_type==null?"":String(m.attribute_type))}</td>`+
        `<td class=cmt><button class="lnk addn" title="comment on this mapping">`+
          ((m.notes||[]).length?`&#9679; ${(m.notes||[]).length}`:"comment")+`</button></td></tr>`;
    }).join("")+`</tbody></table>`;
  el("mbody").scrollTop=0;

  const from=r.offset+1, to=Math.min(r.offset+r.rows.length, r.total);
  el("mpage").innerHTML=
    `<span>${num(from)}\u2013${num(to)} of ${num(r.total)}`+
    (MTYPE?` in ${esc(MTYPE)}`:"")+`</span>`+
    `<button class="lnk mprev"${r.offset?"":" disabled"}>&larr; previous</button>`+
    `<button class="lnk mnext"${to<r.total?"":" disabled"}>next &rarr;</button>`;
}
el("mtypes").addEventListener("click",e=>{
  const t=e.target.closest(".mtype"); if(!t)return;
  MTYPE=t.dataset.t; MOFF=0; loadMaps();
});
el("mpage").addEventListener("click",e=>{
  if(e.target.closest(".mprev")){MOFF=Math.max(0,MOFF-MLIM);loadMaps();}
  else if(e.target.closest(".mnext")){MOFF=MOFF+MLIM;loadMaps();}
});
el("mbody").addEventListener("click",async e=>{
  const add=e.target.closest(".addn");
  if(!add)return;
  const key=add.closest("tr").dataset.key;
  const text=prompt("Comment on this mapping");
  if(text===null)return;
  await fetch("/api/mapnote",{method:"POST",
    body:JSON.stringify({key,text})});
  loadMaps();
});
el("mq").addEventListener("input",()=>{clearTimeout(MAPQ);
  MOFF=0;   // a filtered list is a different list; carrying an offset over it
  MAPQ=setTimeout(loadMaps,180);});
el("mx").onclick=()=>el("mveil").classList.remove("on");
el("mveil").onclick=e=>{if(e.target.id==="mveil")el("mveil").classList.remove("on");};

addEventListener("keydown",e=>{
  if(el("mveil").classList.contains("on")){
    if(e.key==="Escape") el("mveil").classList.remove("on");
    return;
  }
  if(el("app").style.display==="none")return;
  // Cmd/Ctrl+Shift+F jumps to the search box from anywhere, including from
  // inside another field -- so it is checked BEFORE the input bail-out and
  // before modifiers are rejected.
  if((e.metaKey||e.ctrlKey)&&e.shiftKey&&(e.key==="F"||e.key==="f")){
    e.preventDefault();
    if(el("body").classList.contains("narrow")) toggleSide();
    const box=el("q"); box.focus(); box.select();
    return;
  }
  if(e.target.tagName==="INPUT"||e.target.tagName==="SELECT"){
    if(e.key==="Escape") e.target.blur();
    return;
  }
  if(e.metaKey||e.ctrlKey||e.altKey)return;
  const k=e.key, kl=k.toLowerCase();
  if(kl==="j"||k==="ArrowDown"||k===" "){e.preventDefault();go(1);}
  else if(kl==="k"||k==="ArrowUp"){e.preventDefault();go(-1);}
  else if(k==="ArrowRight"){e.preventDefault();stepFolder(1);}
  else if(k==="ArrowLeft"){e.preventDefault();stepFolder(-1);}
  else if(k==="]"){e.preventDefault();step_page(1);}
  else if(k==="["){e.preventDefault();step_page(-1);}
  else if(k==="Enter"){e.preventDefault();reviewNext();}
  else if(k==="R"){e.preventDefault();reviewFolder();}
  else if(kl==="r"){e.preventDefault();toggleReview();}
  else if(kl==="c"){e.preventDefault();el("cbox").focus();}
  else if(kl==="s"){e.preventDefault();toggleSide();}
  else if(kl==="i"){e.preventDefault();toggleInfo();}
  else if(kl==="m"){e.preventDefault();maps();}
  else if(kl==="h"){e.preventDefault();HILITE=!HILITE;
    PIISID=null; hilLabel(); render();}
  else if(kl==="y"){e.preventDefault();SYNC=!SYNC;el("syn").textContent=SYNC?"sync on":"sync off";}
  else if(kl==="a"){e.preventDefault();onlyNew=!onlyNew;
    el("mode").textContent=onlyNew?"unreviewed only":"all files";build();list();render();}
  else if(kl==="e"){e.preventDefault();el("app").style.display="none";
    el("veil").classList.add("on");note("");if(!twoWay&&el("root").value.trim())inspect();}
  else if(k==="/"){e.preventDefault();el("q").focus();}
  else if(k==="?"){e.preventDefault();alert(
   "Move\\n  j / down      next file\\n  k / up        previous file\\n"+
   "  right / left  next / previous folder\\n  ] / [         both panes one page\\n\\n"+
   "Mark\\n  r             reviewed on or off\\n  c             add a comment\\n\\n"+
   "View\\n  a             all files / unreviewed only\\n  s             show or hide the list\\n"+
   "  y             scroll sync on or off\\n  /  or  \u2318\u21e7F   search\\n  e             change what is compared\\n\\n"+
   "Check\\n  n             what every folder name became\\n  m             the run\u2019s PII mappings\\n"+
   "  i             details for this document");}
});

/* Resizing the list. Written to the grid variable live so the panes reflow as
   you drag, and remembered per browser. */
(function(){
  const g=el("grip"), bd=el("body");
  const SW="glasswaller.sidewidth";
  const set=w=>{w=Math.max(170,Math.min(760,Math.round(w)));
    bd.style.setProperty("--sw",w+"px"); return w;};
  const saved=parseInt(localStorage.getItem(SW)||"",10);
  if(saved) set(saved);
  let on=false, x0=0, W=saved||250;
  g.addEventListener("mousedown",e=>{on=true;x0=bd.getBoundingClientRect().left;
    g.classList.add("on");document.body.classList.add("rz");e.preventDefault();});
  // The rect is read once per drag, not per mousemove: reading it in the move
  // handler forces a synchronous layout of a pane holding thousands of rows.
  addEventListener("mousemove",e=>{if(on) W=set(e.clientX-x0);});
  addEventListener("mouseup",()=>{if(!on)return;on=false;g.classList.remove("on");
    document.body.classList.remove("rz");localStorage.setItem(SW,W);});
  // Double-click fits the widest name currently listed.
  g.addEventListener("dblclick",()=>{
    const w=Math.max(...[...document.querySelectorAll("#list .file .t")]
      .map(n=>n.scrollWidth+96), 250);
    W=set(w); localStorage.setItem(SW,W);});
})();

fetch("/api/boot").then(r=>r.json()).then(b=>{
  CAN=!!b.render;
  const box=el("recent"); box.innerHTML="";
  (b.recent||[]).slice(0,3).forEach(v=>{const d=document.createElement("div");
    d.className="recent";d.textContent="↩ "+v;
    d.onclick=()=>{el("root").value=v;syncProf();inspect();};box.appendChild(d);});
  if(b.ready){ start(b); } else el("root").focus();
});
</script></body></html>"""


def _sides(root, left, right, profile, source, output):
    """Resolve the request into (left_store, right_store, filters)."""
    if left and right and left == right:
        # --single points both halves at one tree. Opening it twice builds two
        # Stores, lists it twice (paths is a per-instance cached_property), and
        # runs find_variants twice -- which on a tree carrying both raw/ and
        # files/ fails with "pick the two halves there" for a review that has
        # only one half by definition.
        st = stores.open_store(resolve_root(left), profile)
        return st, st, {}
    if root:
        # A location pasted from the console usually points at the output
        # half. Both halves are one level up.
        st = stores.open_store(resolve_root(root), profile)
        # One location: both halves live inside it, told apart by folder name.
        # An empty source means "everything that is not the output", which is
        # the shape of an in-place run (the tree is the source, _pii/output is
        # the result).
        return st, st, {
            "left_only": source or None,
            "right_only": output or None,
            "left_exclude": None if source else (output or None),
        }
    ls, rs = stores.open_store(left, profile), stores.open_store(right, profile)
    # With two explicit locations there is no selector to disambiguate, so a
    # side that holds the same documents twice (a download carrying both
    # "raw/" and "files/") would pair each source against its own sibling.
    # Say so rather than returning a confident, wrong index.
    for side, st in (("source", ls), ("output", rs)):
        dup = pairing.find_variants(st.docs, set(pairing.DEFAULT_IGNORE))
        if len(dup) > 1:
            names = ", ".join(f"{k}/ ({v})" for k, v in sorted(dup.items(), key=lambda t: -t[1]))
            raise ValueError(
                f"the {side} holds more than one copy of each document ({names}). "
                f"Point at one location instead and pick the two halves there, "
                f"or give a more specific path."
            )
    return ls, rs, {}


def resolve_root(spec: str) -> str:
    """Canonical location for a single-location request.

    Order matters and cost a debugging round: a console URL carries the run's
    depth in ``?prefix=``, not in its path, so climbing out of the output half
    has to happen AFTER the URL is turned into an s3:// URI. Climbing first
    silently did nothing, and the review opened on the output half alone.
    """
    s3 = stores.parse_s3(spec)
    return pairing.run_root(s3[0] if s3 else (spec or "").strip())


def inspect_root(root: str, profile: str | None) -> dict:
    """What the two halves inside one location look like."""
    root = resolve_root(root)
    st = stores.open_store(root, profile)
    # Deliberately the RAW listing, not ``docs``: an in-place run puts its
    # output under ``_pii/output``, which the document filter drops. It has to
    # be visible here or it could never be chosen as a side.
    paths = [p for p in st._list() if "__MACOSX" not in p]
    if not paths:
        return {"error": f"nothing found in {root}"}
    out = pairing.autosplit(paths)
    # Hand back what was actually opened. The popup writes this into the
    # location box, so a pasted console URL visibly becomes the s3:// URI the
    # recents list and marks.json will be keyed by -- one run, one entry.
    out["root"] = st.spec
    return out


#: Rows one search returns. A substring like "page" matches thirty thousand
#: files and the reviewer wants the handful they were sent, so the list is
#: bounded and the true count reported alongside it.
SEARCH_MAX = 300

#: Pairs kept per app folder. Nobody reviews an export end to end -- the job
#: is a few files per app and a search for the handful somebody reported -- and
#: a list of 121,538 is one nobody can navigate.
PER_APP = 100


#: Where this laptop's sampling salt lives. In the home directory rather than
#: beside the code, so it survives re-cloning the repo and stays one identity
#: per machine rather than one per checkout.
SALT_FILE = Path.home() / ".glasswaller-salt"


def reviewer_salt(override: str | None = None) -> str:
    """A value unique to this machine, stable forever, used to pick the sample.

    Two people reviewing the same run should not both spend their afternoon on
    the same hundred documents -- between them they should cover two hundred.
    Seeding the sample on something per-machine gets that for free, with no
    coordination, no server, and nobody assigning work.

    Written down rather than derived from the hostname, because it has to
    survive a rename and a re-clone: the whole point is that a refresh, a
    restart or a fresh checkout puts the SAME files back in front of the same
    person. Verdicts are keyed by path, and a sample that moved would strand
    yesterday's review.
    """
    if override:
        return override.strip()
    try:
        got = SALT_FILE.read_text().strip()
        if got:
            return got
    except OSError:
        pass
    made = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    try:
        SALT_FILE.write_text(made + "\n")
        SALT_FILE.chmod(0o600)
    except OSError:  # noqa: BLE001 -- read-only home; the sample is then per-run
        pass
    return made


def _thin(rows, per_app: int, salt: str = ""):
    """At most ``per_app`` pairs per app folder, chosen at random.

    Per app, not per run: a single budget spent top-down would go entirely to
    whichever app sorts first and show none of the rest.

    Random rather than the first N, because S3 hands back keys in sort order,
    so the head of the list is always page_000001 of whoever sorts first --
    the same corner of the same export every time, with whole categories of
    defect never on screen.

    Seeded on the app name AND this machine's salt, so the same run thins to
    the same files every time it is opened here, and to a different hundred on
    a colleague's laptop. Verdicts in marks.json are keyed by path, and a
    sample that reshuffled on reopen would strand yesterday's review against
    files nobody can see today.
    """
    if not per_app:
        return rows, {}
    by_app: dict[str, list] = {}
    for r in rows:
        by_app.setdefault(r["label"].split("/")[0], []).append(r)
    kept, dropped = [], {}
    for app, group in by_app.items():
        if len(group) <= per_app:
            kept += group
            continue
        dropped[app] = len(group) - per_app
        kept += random.Random(f"{salt}\x00{app}").sample(group, per_app)
    kept.sort(key=lambda r: r["label"])
    return kept, dropped


def _kept_names(left: str, right: str | None, ign: set) -> list[str]:
    """Folder names this document sits under that survived into the output
    unchanged AND read as somebody's personal data.

    Per document rather than per folder, so the warning lands on the screen
    the reviewer is already looking at instead of only in the audit panel.
    """
    if not right:
        return []
    ln = pairing.normalise(left, ign)[:-1]
    rn = pairing.normalise(right, ign)[:-1]
    if len(ln) != len(rn):
        return []
    return [a for a, b in zip(ln, rn) if a == b and pairing.looks_personal(a)]


def open_review(root=None, left=None, right=None, profile=None,
                source=None, output=None, ignore=None, label=None, drop=None,
                per_app: int = PER_APP, mappings: str | None = None,
                seed: str | None = None, solo: bool = False,
                solo_label: str = "Transformed") -> dict:
    ls, rs, filt = _sides(root, left, right, profile, source, output)
    ign = {s.strip().lower() for s in (ignore or pairing.DEFAULT_IGNORE) if s.strip()}
    ign |= {s.lower() for s in (source, output) if s}

    idx = pairing.build(ls, rs, ignore=ignore, drop_globs=drop, **filt)

    def _bytes(store, key):
        try:
            return store.size(key) if key else 0
        except Exception:  # noqa: BLE001
            return 0

    rows = [
        {"id": n, "left": p["left"], "right": p["right"], "how": p["how"],
         # Off the listing, which already carried it -- no extra call. What a
         # folder weighs is how you tell a mailbox from a drive full of
         # scanned PDFs, and it is the difference between "100 files" meaning
         # ten minutes and meaning an afternoon.
         "lb": _bytes(ls, p["left"]), "rb": _bytes(rs, p["right"]),
         "label": "/".join(pairing.normalise(p["left"], ign))}
        for n, p in enumerate(idx["pairs"])
    ]
    # "Missing" is only meaningful when both halves were listed WHOLE. The
    # listing stops after a bounded number of pages, so on a large export a
    # counterpart can be absent from the index and present in the bucket --
    # and a row saying "nothing in the output for this document" is then a
    # false alarm about the pipeline, which is the most expensive kind of
    # wrong this tool can be. Where the walk was truncated, say nothing rather
    # than something untrue.
    partial = bool(getattr(ls, "capped", False) or getattr(rs, "capped", False))
    if not partial:
        for lp in idx["unmatched_left"]:
            rows.append({"id": len(rows), "left": lp, "right": None, "how": "missing",
                         "lb": _bytes(ls, lp), "rb": 0,
                         "label": "/".join(pairing.normalise(lp, ign))})
    # The folder NAMES are half the deliverable and appear in neither pane.
    # ``gmail/anirudh.trivedi@inc42.com/messages/page_000001.jsonl`` names a
    # person and their employer in the object key, whatever the documents
    # under it look like, so the source-to-output correspondence is worked out
    # once here and audited in its own panel.
    for r in rows:
        # In single mode left IS right, so every personal-looking segment reads
        # as "unchanged in the output" and the tool's own leak hint fires on
        # every document. There is no output half to have changed it: say
        # nothing rather than something untrue.
        r["kept"] = [] if solo else _kept_names(r["left"], r["right"], ign)

    rows.sort(key=lambda r: r["label"])
    # Numbered over EVERY pair, before the sample is taken, and the whole set
    # is kept. An id that meant "the nth row you were sent" made the documents
    # outside the sample unopenable -- there was no id that named them -- so a
    # search could find a reported file and then not show it. Numbering first
    # costs nothing and makes every pair in the run addressable.
    for n, r in enumerate(rows):
        r["id"] = n
    salt = reviewer_salt(seed)
    every = rows
    rows, thinned = _thin(rows, per_app, salt)
    shown = {r["id"] for r in rows}
    for r in every:
        r["sampled"] = r["id"] in shown

    lname = f"{ls}::{source or ''}"
    rname = f"{rs}::{output or ''}"
    sid = session_id(lname, rname)
    all_marks = _read_json(MARKS, {})
    marks = _migrate(all_marks.setdefault(sid, {}))
    all_marks[sid] = marks

    map_spec, map_store, map_inner = mappings, None, None
    if not map_spec:
        inner = find_mappings(rs)
        if inner:
            map_spec, map_store, map_inner = f"{rs}/{inner}", rs, inner

    reset_derived()          # a new review is a new run; nothing carries over
    with _LOCK:
        S.update(ready=True, rows=every, sample=rows,
                 left_store=ls, right_store=rs,
                 profile=profile, sample_salt=salt,
                 map_spec=map_spec, map_store=map_store,
                 map_inner=map_inner,
                 sid=sid, all_marks=all_marks, marks=marks,
                 left=f"{ls}{'/' + source if source else ''}",
                 right=f"{rs}{'/' + output if output else ''}")

    if root or left:
        # ``ls.spec`` not ``root``: the store holds the canonical s3:// form,
        # so a console URL and the URI for the same run make one recents entry
        # instead of two.
        spec = ls.spec if root else left
        recent = _read_json(RECENT, [])
        recent = [spec] + [x for x in recent if x != spec]
        _write_json(RECENT, recent[:10])

    counts = dict(idx["counts"])
    counts["by_how"] = dict(counts["by_how"])
    counts["by_how"]["missing"] = 0 if partial else len(idx["unmatched_left"])
    counts["partial"] = partial
    print(f"  {len(rows)} documents  {counts['by_how']}", flush=True)
    if idx["unmatched_right"]:
        print(f"  {len(idx['unmatched_right'])} output file(s) with no source", flush=True)

    # Reported, never silent. A bucket can hold several runs' worth of export,
    # and the documents belonging to the OTHER ones are not findings -- but
    # "your location covers more than this run" is worth a line, and hiding
    # rows without saying so would be worse than the noise it removes.
    if thinned:
        named = ", ".join(f"{a}/ ({n} more)" for a, n in
                          sorted(thinned.items(), key=lambda t: -t[1])[:4])
        print(f"  showing {per_app} per app (sample {salt[:6]}) — "
              f"not shown: {named}", flush=True)

    units = {} if partial else (idx.get("out_of_scope_units") or {})
    scope_note = None
    if units:
        ranked = sorted(units.items(), key=lambda t: -t[1])
        total = sum(units.values())
        # One branch is the common case and reads better without its own
        # count repeated back at you; several need the breakdown.
        named = ranked[0][0] + "/" if len(ranked) == 1 else \
            ", ".join(f"{u}/ ({n})" for u, n in ranked[:3])
        more = "" if len(ranked) <= 3 else f" and {len(ranked) - 3} more"
        scope_note = (f"{total:,} document(s) under {named}{more} have no output at "
                      f"all, so this run did not cover them and they are not "
                      f"listed. Point at that location directly to review it.")
        # Console only. As a page banner this sat above every screen for the
        # whole session restating a fact the file list already shows -- the
        # uncovered units are not listed -- so it read as an unfixable warning
        # about a healthy run. Logged once at startup instead.
        print(f"  {scope_note}", flush=True)

    # Safety net. If almost nothing paired, the split is almost certainly
    # wrong — and the reviewer has no way to tell that from a screen of
    # "nothing in the output", which looks exactly like a pipeline that
    # dropped everything. So check whether another folder would do better and
    # offer it, rather than letting a wrong choice read as a catastrophic run.
    hint = None
    missing = 0 if partial else len(idx["unmatched_left"])
    if root and rows and missing and missing / len(rows) > 0.5:
        guess = pairing.autosplit([p for p in ls.paths if "__MACOSX" not in p])
        # Never offer a folder that the SOURCE is made of. On the run this was
        # written against the banner said "jira/ holds far more — that is
        # probably the output folder", and jira/ was the source: taking the
        # advice would have compared the run against itself. A folder every
        # source path already sits under cannot be the other half.
        srcseg = {seg.lower() for p in ls.docs for seg in pairing.segments(p)[:-1]}
        outseg = {seg.lower() for p in rs.docs for seg in pairing.segments(p)[:-1]}
        better = [o for o in guess["options"]
                  if o["name"] not in (source, output) and o["files"] > missing * 0.5
                  and not (o["name"].lower() in srcseg and o["name"].lower() not in outseg)]
        if better:
            alt = max(better, key=lambda o: o["files"])["name"]
            hint = {"output": alt,
                    "text": (f"{missing} of {len(rows)} documents have no counterpart in "
                             f"{output or 'the output'}/. {alt}/ holds far more — "
                             f"that is probably the output folder.")}

    def short(store, folder):
        # The header had the whole absolute path in it, which is the one part
        # of the screen that never changes and the least worth reading.
        return folder or Path(str(store).split(":", 1)[-1].rstrip("/")).name or str(store)

    session = {"pairs": rows, "marks": marks, "counts": counts,
               "solo": bool(solo), "solo_label": solo_label,
               "total": len(every),
               "left": S["left"], "right": S["right"], "hint": hint,
               "thinned": thinned, "partial": partial, "per_app": per_app,
               "sample": salt[:6],
               "has_map": bool(map_spec),
               # Enough for the header to say whether the panel is worth
               # opening. The rows themselves come on demand.
               "left_short": short(ls, source), "right_short": short(rs, output),
               "source": source, "output": output, "root": root,
               # What the browser tab is named. Two tabs on two batches are
               # otherwise identical, which is how a reviewer ends up reading
               # the wrong day's output.
               "label": (label or "").strip()}
    with _LOCK:
        S["session"] = session
    return session


def native_picker() -> dict:
    """Ask macOS for a folder or file. Falls back to a clear message."""
    import subprocess

    script = (
        'try\n'
        '  set f to choose folder with prompt "Pick the run to review"\n'
        '  return POSIX path of f\n'
        'on error number -128\n'
        '  return ""\n'
        'end try'
    )
    try:
        out = subprocess.run(["osascript", "-e", script],
                             capture_output=True, timeout=180)
    except FileNotFoundError:
        return {"error": "no native picker here — paste the path instead"}
    except subprocess.TimeoutExpired:
        return {"error": "picker timed out"}
    if out.returncode != 0:
        return {"error": out.stderr.decode()[:200] or "picker failed"}
    return {"path": out.stdout.decode().strip().rstrip("/")}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype: str, code: int = 200, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(json.dumps(obj).encode(), "application/json", code)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(PAGE.encode(), "text/html; charset=utf-8")
        if path == "/api/boot":
            out = {"recent": _read_json(RECENT, []),
                   "ready": S.get("ready", False),
                   "left": S.get("left", ""), "right": S.get("right", "")}
            if S.get("ready"):
                # The full session, not just the pairs. Returning less meant a
                # page reload came back with no idea what it was comparing:
                # the panes read "Source · source" and the split chip showed a
                # question mark.
                out.update(S.get("session", {}))
            out["render"] = RENDER.available
            return self._json(out)
        if path == "/api/search":
            # Across every pair, not the sample. The sample is what you review
            # by default; a search is what you do when somebody reports a file
            # by name, and answering that from a hundred rows per app would
            # miss it 99 times in 100.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            look = (q.get("q") or [""])[0].strip().lower()
            rows = S.get("rows") or []
            if not look:
                return self._json({"rows": [], "matched": 0, "total": len(rows)})
            hit = [r for r in rows
                   if look in r["label"].lower()
                   or look in (r["right"] or "").lower()
                   or look in r["left"].lower()]
            return self._json({"rows": hit[:SEARCH_MAX], "matched": len(hit),
                               "total": len(rows), "cap": SEARCH_MAX})
        if path == "/api/pii":
            # Scoped to ONE document -- see pii_index for why a run-wide list
            # cannot work. Without a sid there is nothing to intersect against,
            # so there is nothing to mark yet.
            src = S.get("map_spec")
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            sid = (q.get("sid") or [""])[0].strip()
            blank = {"orig": [], "repl": [], "leak": []}
            if not sid:
                return self._json(blank)
            try:
                row = S["rows"][int(sid)]
                # Per user, not per run -- see resolve_map.
                user = (row.get("label") or "").split("/")[0]
                lt = rt = ""
                if row["left"]:
                    lt = _doc_text("left", sid, row["left"], S["left_store"])
                if row["right"]:
                    rt = _doc_text("right", sid, row["right"], S["right_store"])
                # No mapping table for this user -- derive the marks from the
                # two panes instead. Highlighting is the whole point of the
                # tool, so it degrades rather than switching off.
                spec = resolve_map(src, S.get("profile"), user) if src else None
                if not spec:
                    warm_derived(user)
                    return self._json(derive_pii(user, sid, lt, rt))
                inner = S.get("map_inner") if spec == src else None
                store = S.get("map_store") if spec == src else None
                idx = pii_index(spec, S.get("profile"), store, inner)
            except Exception as exc:  # noqa: BLE001 -- surfaced on the card
                return self._json(dict(blank, error=f"{type(exc).__name__}: {exc}"[:200]))
            # A solo review pairs a tree with itself and can be either half of
            # a run, so each side falls back to the other and mark() lets the
            # colours say which it was looking at.
            return self._json({
                "orig": pii_for(idx, "orig", lt or rt),
                "repl": pii_for(idx, "repl", rt or lt),
                "leak": pii_for(idx, "leak", lt + "\n" + rt),
                "total": idx["count"],
                "user": user,
                "db": spec,
            })
        if path == "/api/mappings":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                src = S.get("map_spec")
                if not src:
                    return self._json({"error": "no mapping database for this run"})
                out = read_mappings(src, S.get("profile"),
                                    S.get("map_store"), S.get("map_inner"))
            except Exception as exc:  # noqa: BLE001 -- shown in the panel
                return self._json({"error": f"{type(exc).__name__}: {exc}"[:200]})

            def one(name, cast, default):
                raw = (q.get(name) or [""])[0].strip()
                try:
                    return cast(raw) if raw else default
                except ValueError:
                    return default

            page = browse_mappings(out["rows"],
                                   kind=(q.get("type") or [""])[0].strip() or None,
                                   look=(q.get("q") or [""])[0],
                                   offset=one("offset", int, 0),
                                   limit=min(one("limit", int, PAGE_ROWS), 1000))
            notes = _read_json(NOTES, {}).get(out["path"], {})
            for r in page["rows"]:
                r["key"] = map_key(r)
                r["notes"] = notes.get(r["key"], [])
            page.update(path=out["path"], count=out["count"])
            return self._json(page)
        if path.startswith("/api/metrics/"):
            try:
                return self._json(metrics(path.rsplit("/", 1)[1]))
            except Exception as exc:  # noqa: BLE001 -- advisory panel
                return self._json({"error": f"{type(exc).__name__}: {exc}"})
        if path.startswith("/api/doc/"):
            try:
                _, _, _, side, sid = path.split("/", 4)
                row = S["rows"][int(sid)]
                key = row["left"] if side == "left" else row["right"]
                if key is None:
                    return self._json({"kind": "none"})
                store = S["left_store"] if side == "left" else S["right_store"]
                data = store.cached_read(key)
                shape = view(key, data)
                if shape["kind"] == "pdf":
                    if not RENDER.available:
                        # The one type the browser really does display in a
                        # frame. Kept on the iframe route deliberately: without
                        # PyMuPDF the plugin viewer is the only way to read a
                        # PDF here, and it shows rather than saves.
                        return self._json({"kind": "raw"})
                    return self._json({"kind": "pdf",
                                       "pages": RENDER.pages(f"{side}:{sid}", data)})
                return self._json(shape)
            except Exception as exc:  # noqa: BLE001 -- surfaced on the card
                return self._json({"kind": "other",
                                   "why": f"{type(exc).__name__}: {exc}"[:200]})
        if path.startswith("/page/"):
            try:
                _, _, side, sid, n = path.split("/", 4)
                row = S["rows"][int(sid)]
                key = row["left"] if side == "left" else row["right"]
                store = S["left_store"] if side == "left" else S["right_store"]
                png = RENDER.page_png(f"{side}:{sid}", store.cached_read(key),
                                      int(n.split(".")[0]))
                return self._send(png, "image/png")
            except Exception as exc:  # noqa: BLE001
                return self._send(str(exc).encode()[:300], "text/plain", 404)
        if path.startswith("/doc/"):
            try:
                _, _, side, sid = path.split("/", 3)
                row = S["rows"][int(sid)]
                key = row["left"] if side == "left" else row["right"]
                if key is None:
                    return self._send(b"no counterpart", "text/plain", 404)
                store = S["left_store"] if side == "left" else S["right_store"]
                data = store.cached_read(key)
                # Warm the next document while this one is on screen. On an
                # s3:// side each read is a round trip, and a reviewer moving
                # at one document every few seconds would feel every one.
                nxt = S["rows"][int(sid) + 1] if int(sid) + 1 < len(S["rows"]) else None
                if nxt:
                    nkey = nxt["left"] if side == "left" else nxt["right"]
                    if nkey:
                        store.prefetch(nkey)
            except Exception as exc:  # noqa: BLE001
                return self._send(str(exc).encode()[:400], "text/plain", 404)
            name = Path(key).name
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            # Anything textual is served as text/plain. A browser SAVES
            # text/csv, which is the download dialog this route used to pop.
            if ctype.startswith("text/") and not ctype.startswith("text/html"):
                ctype = "text/plain; charset=utf-8"
            # HTTP headers are latin-1. A macOS screenshot is named with a
            # narrow no-break space (U+202F) and crashed send_header mid
            # response, so the browser got an empty reply and the pane went
            # blank with no error anywhere the reviewer could see. Send an
            # ASCII-safe name plus the real one per RFC 5987.
            ascii_name = name.encode("ascii", "replace").decode("ascii").replace('"', "'")
            quoted = urllib.parse.quote(name, safe="")
            return self._send(data, ctype, 200, extra=[(
                "Content-Disposition",
                f"inline; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted}",
            )])
        self._send(b"not found", "text/plain", 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if path == "/api/browse":
            return self._json(native_picker())
        if path == "/api/inspect":
            try:
                return self._json(inspect_root(
                    (body.get("root") or "").strip(),
                    (body.get("profile") or "").strip() or None))
            except Exception as exc:  # noqa: BLE001 -- surfaced in the popup
                return self._json({"error": f"{type(exc).__name__}: {exc}"})
        if path == "/api/open":
            try:
                return self._json(open_review(
                    root=(body.get("root") or "").strip() or None,
                    left=(body.get("left") or "").strip() or None,
                    right=(body.get("right") or "").strip() or None,
                    profile=(body.get("profile") or "").strip() or None,
                    source=(body.get("source") or "").strip() or None,
                    output=(body.get("output") or "").strip() or None,
                    label=(body.get("label") or "").strip() or None,
                    mappings=(body.get("mappings") or "").strip() or None,
                    seed=(body.get("seed") or "").strip() or None,
                ))
            except Exception as exc:  # noqa: BLE001 -- surfaced in the popup
                return self._json({"error": f"{type(exc).__name__}: {exc}"})
        if path == "/api/usemap":
            # The run did not ship a database, which is the common case: it is
            # written beside the pipeline and often never uploaded. Without
            # this the only way to see the mappings was a command-line flag,
            # so a reviewer running ./runs i1 had no route to them at all and
            # the panel was simply a dead button.
            spec = (body.get("spec") or "").strip()
            if not spec:
                return self._json({"error": "give a path or an s3:// URI"})
            try:
                out = read_mappings(spec, S.get("profile"))
            except Exception as exc:  # noqa: BLE001 -- shown in the panel
                return self._json({"error": f"{type(exc).__name__}: {exc}"[:200]})
            with _LOCK:
                S["map_spec"] = spec
                S["map_store"] = None
                S["map_inner"] = None
                if S.get("session"):
                    S["session"]["has_map"] = True
            return self._json({"ok": True, "count": out["count"]})
        if path == "/api/mapnote":
            key, text = body.get("key"), (body.get("text") or "").strip()
            src = S.get("map_spec")
            if not (src and key):
                return self._json({"error": "no mapping"}, 400)
            with _LOCK:
                all_notes = _read_json(NOTES, {})
                per = all_notes.setdefault(src, {})
                got = per.setdefault(key, [])
                if text:
                    got.append(text)
                elif got:
                    # An empty body removes the last one, which is the whole
                    # of "undo" here. No editing, no history -- a comment on a
                    # substitution is a note to a colleague, not a record.
                    got.pop()
                if not got:
                    per.pop(key, None)
                _write_json(NOTES, all_notes)
            return self._json({"notes": got})
        if path == "/api/mark":
            if not S.get("ready"):
                return self._json({"error": "no session"}, 409)
            k, r = body.get("key"), body.get("rec") or {}
            rec = {"viewed": bool(r.get("viewed")),
                   "reviewed": bool(r.get("reviewed")),
                   "comments": [c for c in (r.get("comments") or []) if str(c).strip()]}
            with _LOCK:
                if rec["viewed"] or rec["reviewed"] or rec["comments"]:
                    S["marks"][k] = rec
                else:
                    S["marks"].pop(k, None)
                _write_json(MARKS, S["all_marks"])
            return self._json({})
        self._json({"error": "not found"}, 404)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _name_for(spec: str) -> str:
    """A short, distinguishable tab name for a location."""
    return Path(str(spec).rstrip("/")).name or str(spec)


def plan(a) -> list[dict]:
    """Every review the arguments ask for, in the order they were given.

    One is the ordinary case and runs in this process; more than one fans out
    to a server each. Kept separate from ``main`` so the collecting can be
    tested without starting anything.
    """
    jobs = [{"root": r, "label": a.label or _name_for(r)} for r in (a.root or [])]
    jobs += [{"left": l, "right": r,
              "label": a.label or f"{_name_for(l)} → {_name_for(r)}"}
             for l, r in (a.pair or [])]
    if a.left and a.right:
        jobs.append({"left": a.left, "right": a.right,
                     "label": a.label or f"{_name_for(a.left)} → {_name_for(a.right)}"})
    return jobs


def _fan_out(jobs, a) -> int:
    """One review per location, each its own server, all opened at once.

    Comparing runs means having them side by side, and this tool holds one
    session per process -- the index, the marks and the render cache are all
    per-server state. Rather than teach every one of those to be
    multi-tenant, run one server per review and hand back the list of URLs.
    They are independent: marks.json is already keyed by the pair of
    locations, so three tabs cannot overwrite each other's verdicts.
    """
    import atexit
    import signal

    import tempfile

    kids, urls, logs = [], [], []
    for n, job in enumerate(jobs):
        port = a.port + n
        cmd = [sys.executable, str(Path(__file__).resolve()),
               "--port", str(port), "--no-open"]
        if job.get("root"):
            cmd.append(job["root"])
        else:
            cmd += ["--left", job["left"], "--right", job["right"]]
        # seed and mappings belong here too, or a fan-out of three reviews
        # would sample each one off this machine's own salt while the single
        # -review path honoured --seed. Same command, two behaviours.
        for flag in ("profile", "source", "output", "mappings", "seed"):
            if getattr(a, flag, None):
                cmd += [f"--{flag}", getattr(a, flag)]
        # Repeatable, so it cannot ride the loop above -- forwarding only the
        # first glob would silently half-apply the filter in a fan-out.
        for g in (getattr(a, "drop", None) or []):
            cmd += ["--drop", g]
        cmd += ["--label", job["label"]]
        # Each child's chatter goes to its own file rather than the shared
        # terminal. Three reviews indexing at once interleaved into an
        # unreadable braid, and the one thing a person needs from this command
        # is a clean list of URLs. A file, not a pipe: nobody is draining
        # these while they run, and a full pipe buffer would wedge the child.
        log = tempfile.NamedTemporaryFile(prefix="glasswaller-", suffix=".log",
                                          delete=False)
        kids.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        logs.append(log.name)
        urls.append((job["label"], f"http://127.0.0.1:{port}/"))

    def stop(*_):
        for k in kids:
            if k.poll() is None:
                k.terminate()
        for f in logs:
            try:
                Path(f).unlink()
            except OSError:
                pass
    atexit.register(stop)
    signal.signal(signal.SIGTERM, lambda *_: (stop(), sys.exit(0)))

    # Indexing is a network walk per review, so they are told to be quiet and
    # the tabs open once each one actually answers. Opening first gave three
    # connection-refused pages, which reads as "the tool is broken".
    print(f"\n  starting {len(jobs)} reviews — this takes a moment each\n", flush=True)
    for (label, url), kid in zip(urls, kids):
        ready, waited = False, 0.0
        # Wait for as long as the child is alive rather than on a clock.
        # A fixed budget was wrong: indexing an S3 prefix is a paginated walk
        # of every key, which took minutes on the real runs, and a two-minute
        # cap reported "did not start" for reviews that were about to come up
        # perfectly. The child exiting is the only honest failure signal.
        while kid.poll() is None:
            try:
                urllib.request.urlopen(url, timeout=2).read(1)
                ready = True
                break
            except Exception:  # noqa: BLE001 -- still indexing
                time.sleep(1.0)
                waited += 1.0
                # Silence past half a minute reads as a hang, and the reason
                # it is slow (a large bucket) is worth naming.
                if waited % 30 == 0:
                    print(f"    …still indexing {label}  ({int(waited)}s)",
                          flush=True)
        if ready:
            print(f"    {url}   {label}", flush=True)
            if not a.no_open:
                webbrowser.open(url)
        else:
            # Silence is the wrong failure mode. Show why this one did not
            # come up, from its own log, instead of a bare "did not start".
            print(f"  ! {label} stopped before it was ready:", flush=True)
            why = Path(logs[urls.index((label, url))]).read_text()[-800:].strip()
            for line in (why or "it wrote nothing").splitlines()[-8:]:
                print(f"      {line}", flush=True)
    print("\n  Ctrl-C stops all of them.\n", flush=True)
    try:
        for k in kids:
            k.wait()
    except KeyboardInterrupt:
        stop()
        print("\nstopped. verdicts are in", MARKS, flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Side-by-side review of a redaction run.",
        epilog="Give several locations, or repeat --pair, to open several "
               "reviews at once — one browser tab each, on consecutive ports.")
    ap.add_argument("root", nargs="*",
                    help="folder, .zip or S3 location holding both halves. "
                         "Give more than one to open one review per location.")
    ap.add_argument("--pair", nargs=2, action="append", metavar=("SOURCE", "OUTPUT"),
                    help="a review whose two halves live apart. Repeatable.")
    ap.add_argument("--left", help="source, when the two halves live apart")
    ap.add_argument("--right", help="output, when the two halves live apart")
    ap.add_argument("--source", help="folder name of the source half inside root")
    ap.add_argument("--output", help="folder name of the output half inside root")
    ap.add_argument("--profile", help="AWS profile for S3 locations")
    ap.add_argument("--drop", action="append", metavar="GLOB",
                    help="drop paths matching GLOB from BOTH halves before "
                         "pairing. For artefacts a run never emits, so they "
                         "stop reading as missing output. Repeatable.")
    ap.add_argument("--label", help="what to call this batch in the tab title")
    ap.add_argument("--mappings", help="pii_mappings.db to inspect -- or the "
                                   "FOLDER/prefix holding one per user, for a "
                                   "multi-user run -- if the run did not ship "
                                   "one next to its output")
    ap.add_argument("--seed", help="sample to use instead of this machine's own. "
                                   "Pass a colleague's to review exactly what "
                                   "they are reviewing.")
    ap.add_argument("--single", metavar="LOCATION",
                    help="review ONE tree on its own -- no source half, one "
                         "pane. For eyeballing transformed/processed data "
                         "where there is nothing to compare it against.")
    ap.add_argument("--single-label", default="Transformed",
                    help="heading for the single pane (default: Transformed)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()

    # One tree, one pane. Pairing a location with ITSELF makes every document
    # match itself by exact name, so the index is one row per file and the
    # right pane has nothing to add -- which is what `solo` hides.
    if a.single:
        a.left = a.right = a.single
        a.label = a.label or _name_for(a.single)

    jobs = plan(a)
    if len(jobs) > 1:
        return _fan_out(jobs, a)

    a.root = a.root[0] if a.root else None
    if jobs and not a.root:
        a.left, a.right = jobs[0].get("left"), jobs[0].get("right")
    a.label = a.label or (jobs[0]["label"] if jobs else None)

    if a.root and not (a.source or a.output):
        guess = inspect_root(a.root, a.profile)
        if guess.get("error"):
            print("  " + guess["error"], flush=True)
            return
        a.source, a.output = guess["source"], guess["output"]
        opts = ", ".join(f"{o['name']}/ ({o['files']})" for o in guess["options"])
        print(f"  inside: {opts}", flush=True)
        print(f"  using source={a.source or 'everything else'}  output={a.output}", flush=True)
        if guess.get("warn"):
            print(f"  note: {guess['warn']}", flush=True)
    if a.root or (a.left and a.right):
        open_review(root=a.root, left=a.left, right=a.right, profile=a.profile,
                    label=a.label, mappings=a.mappings, seed=a.seed,
                    source=a.source, output=a.output, drop=a.drop,
                    solo=bool(a.single), solo_label=a.single_label)

    url = f"http://127.0.0.1:{a.port}/"
    print(f"\n  {url}\n", flush=True)
    if not a.no_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    with Server(("127.0.0.1", a.port), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped. verdicts are in", MARKS, flush=True)


if __name__ == "__main__":
    main()
