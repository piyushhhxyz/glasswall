# pii-redactor

Replaces PII in a `.docx` with consistent fake values, keeping the document's
formatting intact. The same real value always maps to the same fake one, so
the text still reads naturally and relationships between entities survive.

Detects names, organisations, addresses, emails, phone numbers, URLs, and
Indian identifiers (PAN, Aadhaar, CIN, DIN, GSTIN, passport, bank accounts).
Text inside embedded images is OCR'd and painted over too.

## Install

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e ".[ner]"   # adds a spaCy pass for names the rules miss
pip install -e ".[dev]"   # pytest
```

Requires Python 3.11+. Image OCR uses macOS Vision and is skipped elsewhere.

## Usage

```bash
redact input.docx -o output.docx
```

Writes the redacted file to `output.docx`, plus `mapping.json` (fake -> real)
and `detections.jsonl` (what was found where) into the audit directory.

### Options

| Flag | Meaning |
|---|---|
| `-o, --output` | Output path. Default `out/redacted.docx` |
| `--audit-dir` | Where `mapping.json` and `detections.jsonl` go. Default `out` |
| `--types` | Restrict to specific PII types. Default: all |
| `--keep-issuer` | Leave the issuing company's name intact |
| `--secret` | HMAC key — the same secret produces the same fake values |
| `--ner` | Add a spaCy pass for names the structural rules miss |
| `--no-images` | Skip OCR of embedded images |
| `-q, --quiet` | Suppress the summary |

### Example

```bash
redact report.docx -o clean.docx --secret my-key --types person org email
```

Same secret, same input → identical output, so runs are reproducible and
separate documents stay consistent with each other.

## Library

```python
from pii_redactor.pipeline import redact

result = redact("input.docx", "output.docx")
print(len(result.detections), "spans redacted")
```

## Verifying an S3 export (`pii-verify`)

The redactor works a file at a time. `pii-verify` is the other half: it points at
a **pair** of S3 prefixes — the original export and the redacted one — and answers
the question the redactor cannot answer about itself, *did anything survive?*

```bash
pip install -e ".[s3]"
cp .env.example .env      # fill in credentials and the two URIs
pii-verify serve          # opens http://127.0.0.1:8000
```

`.env` is gitignored. Standard `AWS_PROFILE` / instance credentials work too;
anything already in the environment wins over the file.

### What it shows

Browse the two trees as one merged listing. Every row is tagged `both`,
`renamed`, `orig only` or `redacted only`, so a file the redaction run never
wrote is visible without hunting for it. Pick a file and you get:

- **Side by side** — the original and the redacted text, line-aligned. PII found
  in the original is highlighted on the left; anything that *survived* is
  highlighted red on the right.
- **Leaks** — values detected in the original that still occur in the redacted
  file, ranked by severity. This is the only tab that represents a failure.
- **Structural** — matches set aside as machine noise, each with the reason.
- **All findings** — every detection on both sides, plus the surrogates the
  redactor introduced.

Objects are fetched capped (5 MiB by default, `MAX_OBJECT_BYTES`) with a ranged
GET, and listings are lazy — the reference export holds ~773k objects, so nothing
walks the tree.

### File types

Nothing is skipped outright. Every file lands in one of three tiers, so the
viewer always says *something* about both sides:

**1 — parsed to structured text**, which is what makes a diff readable:

| | |
|---|---|
| data | `.json` `.jsonl` `.ndjson` `.geojson` (re-indented), `.csv` `.tsv` (column-aligned), `.parquet`, `.xml` `.html` `.plist` (pretty-printed) |
| documents | `.docx` `.docm`, `.pdf`, `.xlsx` `.xlsm`, `.pptx` `.pptm`, `.odt` `.ods` `.odp`, `.rtf` |
| mail | `.eml`, `.mbox` — headers plus decoded text parts |
| archives | `.zip` `.apk` `.jar` `.tar` — member manifest, plus the text of small members |
| wrappers | `.gz` `.bz2` `.xz` — unwrapped, then dispatched on the name underneath, so `part.jsonl.gz` diffs as JSONL |
| databases | `.sqlite` `.db` — schema and row counts |
| images | `.png` `.jpg` `.webp` `.heic` `.svg` … — rendered side by side in the browser, and OCR'd where macOS Vision is available |
| plain text | ~50 code/config/subtitle/calendar extensions |

**2 — extracted strings.** A format with no parser here still gets its printable
runs pulled out and scanned. PII in an opaque container is still PII, and finding
an email in a `.doc` beats skipping the file.

**3 — byte identity.** For genuinely opaque content (`.mp4`, `.mp3`, fonts,
binaries) both sides report size and SHA-256, so "unchanged" is distinguishable
from "rewritten".

Extensions are a hint, not the decision: content is sniffed by magic bytes when
the name is missing or misleading. That matters here — hundreds of sampled objects
have no extension at all, and redaction renames files to things like
`report.some logistics corp`, whose "extension" is a surrogate company name.

The heavier parsers are optional (`pip install -e ".[formats]"` — pypdf,
openpyxl, python-pptx, pyarrow). Each is imported lazily; a missing one degrades
to tier 2 with a note naming the package, never an error.

### Leak, redacted, or surrogate

A redacted file is *supposed* to be full of things that look like PII: the
redactor replaces real values with realistic fakes. Scanning the output alone
therefore reports just as many hits as scanning the input and proves nothing.
What matters is whether an **original** value is still present, so every finding
lands in one of three buckets:

| | meaning |
|---|---|
| **leak** | detected in the original, still present in the output — a failure |
| **redacted** | detected in the original, gone from the output — the goal |
| **surrogate** | in the output only, never in the original — expected |

Comparison ignores whitespace entirely, because respacing is unpredictable in
both directions: `foo@bar. com` may be normalised to `foo@bar.com`, and a rewrap
can just as easily split a value that was intact.

Detections are shared with the redactor (`pii_redactor.detectors`), so the two
agree by construction. The gazetteer and spaCy passes are excluded: both build
their vocabulary from the document in front of them, which is unstable across a
before/after pair.

### Structural noise

Those detectors were tuned for prose in DOCX. Applied to Slack and API dumps the
same patterns fire on structure — `"ts": "1712128948.892889"` reads as an
address, an epoch-millisecond id satisfies Luhn and reads as a card number. Those
matches are moved to `ignored` with a reason and left out of the redaction rate,
never silently dropped (`suppress_noise=False` turns it off). The rules are
conservative: only numeric-shaped types are ever set aside, and never an email,
PAN, or labelled date of birth. See `pii_verifier/noise.py`.

### Renamed paths

Redaction rewrites path components, not just file contents, so the two sides do
not always share a key. Most components are untouched — schema folders like
`attachments/`, `boards/`, `comments/` keep their names — but two kinds do change:

- **identity folders**, e.g. `jira/person.one@example.com/` → `jira/surrogate.one@example.net/`
- **any component that trips a detector**, e.g. `versions/` → `Zephyr/`, where an
  ordinary schema name was replaced with a company surrogate

File names change the same way: `Screenshot 2026-06-22 at 4.04.30 PM.png` comes
out as `Screenshot 2668-06-22 …` (the year is surrogated as a date).

Such folders are paired automatically by **shape** — the set of exporter-generated
file names underneath (`page_000001.jsonl`, `part-00000.jsonl`), which hold no PII
and so survive. A pairing is only accepted when it is unambiguous: it must clear a
containment threshold, beat the runner-up by a margin, and share at least three
names. Rows paired this way are tagged `renamed` and the listing says so.

Where that is not enough it declines rather than guesses, and says why. The
`google_chat/` and `google_calendar/` prefixes hold ~420 renamed identity folders
per side that are all shaped identically (every user has
`messages/data/page_000001.jsonl`), so nothing in the bucket distinguishes them —
and the export carries no name mapping, only run telemetry under `_pii/`. For
those, type the two paths into the **orig** / **red** boxes above the tree and hit
`pair`; navigation and comparison then proceed across that pair.

### From the terminal

```bash
pii-verify check slack/general/2024-04-05.json        # exits 1 if anything leaked
pii-verify check slack/general/2024-04-05.json --json
```

The relative key is the part after the root prefix — the only name a before/after
pair has in common.

## Tests

```bash
pytest
```

## Note

`mapping.json` reverses the redaction. Keep it out of anything you share.

## License

MIT
