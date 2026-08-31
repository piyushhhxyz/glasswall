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

## Tests

```bash
pytest
```

## Note

`mapping.json` reverses the redaction. Keep it out of anything you share.

## License

MIT
