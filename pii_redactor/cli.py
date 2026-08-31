"""Command line entry point: `redact <input.docx> -o <output.docx>`."""

from __future__ import annotations

import argparse
from pathlib import Path

from .model import PiiType
from .pipeline import redact, write_audit
from .policy import Policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="redact", description="Replace PII in a DOCX with consistent fake alternatives.")
    p.add_argument("source", type=Path, help="input .docx")
    p.add_argument("-o", "--output", type=Path, default=Path("out/redacted.docx"))
    p.add_argument("--audit-dir", type=Path, default=Path("out"), help="where mapping.json and detections.jsonl go")
    p.add_argument("--types", nargs="*", choices=[t.value.lower() for t in PiiType],
                   help="restrict to these PII types (default: all)")
    p.add_argument("--keep-issuer", action="store_true", help="leave the issuing company's name intact")
    p.add_argument("--secret", default=None, help="HMAC key; same secret gives the same surrogates")
    p.add_argument("--ner", action="store_true", help="add a spaCy pass for names the structural cues miss")
    p.add_argument("--no-images", action="store_true",
                   help="skip OCR of embedded images (macOS Vision; on by default)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = Policy.from_names(args.types, redact_issuer=not args.keep_issuer)
    result = redact(
        args.source, args.output, policy=policy,
        secret=args.secret.encode() if args.secret else None,
        use_spacy=args.ner,
        redact_images=not args.no_images,
    )
    write_audit(result, args.audit_dir)

    if not args.quiet:
        persons, orgs = result.gazetteer_size
        print(f"gazetteer: {persons} persons, {orgs} organisations")
        print(f"redacted {len(result.detections)} spans -> {result.output}")
        for pii_type, count in result.counts().items():
            print(f"  {pii_type:<14}{count:>6}")
        if not args.no_images:
            if not result.ocr_available:
                print("images: OCR unavailable (needs macOS Vision) — images left untouched")
            else:
                print(f"images: {result.images_rewritten} rewritten, "
                      f"{len(result.image_findings)} regions redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
