"""Wire the stages together and emit the audit trail."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import PATTERN_DETECTORS, LiteralDetector, place_tokens
from .docx_io import Document, apply
from . import images as image_ocr
from .entities import GazetteerDetector, build_gazetteer, seed_with_spacy, strip_org_suffix
from .model import PiiType, Span, resolve
from .policy import Policy
from .vault import Vault, _brand_key


@dataclass
class Detection:
    part: str
    paragraph: int
    span: Span
    replacement: str


@dataclass
class ImageFinding:
    part: str
    type: str
    original: str
    replacement: str
    confidence: float


@dataclass
class Result:
    output: Path
    detections: list[Detection] = field(default_factory=list)
    vault: Vault | None = None
    gazetteer_size: tuple[int, int] = (0, 0)
    image_findings: list[ImageFinding] = field(default_factory=list)
    images_rewritten: int = 0
    ocr_available: bool = True

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for d in self.detections:
            out[d.span.type.value] = out.get(d.span.type.value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def redact(
    source: str | Path,
    output: str | Path,
    policy: Policy | None = None,
    secret: bytes | None = None,
    use_spacy: bool = False,
    redact_images: bool = True,
) -> Result:
    policy = policy or Policy()
    doc = Document(source)
    paragraphs = doc.paragraphs()
    texts = [p.text for p in paragraphs]

    gaz = build_gazetteer(texts)
    if use_spacy:
        gaz = seed_with_spacy(gaz, texts)

    vault = Vault(
        secret=secret or Vault.secret,
        surnames=set(gaz.surname_tokens),
        org_keys=sorted({_brand_key(strip_org_suffix(o)) for o in gaz.orgs}, key=len, reverse=True),
    )
    detectors = [*PATTERN_DETECTORS, GazetteerDetector(gaz)]

    # Pass 1 discovers whole addresses; pass 2 hunts the fragments they leave behind
    # in neighbouring cells, where no pincode is present to anchor a match.
    found_per_para = [[s for d in detectors for s in d.find(p.text)] for p in paragraphs]
    addresses = [s.text for spans in found_per_para for s in spans if s.type is PiiType.ADDRESS]
    places = LiteralDetector("place", PiiType.LOCATION, place_tokens(addresses, gaz.lowercase_vocab))
    if places.re:
        detectors.append(places)

    result = Result(output=Path(output), vault=vault, gazetteer_size=(len(gaz.persons), len(gaz.orgs)))
    for index, para in enumerate(paragraphs):
        found = found_per_para[index] + list(places.find(para.text))
        spans = [s for s in resolve(found) if policy.accepts(s, para.text)]
        if not spans:
            continue
        edits = []
        for span in spans:
            replacement = vault.surrogate(span.type, span.text)
            edits.append((span.start, span.end, replacement))
            result.detections.append(Detection(para.part, index, span, replacement))
        apply(para, edits)

    if redact_images:
        _redact_images(doc, detectors, vault, policy, gaz, result)

    doc.save(output)
    return result


def _redact_images(doc, detectors, vault, policy, gaz, result: Result) -> None:
    """OCR every embedded image and paint over the PII, then re-encode any barcode.

    Text baked into a picture is invisible to every other stage. In this prospectus
    that is where the most sensitive material lives: two of the eight images are scans
    of a PAN card and an Aadhaar card.
    """
    result.ocr_available = image_ocr.available()
    if not result.ocr_available:
        return
    known = {strip_org_suffix(o) for o in gaz.orgs} | set(gaz.orgs)
    for name, payload in doc.image_parts().items():
        fmt = "PNG" if name.lower().endswith(".png") else "JPEG"
        new, findings = image_ocr.redact_barcode(payload, vault, fmt)
        if not findings:
            new, findings = image_ocr.redact_image(payload, detectors, vault, policy, fmt, known)
        if not new:
            continue
        doc.media[name] = new
        result.images_rewritten += 1
        result.image_findings += [ImageFinding(name, f["type"], f["original"],
                                               f["replacement"], f["confidence"]) for f in findings]


def write_audit(result: Result, directory: str | Path) -> None:
    """Emit the mapping and the per-span log the evaluation report is built from."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    mapping = {f"{ns}:{key}": value for (ns, key), value in (result.vault.mapping if result.vault else {}).items()}
    (directory / "mapping.json").write_text(json.dumps(mapping, indent=2, sort_keys=True))

    with (directory / "image_detections.jsonl").open("w") as fh:
        for f in result.image_findings:
            fh.write(json.dumps({"part": f.part, "type": f.type, "original": f.original,
                                 "replacement": f.replacement, "ocr_confidence": f.confidence}) + "\n")

    with (directory / "detections.jsonl").open("w") as fh:
        for d in result.detections:
            fh.write(json.dumps({
                "part": d.part,
                "paragraph": d.paragraph,
                "type": d.span.type.value,
                "detector": d.span.detector,
                "start": d.span.start,
                "end": d.span.end,
                "original": d.span.text,
                "replacement": d.replacement,
            }) + "\n")
