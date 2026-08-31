"""OCR and redact text baked into embedded images.

Text in a picture is invisible to every other stage of this tool, and it is where
the most sensitive material in this prospectus turned out to live: two of the eight
embedded images are scans of identity documents -- a PAN card and an Aadhaar card,
carrying names, parents' names, dates of birth, a PAN and an Aadhaar number. None of
that appears anywhere in the document's text.

OCR runs on Apple's Vision framework: on-device, offline, no model download, and it
returns bounding boxes so regions can be painted over rather than merely detected.
On a machine without it the stage degrades to a no-op and says so, rather than
silently reporting a clean document.

Two policies apply:

* **Identity documents are redacted wholesale.** Once an image is recognised as an
  ID card, every text region is covered except the issuing authority's boilerplate.
  Per-field detection is the wrong instinct here -- "ANIL SHARMA" is in no gazetteer,
  and a card scan is sensitive as a whole object.
* **Every other image** goes through the same detectors as body text, so a logo with
  a phone number in it is handled like any other phone number.
"""

from __future__ import annotations

import io
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .model import PiiType, Span

# Phrases that mark a scan of a government identity document.
ID_DOCUMENT_MARKERS = re.compile(
    r"income\s*tax\s*department|permanent\s*account\s*number|govt\.?\s*of\s*india|"
    r"government\s+of\s+india|unique\s+identification\s+authority|aadhaar|"
    r"driving\s+licen[cs]e|passport|voter|election\s+commission",
    re.I,
)

# Issuer boilerplate carries no personal information and is worth keeping so the
# redacted image is still recognisable as "a PAN card" rather than a black rectangle.
ISSUER_BOILERPLATE = re.compile(
    r"^(?:income\s*tax\s*department|govt\.?\s*of\s*india|government\s+of\s+india|"
    r"permanent\s+account\s+number(?:\s+card)?|unique\s+identification\s+authority(?:\s+of\s+india)?|"
    r"name|father'?s?\s*name|date\s+of\s+birth|dob|signature|address|male|female|"
    r"[^\w]*)$",
    re.I,
)


@dataclass
class TextBox:
    text: str
    left: float   # all normalised 0-1, origin top-left
    top: float
    width: float
    height: float
    confidence: float


def available() -> bool:
    try:
        import Quartz  # noqa: F401
        import Vision  # noqa: F401
    except ImportError:
        return False
    return True


def ocr(payload: bytes) -> list[TextBox]:
    """Recognise text with Apple Vision. Returns [] when the framework is absent."""
    if not available():
        return []
    import Quartz
    import Vision
    from Foundation import NSURL

    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as fh:
        fh.write(payload)
        path = fh.name
    try:
        source = Quartz.CGImageSourceCreateWithURL(NSURL.fileURLWithPath_(path), None)
        if source is None:
            return []
        image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
        if image is None:
            return []
        request = Vision.VNRecognizeTextRequest.alloc().init()
        request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
        request.setUsesLanguageCorrection_(True)
        handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(image, None)
        handler.performRequests_error_([request], None)

        boxes = []
        for observation in request.results() or []:
            candidate = observation.topCandidates_(1)
            if not candidate:
                continue
            best, box = candidate[0], observation.boundingBox()
            boxes.append(TextBox(
                text=best.string(),
                left=box.origin.x,
                # Vision's origin is bottom-left; images are addressed top-left.
                top=1.0 - box.origin.y - box.size.height,
                width=box.size.width,
                height=box.size.height,
                confidence=best.confidence(),
            ))
        return boxes
    finally:
        Path(path).unlink(missing_ok=True)


def barcodes(payload: bytes) -> list[str]:
    """Decode QR / barcode payloads. The cover page carries a live shortlink to the
    filing, which identifies the issuer as surely as its name does."""
    if not available():
        return []
    import Quartz
    import Vision
    from Foundation import NSURL

    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as fh:
        fh.write(payload)
        path = fh.name
    try:
        source = Quartz.CGImageSourceCreateWithURL(NSURL.fileURLWithPath_(path), None)
        if source is None:
            return []
        image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
        if image is None:
            return []
        request = Vision.VNDetectBarcodesRequest.alloc().init()
        Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(image, None).performRequests_error_(
            [request], None)
        return [o.payloadStringValue() for o in (request.results() or []) if o.payloadStringValue()]
    finally:
        Path(path).unlink(missing_ok=True)


def redact_barcode(payload: bytes, vault, fmt: str = "PNG"):
    """Re-encode a QR with a surrogate URL, keeping the code scannable."""
    decoded = barcodes(payload)
    if not decoded:
        return None, []
    try:
        import qrcode
        from PIL import Image
    except ImportError:
        return None, []

    original = decoded[0]
    surrogate = vault.surrogate(PiiType.URL, original)
    source = Image.open(io.BytesIO(payload))
    replacement = qrcode.make(surrogate).convert("RGB").resize(source.size)
    buffer = io.BytesIO()
    replacement.save(buffer, format=fmt)
    return buffer.getvalue(), [{"type": "URL", "original": original,
                                "replacement": surrogate, "confidence": 1.0}]


def faces(payload: bytes) -> list[tuple[float, float, float, float]]:
    """Face rectangles, normalised with a top-left origin.

    A redacted identity card that still shows the holder's photograph is not
    anonymised: the face is the most personal field on it.
    """
    if not available():
        return []
    import Quartz
    import Vision
    from Foundation import NSURL

    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as fh:
        fh.write(payload)
        path = fh.name
    try:
        source = Quartz.CGImageSourceCreateWithURL(NSURL.fileURLWithPath_(path), None)
        if source is None:
            return []
        image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
        if image is None:
            return []
        request = Vision.VNDetectFaceRectanglesRequest.alloc().init()
        Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(image, None).performRequests_error_(
            [request], None)
        out = []
        for face in request.results() or []:
            box = face.boundingBox()
            out.append((box.origin.x, 1.0 - box.origin.y - box.size.height,
                        box.size.width, box.size.height))
        return out
    finally:
        Path(path).unlink(missing_ok=True)


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _is_sensitive(box: TextBox, detectors, policy, known_terms) -> tuple[bool, PiiType, str]:
    for detector in detectors:
        for span in detector.find(box.text):
            if policy.accepts(span) and len(span) >= max(3, len(box.text.strip()) // 3):
                return True, span.type, span.text
    # Logos OCR badly: "Bluecrest" comes back as "_bluecrest", "Redstone Advisors" as
    # "PRedstone Advisors". Word-boundary matching fails on both, so known entity
    # names are also tested as squashed substrings -- no spaces, no punctuation.
    squashed = _squash(box.text)
    if len(squashed) >= 4:
        for term in known_terms:
            if len(term) < 4:
                continue
            # Either direction: OCR may add noise around the name ("_bluecrest") or catch
            # only the brand out of a longer registered name ("Bluecrest Capital").
            if term in squashed or (len(squashed) >= 5 and squashed in term):
                return True, PiiType.ORG, box.text.strip()
    return False, PiiType.PERSON, box.text


def redact_image(payload: bytes, detectors, vault, policy, fmt: str = "PNG", known_terms=()):
    """Paint over every PII region and draw its surrogate in place.

    Returns (new_bytes, findings). `new_bytes` is None when nothing was redacted, so
    the caller can leave the original part untouched.
    """
    from PIL import Image, ImageDraw, ImageFont

    boxes = ocr(payload)
    if not boxes:
        return None, []

    known_terms = {_squash(t) for t in known_terms}
    joined = " ".join(b.text for b in boxes)
    is_id_document = bool(ID_DOCUMENT_MARKERS.search(joined))
    face_boxes = faces(payload) if is_id_document else []

    targets = []
    for box in boxes:
        text = box.text.strip()
        if not text:
            continue
        if is_id_document:
            if ISSUER_BOILERPLATE.match(text):
                continue
            hit, pii_type, matched = True, PiiType.ID_DOCUMENT, text
        else:
            hit, pii_type, matched = _is_sensitive(box, detectors, policy, known_terms)
        if hit:
            targets.append((box, pii_type, matched))
    if not targets and not face_boxes:
        return None, []

    image = Image.open(io.BytesIO(payload)).convert("RGB")
    width, height = image.size
    findings = []

    # Faces first, so a text box drawn over the photo still lands on top.
    from PIL import ImageFilter
    for fx, fy, fw, fh in face_boxes:
        x0, y0 = max(0, int((fx - 0.02) * width)), max(0, int((fy - 0.06) * height))
        x1, y1 = min(width, int((fx + fw + 0.02) * width)), min(height, int((fy + fh + 0.06) * height))
        if x1 <= x0 or y1 <= y0:
            continue
        region = image.crop((x0, y0, x1, y1))
        radius = max(8, (x1 - x0) // 4)
        image.paste(region.filter(ImageFilter.GaussianBlur(radius)), (x0, y0))
        findings.append({"type": "FACE", "original": f"face at {x0},{y0}",
                         "replacement": "blurred", "confidence": 1.0})

    draw = ImageDraw.Draw(image)

    for box, pii_type, matched in targets:
        x0 = max(0, int(box.left * width) - 2)
        y0 = max(0, int(box.top * height) - 2)
        x1 = min(width, int((box.left + box.width) * width) + 2)
        y1 = min(height, int((box.top + box.height) * height) + 2)
        if x1 <= x0 or y1 <= y0:
            continue
        surrogate = vault.surrogate(pii_type, box.text.strip())
        draw.rectangle([x0, y0, x1, y1], fill=(28, 28, 30))
        font = _fit_font(ImageFont, surrogate, x1 - x0, y1 - y0)
        if font is not None:
            draw.text((x0 + 2, y0 + 1), surrogate, fill=(245, 245, 245), font=font)
        findings.append({"type": pii_type.value, "original": box.text.strip(),
                         "replacement": surrogate, "confidence": round(box.confidence, 3)})

    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue(), findings


_FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
]


def _fit_font(ImageFont, text: str, box_width: int, box_height: int):
    """Largest font that keeps the surrogate inside the box it replaces."""
    for path in _FONT_CANDIDATES:
        if not Path(path).exists():
            continue
        for size in range(max(6, box_height), 5, -1):
            try:
                font = ImageFont.truetype(path, size)
            except OSError:
                break
            if font.getlength(text) <= box_width - 4:
                return font
        return None
    return None
