"""Read/write DOCX text without disturbing formatting.

A DOCX stores a paragraph's text as a sequence of runs, and Word splits runs on
every styling change -- so "Ravi Mohan Sharma" is commonly stored as five
separate <w:t> nodes. Detectors must therefore see *flattened* paragraph text,
while writeback must land back on the original nodes.

This module provides that bridge: `FlatParagraph` exposes one string plus an
offset map, and `apply` writes edits back run-by-run, leaving every other byte
of the package untouched.
"""

from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML = "http://www.w3.org/XML/1998/namespace"


def w(tag: str) -> str:
    return f"{{{W}}}{tag}"


# Parts that can hold body text. Headers/footers matter: this prospectus has 149
# of them, and a naive document.xml-only pass silently leaks whatever they carry.
TEXT_PARTS = ("word/document.xml", "word/header", "word/footer", "word/footnotes.xml", "word/endnotes.xml")

# <w:tab/> and <w:br/> carry no characters but do separate words. We surface them
# as single-space pseudo-nodes so "Chairman<tab>Executive" cannot flatten into
# "ChairmanExecutive" and defeat gazetteer matching.
SEPARATORS = {w("tab"): " ", w("br"): "\n"}

# Field-code runs. A hyperlink stores its target here, not in <w:t>:
#
#     <w:instrText> HYPERLINK "mailto:info@acmeindustries.com" </w:instrText>
#
# The display text is redacted, the target is not, and the address stays live behind
# the link. Nothing is visible in the document body, so a reader-based leak check
# never sees it -- which is precisely why it has to be a writable node here.
TEXT_TAGS = (w("t"), w("instrText"), w("delInstrText"))


@dataclass
class Node:
    """One writable text position inside a paragraph."""

    el: etree._Element
    start: int
    end: int
    is_separator: bool = False


@dataclass
class FlatParagraph:
    part: str
    el: etree._Element
    text: str
    nodes: list[Node] = field(default_factory=list)


def _iter_text_nodes(para: etree._Element):
    for el in para.iter():
        if el.tag in TEXT_TAGS:
            yield el, el.text or "", False
        elif el.tag in SEPARATORS:
            yield el, SEPARATORS[el.tag], True


def flatten(part: str, para: etree._Element) -> FlatParagraph:
    buf, nodes, pos = [], [], 0
    for el, text, is_sep in _iter_text_nodes(para):
        nodes.append(Node(el, pos, pos + len(text), is_sep))
        buf.append(text)
        pos += len(text)
    return FlatParagraph(part=part, el=para, text="".join(buf), nodes=nodes)


def _set_node_text(node: Node, text: str) -> None:
    """Write `text` to a node, converting separators to real runs when edited."""
    if not node.is_separator:
        node.el.text = text
        # Word strips edge whitespace unless told not to.
        if text != text.strip():
            node.el.set(f"{{{XML}}}space", "preserve")
        return

    if text in SEPARATORS.get(node.el.tag, ""):
        return  # untouched separator, leave the element as-is
    parent = node.el.getparent()
    index = parent.index(node.el)
    parent.remove(node.el)
    if text:
        t = etree.SubElement(parent, w("t"))
        t.text = text
        t.set(f"{{{XML}}}space", "preserve")
        parent.remove(t)
        parent.insert(index, t)


def apply(para: FlatParagraph, edits: list[tuple[int, int, str]]) -> None:
    """Apply (start, end, replacement) edits given in flat-text coordinates.

    Each replacement is emitted in whichever node contains its *first* character;
    the tail of the span is deleted from the nodes it spills into. That keeps the
    replacement inside a single run, inheriting that run's formatting.
    """
    if not edits:
        return
    edits = sorted(edits, key=lambda e: e[0])
    flat = para.text

    for node in para.nodes:
        lo, hi = node.start, node.end
        out, cursor = [], lo
        for start, end, replacement in edits:
            if end <= lo or start >= hi:
                continue
            if start > cursor:
                out.append(flat[cursor:start])
            if start >= lo:
                out.append(replacement)  # this node owns the span
            cursor = max(cursor, min(hi, end))
        if cursor == lo and not out:
            continue  # untouched node
        out.append(flat[cursor:hi])
        _set_node_text(node, "".join(out))


class Document:
    """A DOCX opened as raw XML parts, so nothing outside the text is rewritten."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.trees: dict[str, etree._ElementTree] = {}
        self.media: dict[str, bytes] = {}   # replacement bytes for word/media/* parts
        with zipfile.ZipFile(self.path) as zf:
            self.names = zf.namelist()
            for name in self.names:
                if name.startswith(TEXT_PARTS):
                    self.trees[name] = etree.fromstring(zf.read(name)).getroottree()

    def image_parts(self) -> dict[str, bytes]:
        with zipfile.ZipFile(self.path) as zf:
            return {n: zf.read(n) for n in self.names if n.startswith("word/media/")}

    def paragraphs(self) -> list[FlatParagraph]:
        out = []
        for part, tree in self.trees.items():
            for para in tree.getroot().iter(w("p")):
                flat = flatten(part, para)
                if flat.text.strip():
                    out.append(flat)
        return out

    def save(self, out_path: str | Path) -> Path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.path, out_path)  # preserve media, styles, rels verbatim
        with zipfile.ZipFile(self.path) as src:
            items = [(i, src.read(i.filename)) for i in src.infolist()]
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as dst:
            for info, payload in items:
                if info.filename in self.trees:
                    payload = etree.tostring(
                        self.trees[info.filename], xml_declaration=True, encoding="UTF-8", standalone=True
                    )
                elif info.filename in self.media:
                    payload = self.media[info.filename]
                dst.writestr(info, payload)
        return out_path
