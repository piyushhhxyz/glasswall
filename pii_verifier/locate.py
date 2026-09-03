"""Turning a character offset into somewhere a person can actually look.

"Offset 94445" is not actionable; line, column, snippet and path are.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

SNIPPET_BEFORE = 48
SNIPPET_AFTER = 48
# How far up to walk looking for enclosing keys before giving up on a path.
MAX_PATH_LINES = 400
MAX_PATH_DEPTH = 8

_KEY_LINE = re.compile(r'^\s*"([^"]{1,80})"\s*:')
# `[` alone, or `"key": [` -- the second both names a field and opens a list, so
# the path needs the key *and* the index within it.
_ARRAY_OPEN = re.compile(r'^\s*(?:"[^"]*"\s*:\s*)?\[\s*$')
_ELEMENT_OPEN = re.compile(r"^\s*[{\[]")


@dataclass
class LineIndex:
    """Offset -> (line, column), built once per text and reused per finding."""

    starts: list[int]
    lines: list[str]

    @classmethod
    def build(cls, text: str) -> "LineIndex":
        starts, position = [0], 0
        for line in text.splitlines(keepends=True):
            position += len(line)
            starts.append(position)
        return cls(starts=starts[:-1] or [0], lines=text.splitlines())

    def position(self, offset: int) -> tuple[int, int]:
        """1-based line, 1-based column."""
        index = bisect.bisect_right(self.starts, offset) - 1
        index = max(0, min(index, len(self.starts) - 1))
        return index + 1, offset - self.starts[index] + 1


def snippet(text: str, start: int, end: int) -> dict:
    """The match plus a little either side, for showing without the whole file."""
    left = max(0, start - SNIPPET_BEFORE)
    right = min(len(text), end + SNIPPET_AFTER)
    return {
        "before": text[left:start].replace("\n", "⏎"),
        "match": text[start:end].replace("\n", "⏎"),
        "after": text[end:right].replace("\n", "⏎"),
        "clipped_left": left > 0,
        "clipped_right": right < len(text),
    }


def _element_index(lines: list[str], opener: int, target: int, indent: int) -> str:
    """Which element of the array opened at `opener` contains `target`."""
    element_indent = indent + 2
    seen = 0
    for number in range(opener + 1, target):
        line = lines[number - 1]
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) == element_indent and _ELEMENT_OPEN.match(line):
            seen += 1
    return str(max(0, seen - 1))


def _inline_key(line: str, column: int) -> str | None:
    """The nearest `"key":` to the left of `column` on the same line.

    JSONL puts a record on one line, so the key must come from the line itself.
    """
    matches = list(re.finditer(r'"([^"]{1,80})"\s*:', line[: max(0, column - 1)]))
    return matches[-1].group(1) if matches else None


def structural_path(index: LineIndex, line_number: int, column: int = 0) -> str:
    """A breadcrumb to the value on `line_number`, e.g. `messages > 3 > text`.

    `extract` pretty-prints at a fixed indent, so indentation gives the depth.
    """
    lines = index.lines
    if not 1 <= line_number <= len(lines):
        return ""
    current = lines[line_number - 1]
    depth = len(current) - len(current.lstrip())
    parts: list[str] = []

    own_key = _KEY_LINE.match(current)
    if own_key:
        parts.append(own_key.group(1))
    elif column:
        inline = _inline_key(current, column)
        if inline:
            parts.append(inline)

    for number in range(line_number - 1, max(0, line_number - MAX_PATH_LINES) - 1, -1):
        line = lines[number - 1]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent >= depth:
            continue
        key = _KEY_LINE.match(line)
        if _ARRAY_OPEN.match(line):
            parts.append(_element_index(lines, number, line_number, indent))
        if key:
            parts.append(key.group(1))
        depth = indent
        if len(parts) >= MAX_PATH_DEPTH or indent == 0:
            break

    return " > ".join(reversed(parts))


def describe(text: str, start: int, end: int, index: LineIndex | None = None) -> dict:
    """Everything needed to point at one occurrence: line, column, path, snippet."""
    index = index or LineIndex.build(text)
    line, column = index.position(start)
    return {
        "line": line,
        "column": column,
        "start": start,
        "end": end,
        "path": structural_path(index, line, column),
        "snippet": snippet(text, start, end),
    }
