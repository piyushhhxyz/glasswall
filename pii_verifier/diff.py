"""Line alignment for the side-by-side view."""

from __future__ import annotations

from difflib import SequenceMatcher

# Long identical stretches are noise. Keep a few lines either side of a change so
# the reader has context, and collapse the rest into a marker row.
CONTEXT_LINES = 3


def _row(tag: str, left_no, left, right_no, right) -> dict:
    return {"tag": tag, "left_no": left_no, "left": left, "right_no": right_no, "right": right}


def align(before: str, after: str, collapse: bool = True, max_rows: int = 4000) -> dict:
    """Pair up the lines of two texts."""
    left_lines = before.splitlines()
    right_lines = after.splitlines()
    matcher = SequenceMatcher(None, left_lines, right_lines, autojunk=False)

    rows: list[dict] = []
    changed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            count = i2 - i1
            # Collapse only when there is enough of a run to be worth hiding.
            if collapse and count > 2 * CONTEXT_LINES + 1:
                head = range(i1, i1 + CONTEXT_LINES)
                tail = range(i2 - CONTEXT_LINES, i2)
                for i in head:
                    rows.append(_row("equal", i + 1, left_lines[i], j1 + (i - i1) + 1, right_lines[j1 + (i - i1)]))
                rows.append(_row("skip", None, f"{count - 2 * CONTEXT_LINES} identical lines", None, ""))
                for i in tail:
                    offset = j2 - (i2 - i)
                    rows.append(_row("equal", i + 1, left_lines[i], offset + 1, right_lines[offset]))
            else:
                for offset in range(count):
                    rows.append(
                        _row("equal", i1 + offset + 1, left_lines[i1 + offset],
                             j1 + offset + 1, right_lines[j1 + offset])
                    )
            continue

        # A replace block is ragged: the two sides rarely have the same number of
        # lines, so pad the shorter one with None to keep the columns aligned.
        left_block = [(i + 1, left_lines[i]) for i in range(i1, i2)]
        right_block = [(j + 1, right_lines[j]) for j in range(j1, j2)]
        changed += max(len(left_block), len(right_block))
        for offset in range(max(len(left_block), len(right_block))):
            left_no, left = left_block[offset] if offset < len(left_block) else (None, None)
            right_no, right = right_block[offset] if offset < len(right_block) else (None, None)
            rows.append(_row(tag, left_no, left, right_no, right))

    truncated = len(rows) > max_rows
    return {
        "rows": rows[:max_rows],
        "truncated": truncated,
        "changed_lines": changed,
        "left_lines": len(left_lines),
        "right_lines": len(right_lines),
        "identical": changed == 0,
    }
