"""Load user-supplied ASCII artwork from a UTF-8 text file (assets/berserk.txt)."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from core.textsafe import display_width

MAX_BYTES = 256 * 1024
MAX_LINES = 200
MIN_ART_ROWS = 8
_BLANK_CHARS = " ⠀"  # space and braille blank


@dataclass(frozen=True)
class Art:
    lines: List[str]
    width: int


def _clean(line: str) -> str:
    line = line.replace("\t", "    ")
    line = "".join(ch for ch in line if unicodedata.category(ch)[0] != "C")
    return line.rstrip(" ")


def parse_art(text: str) -> Optional[Art]:
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")[:MAX_LINES]
    lines = [_clean(line) for line in raw]
    while lines and not lines[0].strip(_BLANK_CHARS):
        lines.pop(0)
    while lines and not lines[-1].strip(_BLANK_CHARS):
        lines.pop()
    if not lines:
        return None
    return Art(lines=lines, width=max(display_width(line) for line in lines))


def load_art(path: Path) -> Optional[Art]:
    """Return the artwork, or None if the file is absent, unreadable or empty."""
    try:
        data = Path(path).read_bytes()[:MAX_BYTES]
    except OSError:
        return None
    return parse_art(data.decode("utf-8", errors="replace"))


def fit_art(art: Optional[Art], max_width: int, max_height: int) -> Optional[List[str]]:
    """Lines that fit the box, or None. Never scales; crops from the bottom when short on rows."""
    if art is None or art.width > max_width or max_height < MIN_ART_ROWS:
        return None
    return art.lines[:max_height]
