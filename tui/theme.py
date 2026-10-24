"""Colour palette with 256-colour, 8-colour and monochrome fallbacks."""

from __future__ import annotations

import curses
from dataclasses import dataclass
from typing import Dict

STYLE_NAMES = ("bone", "ash", "dim", "iron", "crimson", "blood", "amber", "green", "title", "select")

_BLACK_256 = 16
_FG_256 = {"bone": 253, "ash": 247, "dim": 242, "iron": 238, "crimson": 88,
           "blood": 160, "amber": 136, "green": 65}
_FG_8 = {"bone": curses.COLOR_WHITE, "ash": curses.COLOR_WHITE, "dim": curses.COLOR_WHITE,
         "iron": curses.COLOR_BLACK, "crimson": curses.COLOR_RED, "blood": curses.COLOR_RED,
         "amber": curses.COLOR_YELLOW, "green": curses.COLOR_GREEN}


@dataclass
class Theme:
    attrs: Dict[str, int]
    level: int  # 0 mono, 8, 256

    def attr(self, name: str) -> int:
        return self.attrs.get(name, self.attrs["ash"])


def detect_color_level() -> int:
    try:
        if not curses.has_colors():
            return 0
        return 256 if curses.COLORS >= 256 else 8
    except curses.error:
        return 0


def build_theme(level: int, curses_mod=curses) -> Theme:
    """Create style attributes. Levels 8 and 256 require an initialised curses screen."""
    c = curses_mod
    if level <= 0:
        return Theme({
            "bone": c.A_BOLD, "ash": c.A_NORMAL, "dim": c.A_DIM, "iron": c.A_DIM,
            "crimson": c.A_BOLD, "blood": c.A_BOLD, "amber": c.A_BOLD,
            "green": c.A_NORMAL, "title": c.A_BOLD, "select": c.A_REVERSE}, 0)
    names = ("bone", "ash", "dim", "iron", "crimson", "blood", "amber", "green")
    attrs: Dict[str, int] = {}
    bg = _BLACK_256 if level >= 256 else c.COLOR_BLACK
    for pair, name in enumerate(names, start=1):
        fg = _FG_256[name] if level >= 256 else _FG_8[name]
        c.init_pair(pair, fg, bg)
        attrs[name] = c.color_pair(pair)
    if level < 256:
        attrs["bone"] |= c.A_BOLD
        attrs["dim"] |= c.A_DIM
        attrs["iron"] |= c.A_BOLD
        attrs["blood"] |= c.A_BOLD
    attrs["title"] = attrs["crimson"] | c.A_BOLD
    attrs["select"] = attrs["bone"] | c.A_BOLD
    return Theme(attrs, level)


def background_attr(theme: Theme, curses_mod=curses) -> int:
    return curses_mod.color_pair(2) if theme.level else curses_mod.A_NORMAL
