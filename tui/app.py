"""Curses application: input handling, drawing and the bounded inspection worker."""

from __future__ import annotations

import curses
import locale
import os
import queue
import threading
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core import TOOL_NAME, TOOL_VERSION
from core.assessment import AdvisoryDB, Assessment, QUALITY_MANUAL, assess_manual, assess_url
from core.reports import export_report
from core.scanner import ScanError
from core.textsafe import clip, display_width, sanitize_text
from . import screens
from .art import Art, load_art
from .theme import Theme, background_attr, build_theme, detect_color_level

MIN_W, MIN_H = 44, 12
FRAME_MAX_W = 84
MAX_INPUT = 2048
ESC = "\x1b"


class App:
    def __init__(self, stdscr, db: AdvisoryDB, art: Optional[Art], allow_local: bool,
                 export_dir: Path) -> None:
        self.s = stdscr
        self.db = db
        self.art = art
        self.allow_local = allow_local
        self.export_dir = export_dir
        self.theme: Theme = build_theme(detect_color_level())
        self.state = "home"
        self.menu_index = 0
        self.buffer = ""
        self.cursor = 0
        self.scroll = 0
        self.assessment: Optional[Assessment] = None
        self.error: Optional[ScanError] = None
        self.status: Optional[Tuple[str, str]] = None
        self.stage = 0
        self.target = ""
        self.job = 0
        self.events: "queue.Queue" = queue.Queue()
        self.input_kind = "url"
        self.return_state = "home"
        self.page = 10

    # ------------------------------------------------------------ drawing

    def put(self, y: int, x: int, text: str, style: str, max_w: int) -> None:
        if max_w <= 0 or y < 0:
            return
        try:
            self.s.addstr(y, x, clip(sanitize_text(text), max_w), self.theme.attr(style))
        except curses.error:
            pass

    def draw_line(self, y: int, x: int, line: screens.Line, max_w: int) -> None:
        used = 0
        for text, style in line:
            self.put(y, x + used, text, style, max_w - used)
            used += display_width(sanitize_text(text))
            if used >= max_w:
                break

    def draw(self) -> None:
        s = self.s
        s.erase()
        h, w = s.getmaxyx()
        if h < MIN_H or w < MIN_W:
            self.put(0, 0, "TERMINAL TOO SMALL", "blood", w)
            self.put(1, 0, "Need %dx%d, have %dx%d" % (MIN_W, MIN_H, w, h), "dim", w)
            self.put(2, 0, "[Q] exit", "dim", w)
            s.refresh()
            return
        fw = min(w, FRAME_MAX_W)
        x0 = (w - fw) // 2
        inner = fw - 4
        cx = x0 + 2
        top, bottom = 3, h - 4          # content rows top..bottom inclusive
        ch = bottom - top + 1

        edge = "+" + "-" * (fw - 2) + "+"
        sep = "|" + "-" * (fw - 2) + "|"
        self.put(0, x0, edge, "iron", fw)
        self.put(2, x0, sep, "iron", fw)
        self.put(h - 3, x0, sep, "iron", fw)
        self.put(h - 1, x0, edge, "iron", fw)
        for y in (1,) + tuple(range(3, h - 3)) + (h - 2,):
            self.put(y, x0, "|", "iron", 1)
            self.put(y, x0 + fw - 1, "|", "iron", 1)
        self.put(1, cx, TOOL_NAME, "title", inner)
        ver = "v" + TOOL_VERSION
        self.put(1, x0 + fw - 2 - len(ver), ver, "dim", len(ver))

        footer: List[Tuple[str, str]] = []
        indicator = ""
        if self.state == "home":
            self.draw_home(cx, top, inner, ch, x0, fw)
            footer = [("UP/DN", "SELECT"), ("ENTER", "OPEN"), ("Q", "EXIT")]
        elif self.state == "input":
            self.draw_input(cx, top, inner)
            footer = [("ENTER", "BEGIN"), ("ESC", "BACK")]
        elif self.state == "working":
            self.draw_working(cx, top, inner)
            footer = [("ESC", "CANCEL")]
        elif self.state == "result":
            self.draw_dashboard(cx, top, inner, ch)
            footer = [("N", "NEW")] + [("D", "DETAILS")] + ([("E", "EXPORT")] if self.error is None else []) \
                + [("Q", "QUIT")]
        elif self.state in ("details", "archive"):
            if self.state == "archive":
                lines = screens.build_archive_lines(self.db, inner - 2)
                footer = [("ESC", "BACK"), ("UP/DN", "SCROLL"), ("Q", "QUIT")]
            else:
                if self.error is not None:
                    lines = screens.build_error_lines(self.error.message, self.error.kind, inner - 2)
                else:
                    lines = screens.build_details_lines(self.assessment, self.db, inner - 2)
                footer = [("ESC/B", "BACK"), ("UP/DN", "SCROLL"), ("PGUP/PGDN", "PAGE"), ("Q", "QUIT")]
            self.page = max(1, ch - 1)
            self.scroll = max(0, min(self.scroll, max(0, len(lines) - ch)))
            for i in range(ch):
                idx = self.scroll + i
                if idx >= len(lines):
                    break
                self.draw_line(top + i, cx, lines[idx], inner - 2)
            if len(lines) > ch:
                span = max(1, len(lines) - ch)
                thumb = top + int(self.scroll / span * (ch - 1))
                for y in range(top, top + ch):
                    self.put(y, cx + inner - 1, "#" if y == thumb else "|", "bone" if y == thumb else "iron", 1)
                indicator = "%d%%" % round(100 * self.scroll / span)
        if self.status:
            room = inner - len(TOOL_NAME) - len(ver) - 4
            self.put(1, cx + len(TOOL_NAME) + 2, self.status[0], self.status[1], room)
        self.draw_line(h - 2, cx, screens.footer_line(footer, inner - (len(indicator) + 2 if indicator else 0)), inner)
        if indicator:
            self.put(h - 2, cx + inner - len(indicator) - 1, indicator, "dim", len(indicator))
        if self.state == "input":
            fx = self.input_geometry(inner)[1]
            try:
                s.move(top + 6, cx + 9 + fx)
            except curses.error:
                pass
        s.refresh()

    def draw_dashboard(self, cx: int, top: int, inner: int, ch: int) -> None:
        if self.error is not None:
            view = screens.view_from_error(self.error.message, self.target)
        else:
            view = screens.view_from_assessment(self.assessment)
        for i, row in enumerate(screens.dashboard_rows(view, ch, inner)[:ch]):
            width = sum(display_width(t) for t, _ in row.line)
            x = cx + ((inner - width) // 2 if row.align == "center" else 1)
            self.draw_line(top + i, max(x, cx), row.line, inner)

    def draw_home(self, cx: int, top: int, inner: int, ch: int, x0: int, fw: int) -> None:
        rows = screens.home_rows(ch, inner, self.art)
        menu_w = max(len(r.text) for r in rows if r.kind == "menu") + 4
        for i, row in enumerate(rows[:ch]):
            y = top + i
            if row.kind == "art":
                self.put(y, cx + (inner - row.width) // 2, row.text, "art", inner)
            elif row.kind == "text":
                self.put(y, cx + (inner - display_width(row.text)) // 2, row.text, row.style, inner)
            elif row.kind == "menu":
                x = cx + (inner - menu_w) // 2
                chosen = row.index == self.menu_index
                self.put(y, x, ">" if chosen else " ", "blood", 1)
                self.put(y, x + 3, row.text, "select" if chosen else "ash", inner)

    def input_geometry(self, inner: int) -> Tuple[int, int]:
        width = max(10, inner - 12)
        start = max(0, self.cursor - width + 1)
        return start, self.cursor - start

    def draw_input(self, cx: int, top: int, inner: int) -> None:
        if self.input_kind == "url":
            self.put(top + 1, cx, "INSPECT TARGET", "title", inner)
            hints = ["Enter a hostname or URL. HTTPS is assumed when no scheme is given.",
                     "Only ordinary HEAD/GET requests are sent: no payloads, no probing,",
                     "no uploads. Loopback, private and metadata addresses are refused."]
            label = "TARGET"
        else:
            self.put(top + 1, cx, "MANUAL VERSION", "title", inner)
            hints = ["Enter a known PHP version as MAJOR.MINOR.PATCH, for example 8.3.35.",
                     "This mode is fully offline and uses the bundled advisory snapshot.",
                     "The result is labelled as user-supplied, not as a server observation."]
            label = "VERSION"
        for i, hint in enumerate(hints):
            self.put(top + 3 + i, cx, hint, "dim", inner)
        start, _ = self.input_geometry(inner)
        width = max(10, inner - 12)
        self.put(top + 6, cx, label.ljust(6) + " > ", "crimson", inner)
        self.put(top + 6, cx + 9, self.buffer[start:start + width], "bone", width)

    def draw_working(self, cx: int, top: int, inner: int) -> None:
        self.put(top + 1, cx, "THE INSPECTION", "title", inner)
        self.put(top + 2, cx, self.target, "dim", inner)
        for i, (_, label) in enumerate(screens.STAGES):
            if i < self.stage:
                mark, style = "[x]", "ash"
            elif i == self.stage:
                mark, style = "[>]", "bone"
            else:
                mark, style = "[ ]", "iron"
            self.put(top + 4 + i, cx + 2, "%s %s" % (mark, label), style, inner - 2)

    # ------------------------------------------------------------- actions

    def start_input(self, kind: str) -> None:
        self.input_kind = kind
        self.buffer, self.cursor, self.status = "", 0, None
        self.state = "input"

    def submit_input(self) -> None:
        text = self.buffer.strip()
        if not text:
            self.status = ("Nothing entered.", "amber")
            return
        if self.input_kind == "manual":
            self.assessment, self.error = assess_manual(self.db, text), None
            self.scroll, self.status, self.state = 0, None, "result"
            return
        self.target = sanitize_text(text, 200)
        self.job += 1
        self.stage = 0
        self.state = "working"
        self.status = None
        threading.Thread(target=self._work, args=(self.job, text), daemon=True).start()

    def _work(self, job: int, url: str) -> None:
        def progress(stage: str) -> None:
            self.events.put(("stage", job, stage))
        try:
            result = assess_url(url, self.db, allow_local=self.allow_local, progress=progress)
            self.events.put(("done", job, result))
        except ScanError as exc:
            self.events.put(("error", job, exc))
        except Exception as exc:  # noqa: BLE001 - never let a worker crash the UI
            self.events.put(("error", job, ScanError("internal", "Unexpected failure (%s)." % type(exc).__name__)))

    def poll(self) -> None:
        keys = [k for k, _ in screens.STAGES]
        while True:
            try:
                kind, job, payload = self.events.get_nowait()
            except queue.Empty:
                return
            if job != self.job or self.state != "working":
                continue
            if kind == "stage" and payload in keys:
                self.stage = max(self.stage, keys.index(payload))
            elif kind == "done":
                self.assessment, self.error = payload, None
                self.scroll, self.state = 0, "result"
            elif kind == "error":
                self.assessment, self.error = None, payload
                self.scroll, self.state = 0, "result"

    def export(self) -> None:
        if self.assessment is None:
            return
        try:
            path = export_report(self.assessment, self.export_dir)
            self.status = ("Report written: %s" % os.path.relpath(path), "green")
        except OSError as exc:
            self.status = ("Export failed: %s" % (exc.strerror or "error"), "blood")

    # --------------------------------------------------------------- input

    def read_key(self):
        try:
            return self.s.get_wch()
        except curses.error:
            return None

    def handle_edit(self, key) -> bool:
        if key in ("\n", "\r", curses.KEY_ENTER):
            self.submit_input()
        elif key == ESC:
            self.state, self.status = "home", None
        elif key in ("\x7f", "\b", curses.KEY_BACKSPACE):
            if self.cursor:
                self.buffer = self.buffer[:self.cursor - 1] + self.buffer[self.cursor:]
                self.cursor -= 1
        elif key == curses.KEY_DC:
            self.buffer = self.buffer[:self.cursor] + self.buffer[self.cursor + 1:]
        elif key == curses.KEY_LEFT:
            self.cursor = max(0, self.cursor - 1)
        elif key == curses.KEY_RIGHT:
            self.cursor = min(len(self.buffer), self.cursor + 1)
        elif key in (curses.KEY_HOME, "\x01"):
            self.cursor = 0
        elif key in (curses.KEY_END, "\x05"):
            self.cursor = len(self.buffer)
        elif key == "\x15":
            self.buffer, self.cursor = "", 0
        elif isinstance(key, str) and key.isprintable() and len(self.buffer) < MAX_INPUT:
            self.buffer = self.buffer[:self.cursor] + key + self.buffer[self.cursor:]
            self.cursor += 1
        return True

    def handle_scroll(self, key) -> bool:
        step = {curses.KEY_UP: -1, "k": -1, curses.KEY_DOWN: 1, "j": 1,
                curses.KEY_PPAGE: -self.page, curses.KEY_NPAGE: self.page, " ": self.page,
                curses.KEY_HOME: -10000, curses.KEY_END: 10000}.get(key)
        if step is not None:
            self.scroll = max(0, self.scroll + step)
            return True
        return False

    def handle(self, key) -> bool:
        """Return False to quit."""
        if key == curses.KEY_RESIZE:
            return True
        h, w = self.s.getmaxyx()
        if h < MIN_H or w < MIN_W:
            return not (isinstance(key, str) and key.lower() == "q")
        if self.state == "input":
            return self.handle_edit(key)
        if self.state == "working":
            if key == ESC:
                self.job += 1
                self.state = "home"
            return True
        self.status = None
        low = key.lower() if isinstance(key, str) else key
        if self.state == "home":
            if key == curses.KEY_UP:
                self.menu_index = (self.menu_index - 1) % len(screens.MENU)
            elif key == curses.KEY_DOWN:
                self.menu_index = (self.menu_index + 1) % len(screens.MENU)
            elif low in ("1", "i"):
                self.start_input("url")
            elif low in ("2", "m"):
                self.start_input("manual")
            elif low in ("3", "a"):
                self.return_state, self.scroll, self.state = "home", 0, "archive"
            elif low in ("4", "q"):
                return False
            elif key in ("\n", "\r", curses.KEY_ENTER):
                if self.menu_index == 0:
                    self.start_input("url")
                elif self.menu_index == 1:
                    self.start_input("manual")
                elif self.menu_index == 2:
                    self.return_state, self.scroll, self.state = "home", 0, "archive"
                else:
                    return False
            return True
        # result / details / archive
        if self.state in ("details", "archive") and self.handle_scroll(key):
            return True
        if low == "q":
            return False
        if self.state == "archive":
            if key == ESC or low == "b":
                self.state = "home"
        elif self.state == "details":
            if key == ESC or low == "b":
                self.state = "result"
        elif self.state == "result":
            if low == "n":
                self.start_input("manual" if (self.assessment and self.assessment.mode == "manual") else "url")
            elif low == "d":
                self.scroll, self.state = 0, "details"
            elif low == "e" and self.error is None:
                self.export()
            elif key == ESC:
                self.state = "home"
        return True

    def loop(self) -> None:
        while True:
            try:
                curses.curs_set(1 if self.state == "input" else 0)
            except curses.error:
                pass
            self.s.timeout(100 if self.state == "working" else -1)
            self.draw()
            key = self.read_key()
            if self.state == "working":
                self.poll()
            if key is None:
                continue
            if not self.handle(key):
                return


def _main(stdscr, db: AdvisoryDB, art_path: Path, allow_local: bool, export_dir: Path) -> None:
    stdscr.keypad(True)
    app = App(stdscr, db, load_art(art_path), allow_local, export_dir)
    if app.theme.level:
        stdscr.bkgd(" ", background_attr(app.theme))
    app.loop()


def run(db: AdvisoryDB, art_path: Path, allow_local: bool = False, export_dir: Path = Path("exports")) -> None:
    os.environ.setdefault("ESCDELAY", "25")
    locale.setlocale(locale.LC_ALL, "")
    curses.wrapper(_main, db, art_path, allow_local, export_dir)
