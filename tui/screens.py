"""Screen content builders. Pure functions: no curses, so they are unit-testable.

A *line* is a list of (text, style) segments; style names map to the theme.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core import TOOL_VERSION
from core.assessment import (COVERAGE_UNKNOWN, INCONCLUSIVE, LEGACY_REVIEW, POTENTIAL_EXPOSURE,
                             THRESHOLD_MET, Assessment, AdvisoryDB)
from core.textsafe import display_width, sanitize_text
from .art import Art, fit_art

Segment = Tuple[str, str]
Line = List[Segment]

LABEL_W = 16
TAGLINE = "Beneath the Eclipse, nothing remains hidden."
MENU = [("01", "INSPECT TARGET"), ("02", "MANUAL VERSION"), ("03", "THE ARCHIVE"), ("04", "EXIT")]

STAGES = [("resolve", "Resolving target"), ("connect", "Establishing connection"),
          ("inspect", "Inspecting response"), ("identify", "Identifying PHP version"),
          ("compare", "Comparing advisory records"), ("prepare", "Preparing assessment")]

CLASS_STYLE = {POTENTIAL_EXPOSURE: "blood", LEGACY_REVIEW: "crimson", THRESHOLD_MET: "green",
               INCONCLUSIVE: "amber", COVERAGE_UNKNOWN: "amber"}


# ------------------------------------------------------------- primitives

def blank() -> Line:
    return []


def rule(width: int) -> Line:
    return [("-" * max(width, 0), "iron")]


def para(text: str, width: int, style: str = "ash", indent: int = 0) -> List[Line]:
    text = sanitize_text(text)
    pad = " " * indent
    wrapped = textwrap.wrap(text, max(width - indent, 8), break_long_words=True) or [""]
    return [[(pad + chunk, style)] for chunk in wrapped]


def kv(label: str, value: str, width: int, style: str = "bone") -> List[Line]:
    chunks = textwrap.wrap(sanitize_text(value), max(width - LABEL_W, 8), break_long_words=True) or [""]
    out: List[Line] = []
    for i, chunk in enumerate(chunks):
        head = label.ljust(LABEL_W) if i == 0 else " " * LABEL_W
        out.append([(head, "dim"), (chunk, style)])
    return out


def bullet_list(items: List[str], width: int, style: str = "ash") -> List[Line]:
    out: List[Line] = []
    for item in items:
        wrapped = textwrap.wrap(sanitize_text(item), max(width - 2, 8), break_long_words=True) or [""]
        for i, chunk in enumerate(wrapped):
            out.append([("- " if i == 0 else "  ", "iron"), (chunk, style)])
    return out


def footer_line(items: List[Tuple[str, str]], width: int) -> Line:
    """Key hints that always fit: widen the gaps if there is room, tighten them if not."""
    for gap in (3, 2, 1):
        line: Line = []
        for i, (key, label) in enumerate(items):
            line += [("[%s] " % key, "bone"), (label, "dim")]
            if i < len(items) - 1:
                line.append((" " * gap, "dim"))
        if sum(display_width(t) for t, _ in line) <= width:
            return line
    return [("[%s] " % k, "bone") for k, _ in items]


def lines_to_text(lines: List[Line]) -> str:
    return "\n".join("".join(seg for seg, _ in line) for line in lines)


# ----------------------------------------------------------------- results

# ------------------------------------------------------- THE BRAND (dashboard)

BIG_FONT = {
    "0": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "1": ["  #  ", " ##  ", "  #  ", "  #  ", " ### "],
    "2": [" ### ", "#   #", "  ## ", " #   ", "#####"],
    "3": ["#### ", "    #", " ### ", "    #", "#### "],
    "4": ["#   #", "#   #", "#####", "    #", "    #"],
    "5": ["#####", "#    ", "#### ", "    #", "#### "],
    "6": [" ### ", "#    ", "#### ", "#   #", " ### "],
    "7": ["#####", "    #", "   # ", "  #  ", " #   "],
    "8": [" ### ", "#   #", " ### ", "#   #", " ### "],
    "9": [" ### ", "#   #", " ####", "    #", " ### "],
    "/": ["    #", "   # ", "  #  ", " #   ", "#    "],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    " ": ["   "] * 5,
}
# Each of these is a situational caveat that duplicates a generic limitation; the details
# report states it once (evidence type / limitations) instead of repeating it.
_EVIDENCE_CAVEATS = ("The version is self-reported", "The version was typed")
LBL = 11


@dataclass
class ResultView:
    """Presentation state derived from an Assessment (or an inspection error)."""
    headline: str
    style: str
    score: Optional[str] = None       # "95 / 100", "N/A" or None (no score row at all)
    target: Optional[str] = None
    php: Optional[str] = None
    first_fix: Optional[str] = None
    omen: List[str] = field(default_factory=list)
    reminder: str = "Version-based assessment only. See details for limitations."


def view_from_assessment(a: Assessment) -> ResultView:
    c = a.classification
    score = "%d / 100" % a.risk_score if a.risk_score is not None else "N/A"
    v = ResultView(headline=c, style=CLASS_STYLE.get(c, "ash"), score=score,
                   target=a.target_url if a.mode == "url" else "manual entry (offline)",
                   php=a.version or "UNKNOWN")
    if c == POTENTIAL_EXPOSURE:
        v.first_fix = "PHP %s" % a.first_fixed
        v.omen = ["Reported PHP version predates the upstream fix.",
                  "Actual exploitability has not been verified."]
    elif c == THRESHOLD_MET:
        v.first_fix = "PHP %s" % a.first_fixed
        v.omen = ["Reported version meets the original PHP2Shell fix threshold.",
                  "Runtime and configuration not verified."]
        v.reminder = "Version-based only. CVE-2026-115560 is separate and not covered."
    elif c == LEGACY_REVIEW:
        v.first_fix = "none upstream (EOL branch)"
        v.omen = ["End-of-life branch: patch state is not visible in the version.",
                  "Ask your vendor about PHP2Shell backports."]
    elif c == COVERAGE_UNKNOWN:
        v.omen = [a.omen, "No assessment made."]
    elif a.omen.startswith("CONFLICTING"):
        v.omen = ["Conflicting PHP versions reported.", "No single version chosen."]
    else:
        v.omen = [a.omen, "Exposure cannot be determined."]
        if a.omen.startswith("No PHP version"):
            v.omen = ["No PHP version disclosed. Exposure cannot be determined."]
    return v


def view_from_error(message: str, target: str) -> ResultView:
    return ResultView(headline="INSPECTION FAILED", style="bone", score=None, target=target or None,
                      omen=[message], reminder="A failed inspection is not evidence of safety.")


def shorten(text: str, width: int) -> str:
    """Middle-ellipsis so both ends of a long URL stay visible."""
    text = sanitize_text(text)
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    head = (width - 3) // 2 + (width - 3) % 2
    return text[:head] + "..." + text[len(text) - (width - 3 - head):]


def big_text(text: str) -> List[str]:
    glyphs = [BIG_FONT.get(ch, BIG_FONT[" "]) for ch in text]
    return [" ".join(g[r] for g in glyphs) for r in range(5)]


@dataclass
class DRow:
    line: Line
    align: str = "left"   # "left" | "center"
    rank: int = 0         # 0 = always kept; higher ranks are dropped first when space is short


def dashboard_rows(v: ResultView, ch: int, inner: int) -> List[DRow]:
    """Rows for the compact result screen, fitted to `ch` rows and `inner` columns."""
    body = max(inner - 2, 10)
    wrap_w = max(body - 2, 10)

    def build(big: bool) -> List[DRow]:
        rows: List[DRow] = []
        add = lambda line, align="left", rank=0: rows.append(DRow(line, align, rank))
        add([("THE BRAND", "title")], rank=2)
        add([], rank=8)
        if v.target is not None:
            add([("TARGET".ljust(LBL), "dim"), (shorten(v.target, body - LBL), "bone")])
        if v.php is not None:
            add([("PHP".ljust(LBL), "dim"), (shorten(v.php, body - LBL), "bone")])
        add([], rank=9)
        add(rule(body), rank=6)
        add([], rank=7)
        if v.score is not None:
            if big and v.score != "N/A":
                for text in big_text(v.score):
                    add([(text, v.style)], "center")
            elif big:
                for text in big_text("N/A"):
                    add([(text, v.style)], "center")
            else:
                add([(v.score, v.style)], "center")
            add([], rank=7)
        add([(v.headline, v.style)], "center")
        add([], rank=7)
        add(rule(body), rank=6)
        if v.first_fix:
            add([("FIRST FIX".ljust(LBL), "dim"), (shorten(v.first_fix, body - LBL), "bone")], rank=1)
            add([], rank=7)
        add([("THE OMEN", "crimson")], rank=4)
        for i, text in enumerate(v.omen):
            for j, chunk in enumerate(textwrap.wrap(sanitize_text(text), wrap_w) or [""]):
                add([(chunk, "bone" if i == 0 else "ash")], rank=3 if (i or j) else 0)
        add([], rank=7)
        reminder = v.reminder
        if display_width(reminder) > body:
            reminder = reminder.split(". ")[0].rstrip(".") + "."
        add([(reminder[:body], "dim")], rank=5)
        return rows

    rows = build(True)
    if len(rows) > ch:
        rows = build(False)
    while len(rows) > ch:
        droppable = [i for i, r in enumerate(rows) if r.rank > 0]
        if not droppable:
            break
        top = max(rows[i].rank for i in droppable)
        del rows[[i for i in droppable if rows[i].rank == top][-1]]
    spare = ch - len(rows)
    if spare >= 2:
        rows = [DRow([], rank=0)] * (spare // 3) + rows
    return rows


def dashboard_text(rows: List[DRow], inner: int) -> str:
    out = []
    for r in rows:
        text = "".join(seg for seg, _ in r.line)
        out.append(text.center(inner).rstrip() if r.align == "center" else text)
    return "\n".join(out)


# ----------------------------------------------------- THE ARCHIVE (details)

def _section(title: str) -> List[Line]:
    return [blank(), [(title, "crimson")]]


def build_details_lines(a: Assessment, db: AdvisoryDB, width: int) -> List[Line]:
    style = CLASS_STYLE.get(a.classification, "ash")
    L: List[Line] = [[("THE ARCHIVE // DETAILED REPORT", "title")]]

    L += _section("TARGET INSPECTION")
    if a.mode == "url":
        L += kv("URL", a.target_url or "-", width)
        if a.final_url and a.final_url != a.target_url:
            L += kv("REDIRECTED TO", a.final_url, width)
        if a.http_status is not None:
            L += kv("HTTP STATUS", str(a.http_status), width)
    else:
        L += kv("MODE", "MANUAL (OFFLINE, NO NETWORK)", width)
    L += kv("ASSESSED", a.assessed_at or "-", width)

    L += _section("VERSION EVIDENCE")
    L += kv("PHP VERSION", a.version or "UNKNOWN", width, "bone" if a.version else "amber")
    for i, ev in enumerate(a.evidence_lines or ["none"]):
        L += kv("EVIDENCE" if i == 0 else "", ev, width, "bone" if a.evidence_lines else "dim")
    if a.mode == "url":
        L += kv("HEADER SOURCE", a.evidence_source or "none", width)
    quality = {"EXPLICIT HEADER DISCLOSURE": "EXPLICIT HEADER DISCLOSURE (self-reported, unverified)",
               "USER-SUPPLIED VERSION": "USER-SUPPLIED VERSION (not a server observation)"}
    L += kv("EVIDENCE TYPE", quality.get(a.evidence_quality, a.evidence_quality), width)

    L += _section("PHP2SHELL ASSESSMENT")
    L += kv("CVES", ", ".join(a.primary_cves), width)
    if a.first_fixed:
        threshold = "PHP %s (first fixed release of branch %s)" % (a.first_fixed, a.branch)
    elif a.classification == LEGACY_REVIEW:
        threshold = "none upstream; vendor or source backports may exist"
    else:
        threshold = "not applicable"
    L += kv("FIX THRESHOLD", threshold, width)
    L += kv("RISK SCORE", "%d / 100  (triage heuristic, not CVSS)" % a.risk_score
            if a.risk_score is not None else "N/A", width, style)
    L += kv("CLASSIFICATION", a.classification, width, style)
    L += kv("VERIFICATION", "NOT VERIFIED - no exploitation test performed", width, "dim")
    L += [blank()] + para(a.finding, width, "bone")
    caveats = [c for c in a.caveats if not c.startswith(_EVIDENCE_CAVEATS)]
    if caveats:
        L += [blank(), [("Caveats", "dim")]] + bullet_list(caveats, width)
    if a.notes:
        L += [blank(), [("Notes", "dim")]] + bullet_list(a.notes, width, "dim")

    L += _section("RELATED ADVISORIES")
    for rel in a.related:
        L += kv(rel["cve"], rel["date"] + ", not part of the score", width, "amber")
        L += [blank()] + para(rel["notice_text"], width)
        L += [blank()] + kv("MITIGATION", rel["mitigation"], width)

    L += _section("RECOMMENDATIONS")
    L += para(a.recommendation, width, "bone")
    L += [blank()] + bullet_list(db.data["mitigations"], width, "dim")

    L += _section("LIMITATIONS")
    L += bullet_list(a.limitations, width, "dim")

    L += _section("DATABASE")
    L += kv("SNAPSHOT", "%s, reviewed %s" % (a.db_version, a.db_reviewed), width)
    L += para(db.data.get("snapshot_notice", ""), width, "dim")
    L += [blank(), [("Official references (not fetched by this tool)", "dim")]]
    for s in db.data["sources"]:
        L += para("%s: %s" % (s["title"], s["url"]), width, "dim", 2)
    return L


def build_error_lines(message: str, kind: str, width: int) -> List[Line]:
    L: List[Line] = [[("INSPECTION FAILED", "blood")], blank()]
    L += para(message, width, "bone")
    L += [blank()] + kv("ERROR TYPE", kind, width, "dim") + [blank()]
    L += para("A failed inspection is not evidence that the target is safe or unsafe. No assessment was made.",
              width, "amber")
    return L


def build_archive_lines(db: AdvisoryDB, width: int) -> List[Line]:
    d = db.data
    L: List[Line] = [[("THE ARCHIVE // ADVISORY RECORDS", "title")], blank()]
    L += kv("DATABASE", d["database_version"], width)
    L += kv("LAST REVIEWED", d["last_reviewed"], width)
    L += kv("DISCLOSED", d["initial_disclosure"], width)
    L += para(d.get("snapshot_notice", ""), width, "amber")
    L += [blank(), rule(width), blank(), [("PHP2SHELL (SCORED)", "crimson")]]
    for e in d["primary_scope"]:
        L += [blank(), [(e["cve"], "bone"), ("  %s  CVSS v4.0 %s" % (e.get("ghsa", ""), e.get("cvss_v4", "?")), "dim")]]
        L += para(e["title"], width, "ash", 2)
        L += para(e.get("summary", ""), width, "dim", 2)
    L += [blank(), [("FIRST FIXED UPSTREAM RELEASES", "crimson")], blank()]
    for branch, ver in sorted(db.fixed.items()):
        last = d.get("last_prefix_versions", {}).get(branch, "-")
        L.append([("  PHP %s" % branch, "bone"), ("   last pre-fix %-8s" % last, "dim"),
                  ("first fixed ", "dim"), (ver.numeric, "green")])
    L += [blank(), [("LEGACY (PHP %s AND OLDER)" % d["legacy_policy"]["max_branch"], "crimson")]]
    L += para(d["legacy_policy"]["notes"], width, "ash")
    note = d.get("informational_notes", {}).get("prerelease_8_6")
    if note:
        L += [blank(), [("PHP 8.6 PRERELEASE", "crimson")]] + para(note, width, "ash")
    L += [blank(), rule(width), blank(), [("ADDITIONAL ADVISORY (NOT SCORED)", "amber")]]
    for rel in db.related:
        L += [blank(), [(rel["cve"], "bone"), ("  %s" % rel["date"], "dim")]]
        L += para(rel["summary"], width, "ash", 2)
        L += kv("  STATUS", rel["status_as_of_review"], width, "dim")
        L += kv("  MITIGATION", rel["mitigation"], width, "ash")
    L += [blank(), rule(width), blank(), [("MITIGATIONS", "crimson")]] + bullet_list(d["mitigations"], width)
    L += [blank(), [("SOURCES (NOT FETCHED BY THIS TOOL)", "crimson")]]
    for s in d["sources"]:
        L += para("%s: %s" % (s["title"], s["url"]), width, "dim", 2)
    L += [blank(), [("LIMITATIONS", "crimson")]] + bullet_list(db.limitations, width, "dim")
    return L


# -------------------------------------------------------------------- home

@dataclass
class Row:
    kind: str            # "art" | "text" | "menu" | "gap"
    text: str = ""
    style: str = "ash"
    index: int = -1      # menu index
    width: int = 0       # art block width


def home_rows(content_h: int, inner_w: int, art: Optional[Art]) -> List[Row]:
    """Layout of the opening screen for the available content area."""
    menu = [Row("menu", "%s   %s" % (num, name), index=i) for i, (num, name) in enumerate(MENU)]
    full = [Row("gap"), Row("text", "E C L I P S E", "title"), Row("text", "// P2S", "crimson"),
            Row("gap"), Row("text", "PHP2SHELL VERSION AUDITOR", "bone"),
            Row("text", TAGLINE, "dim"), Row("gap")] + menu
    compact = [Row("text", "E C L I P S E  //  P2S", "title"),
               Row("text", "PHP2SHELL VERSION AUDITOR", "bone"), Row("gap")] + menu
    body = full if content_h >= len(full) else compact
    lines = fit_art(art, inner_w, content_h - len(body) - 1) if art is not None else None
    rows: List[Row] = []
    if lines:
        rows += [Row("art", line, "art", width=art.width) for line in lines] + [Row("gap")]
    rows += body
    spare = content_h - len(rows)
    if spare > 1:
        rows = [Row("gap")] * (spare // 2) + rows
    return rows
