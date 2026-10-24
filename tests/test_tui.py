import tempfile
import unittest
from pathlib import Path

from tests.helpers import ROOT, load_db
from core import assessment as A
from core.textsafe import clip, display_width, redact_url, sanitize_text
from tui import screens
from tui.art import fit_art, load_art, parse_art
from tui.theme import build_theme


class SanitizeTests(unittest.TestCase):
    def test_escape_sequences_neutralised(self):
        out = sanitize_text("\x1b[2J\x1b]0;pwn\x07hello\r\n\x00\u202e\u200b")
        for ch in "\x1b\x07\r\n\x00\u202e\u200b":
            self.assertNotIn(ch, out)
        self.assertIn("hello", out)

    def test_truncation(self):
        self.assertTrue(sanitize_text("a" * 5000, 100).endswith("..."))

    def test_clip_and_width(self):
        self.assertEqual(clip("abcdef", 3), "abc")
        self.assertEqual(display_width("\u6f22\u5b57"), 4)
        self.assertEqual(clip("\u6f22\u5b57", 3), "\u6f22")

    def test_redact(self):
        self.assertEqual(redact_url("https://u:p@h.test:8080/a?t=1#f"), "https://h.test:8080/a")


class ArtTests(unittest.TestCase):
    def test_absent_file(self):
        self.assertIsNone(load_art(Path("/nonexistent/berserk.txt")))

    def test_empty_and_blank_only(self):
        self.assertIsNone(parse_art(""))
        self.assertIsNone(parse_art("\n   \n\u2800\u2800\n"))

    def test_bundled_art_loads_and_is_untouched(self):
        art = load_art(ROOT / "assets" / "berserk.txt")
        if art is None:
            self.skipTest("no artwork supplied")
        self.assertGreater(art.width, 0)

    def test_unusual_characters_and_long_lines(self):
        art = parse_art("\x1b[31mred\x1b[0m\n\u2800\u28ff\u28ff\ttab\n" + "x" * 500 + "\n\u6f22\u5b57\n")
        self.assertIsNotNone(art)
        for line in art.lines:
            self.assertNotIn("\x1b", line)
            self.assertNotIn("\t", line)
        self.assertGreaterEqual(art.width, 500)
        self.assertIsNone(fit_art(art, 80, 40))  # too wide: hidden, never wrapped or cropped sideways

    def test_fit_and_crop(self):
        art = parse_art("\n".join("#" * 20 for _ in range(30)))
        self.assertEqual(len(fit_art(art, 60, 40)), 30)
        self.assertEqual(len(fit_art(art, 60, 12)), 12)   # cropped
        self.assertIsNone(fit_art(art, 60, 5))            # too short: hidden
        self.assertIsNone(fit_art(None, 60, 40))

    def test_art_alignment_preserved(self):
        art = parse_art("  a\n b\nccc")
        self.assertEqual(art.lines, ["  a", " b", "ccc"])


class ScreenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def test_home_without_art(self):
        for h in (8, 14, 20, 40):
            rows = screens.home_rows(h, 70, None)
            self.assertEqual(len([r for r in rows if r.kind == "menu"]), 4)
            self.assertFalse([r for r in rows if r.kind == "art"])

    def test_home_art_never_overflows(self):
        art = parse_art("\n".join("#" * 61 for _ in range(30)))
        for h in range(10, 60):
            for w in (30, 60, 61, 62, 80):
                rows = screens.home_rows(h, w, art)
                arts = [r for r in rows if r.kind == "art"]
                if arts:
                    self.assertLessEqual(arts[0].width, w)
                    self.assertLessEqual(len(rows), max(h, len(rows)) if h < 12 else h)
                if w < 61:
                    self.assertFalse(arts)

    def test_home_rows_fit_height_when_reasonable(self):
        art = parse_art("\n".join("#" * 40 for _ in range(30)))
        for h in range(16, 60):
            self.assertLessEqual(len(screens.home_rows(h, 70, art)), h)

    def test_details_render_all_classes(self):
        for v in ("8.3.35", "8.3.36", "7.4.33", "9.0.0", "junk"):
            a = A.assess_manual(self.db, v)
            for width in (50, 60, 80):
                text = screens.lines_to_text(screens.build_details_lines(a, self.db, width))
                for needle in ("THE ARCHIVE // DETAILED REPORT", "TARGET INSPECTION", "VERSION EVIDENCE",
                               "PHP2SHELL ASSESSMENT", "RELATED ADVISORIES", "CVE-2026-115560",
                               "RECOMMENDATIONS", "LIMITATIONS", "DATABASE", a.classification,
                               "2026.10.23", "https://www.php.net/archive/2026.php"):
                    self.assertIn(needle, text)
                self.assertNotIn("VULNERABLE CONFIRMED", text.upper())
                for line in text.split("\n"):
                    self.assertLessEqual(len(line), width + 2, line)

    def test_details_keep_technical_findings(self):
        a = A.assess_manual(self.db, "8.3.35")
        text = screens.lines_to_text(screens.build_details_lines(a, self.db, 80))
        for needle in (a.finding[:40], "backport", "CVE-2026-109618, CVE-2026-109619", "8.3.36",
                       "95 / 100", "triage heuristic, not CVSS", "NOT VERIFIED", "memory_limit"):
            self.assertIn(needle, text)

    def test_details_header_and_redirect_info(self):
        from core.fingerprint import extract_php_version
        a = A.assess_fingerprint(self.db, extract_php_version([("X-Powered-By", "PHP/8.3.35")]),
                                 target_url="http://x.test/", final_url="https://x.test/home", http_status=200)
        text = screens.lines_to_text(screens.build_details_lines(a, self.db, 80))
        for needle in ("REDIRECTED TO", "https://x.test/home", "HTTP STATUS", "200", "HEADER SOURCE",
                       "X-Powered-By", "self-reported, unverified", "ASSESSED"):
            self.assertIn(needle, text)

    def test_inconclusive_details_have_no_safe_claim(self):
        from core.fingerprint import extract_php_version
        a = A.assess_fingerprint(self.db, extract_php_version([]), target_url="https://x.test/",
                                 final_url="https://x.test/", http_status=200)
        text = screens.lines_to_text(screens.build_details_lines(a, self.db, 78))
        self.assertIn("N/A", text)
        self.assertIn("cannot be determined", text)

    def test_untrusted_text_sanitised_in_details(self):
        from core.fingerprint import extract_php_version
        a = A.assess_fingerprint(self.db, extract_php_version([("X-Powered-By", "\x1b[2J PHP/8.3.35")]),
                                 target_url="https://x.test/\x1b[2J", final_url=None, http_status=200)
        self.assertNotIn("\x1b", screens.lines_to_text(screens.build_details_lines(a, self.db, 78)))
        v = screens.view_from_assessment(a)
        self.assertNotIn("\x1b", screens.dashboard_text(screens.dashboard_rows(v, 18, 76), 76))

    def test_archive_and_error_lines(self):
        self.assertIn("8.3.36", screens.lines_to_text(screens.build_archive_lines(self.db, 70)))
        err = screens.lines_to_text(screens.build_error_lines("boom \x1b[0m", "dns", 60))
        self.assertNotIn("\x1b", err)
        self.assertIn("not evidence", err)


SIZES = [(80, 24), (100, 30), (120, 40), (60, 16), (44, 12)]


def dash(a, w, h, error=None, target=""):
    inner = min(w, 84) - 4
    ch = h - 6
    view = screens.view_from_error(error, target) if error else screens.view_from_assessment(a)
    rows = screens.dashboard_rows(view, ch, inner)
    return rows, screens.dashboard_text(rows, inner), ch, inner


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def manual(self, v):
        return A.assess_manual(self.db, v)

    def test_state_a_potential_exposure(self):
        v = screens.view_from_assessment(self.manual("8.3.35"))
        self.assertEqual((v.score, v.headline, v.style, v.first_fix, v.php), ("95 / 100", "POTENTIAL EXPOSURE", "blood", "PHP 8.3.36", "8.3.35"))
        _, text, _, _ = dash(self.manual("8.3.35"), 80, 24)
        for needle in ("THE BRAND", "95 / 100", "POTENTIAL EXPOSURE", "FIRST FIX", "PHP 8.3.36", "THE OMEN",
                       "predates the upstream fix", "exploitability has not been verified"):
            self.assertIn(needle, text)

    def test_state_b_threshold_met_is_not_a_safety_claim(self):
        v = screens.view_from_assessment(self.manual("8.3.36"))
        self.assertEqual((v.score, v.headline, v.style), ("0 / 100", "ORIGINAL FIX THRESHOLD MET", "green"))
        _, text, _, _ = dash(self.manual("8.3.36"), 80, 24)
        self.assertIn("meets the original PHP2Shell fix threshold", text)
        self.assertIn("CVE-2026-115560", text)
        for banned in ("SAFE", "SECURE", "NOT VULNERABLE"):
            self.assertNotIn(banned, text.upper().replace("UNSAFE", ""))

    def test_state_c_inconclusive(self):
        from core.fingerprint import extract_php_version
        a = A.assess_fingerprint(self.db, extract_php_version([]), target_url="https://x.test/",
                                 final_url="https://x.test/", http_status=200)
        v = screens.view_from_assessment(a)
        self.assertEqual((v.score, v.headline, v.first_fix, v.php), ("N/A", "INCONCLUSIVE", None, "UNKNOWN"))
        _, text, _, _ = dash(a, 80, 24)
        self.assertIn("No PHP version disclosed", text)
        self.assertNotIn("FIRST FIX", text)
        self.assertNotIn("/ 100", text)

    def test_legacy_conflict_unknown_and_error_views(self):
        from core.fingerprint import extract_php_version
        legacy = screens.view_from_assessment(self.manual("7.4.33"))
        self.assertEqual((legacy.score, legacy.headline), ("90 / 100", "LEGACY PATCH REVIEW"))
        conflict = A.assess_fingerprint(
            self.db, extract_php_version([("X-Powered-By", "PHP/8.3.35"), ("Server", "PHP/8.3.36")]),
            target_url="u", final_url="u", http_status=200)
        cv = screens.view_from_assessment(conflict)
        self.assertEqual((cv.score, cv.headline, cv.first_fix), ("N/A", "INCONCLUSIVE", None))
        self.assertIn("Conflicting", cv.omen[0])
        unknown = screens.view_from_assessment(self.manual("9.0.0"))
        self.assertEqual((unknown.score, unknown.headline), ("N/A", "ADVISORY COVERAGE UNKNOWN"))
        err = screens.view_from_error("Connection refused", "https://x.test/")
        self.assertIsNone(err.score)
        _, text, _, _ = dash(None, 80, 24, error="Connection to x refused.", target="https://x.test/")
        self.assertIn("INSPECTION FAILED", text)
        self.assertNotIn("N/A", text)
        self.assertNotIn("/ 100", text)

    def test_fits_every_size_and_keeps_score_and_class(self):
        assessments = [self.manual(v) for v in ("8.3.35", "8.3.36", "7.4.33", "9.0.0", "junk")]
        for a in assessments:
            for w, h in SIZES:
                rows, text, ch, inner = dash(a, w, h)
                self.assertLessEqual(len(rows), ch, (a.classification, w, h))
                self.assertIn(a.classification, text, (w, h))
                if a.risk_score is not None and "#   #" not in text:  # big digits replace the plain score
                    self.assertIn("%d / 100" % a.risk_score, text)
                for line in text.split("\n"):
                    self.assertLessEqual(len(line), inner, line)

    def test_80x24_shows_everything_primary(self):
        rows, text, ch, _ = dash(self.manual("8.3.35"), 80, 24)
        self.assertEqual(ch, 18)
        for needle in ("TARGET", "PHP", "95 / 100", "POTENTIAL EXPOSURE", "FIRST FIX", "THE OMEN",
                       "Version-based assessment only"):
            self.assertIn(needle, text)

    def test_big_score_on_tall_terminals(self):
        _, text, _, _ = dash(self.manual("8.3.35"), 120, 40)
        self.assertIn("#####", text)
        self.assertEqual(len(screens.big_text("95 / 100")), 5)
        self.assertEqual(len(set(len(r) for r in screens.big_text("0 / 100"))), 1)

    def test_long_target_is_shortened_in_bounds(self):
        long_url = "https://example.com/" + "a" * 400 + "/end"
        a = self.manual("8.3.35")
        a.mode, a.target_url = "url", long_url
        rows, text, ch, inner = dash(a, 80, 24)
        self.assertIn("...", text)
        self.assertIn("end", text)
        for line in text.split("\n"):
            self.assertLessEqual(len(line), inner)
        self.assertEqual(screens.shorten("abcdefghij", 7), "ab...ij")
        self.assertEqual(len(screens.shorten("x" * 100, 20)), 20)

    def test_footer_always_fits(self):
        items = [("N", "NEW"), ("D", "DETAILS"), ("E", "EXPORT"), ("Q", "QUIT")]
        for width in range(20, 100):
            line = screens.footer_line(items, width)
            text = "".join(t for t, _ in line)
            self.assertLessEqual(len(text), max(width, 16))
            self.assertIn("[N]", text)
            self.assertIn("[Q]", text) if width >= 40 else None
        self.assertIn("DETAILS", "".join(t for t, _ in screens.footer_line(items, 60)))


class ThemeTests(unittest.TestCase):
    def test_monochrome_fallback(self):
        theme = build_theme(0)
        for name in ("bone", "ash", "dim", "iron", "crimson", "blood", "amber", "green", "title", "select"):
            self.assertIsInstance(theme.attr(name), int)
        self.assertIsInstance(theme.attr("unknown-style"), int)
        self.assertEqual(theme.level, 0)


if __name__ == "__main__":
    unittest.main()
