import unittest

from tests.helpers import load_db  # noqa: F401
from core.fingerprint import CONFLICT, FOUND, NONE, extract_php_version


class FingerprintTests(unittest.TestCase):
    def test_x_powered_by(self):
        r = extract_php_version([("X-Powered-By", "PHP/8.3.35")])
        self.assertEqual((r.status, r.version, r.sources), (FOUND, "8.3.35", "X-Powered-By"))
        self.assertEqual(r.evidence[0].value, "PHP/8.3.35")

    def test_header_casing_and_whitespace(self):
        for name in ("x-powered-by", "X-POWERED-BY", "  X-Powered-By "):
            r = extract_php_version([(name, "  php/8.3.35  ")])
            self.assertEqual(r.version, "8.3.35", name)

    def test_server_header_token(self):
        r = extract_php_version({"Server": "Apache/2.4.58 (Ubuntu) PHP/8.2.35"})
        self.assertEqual(r.version, "8.2.35")

    def test_multiple_identical_values_ok(self):
        r = extract_php_version([("X-Powered-By", "PHP/8.3.35"), ("Server", "Apache PHP/8.3.35")])
        self.assertEqual((r.status, r.version), (FOUND, "8.3.35"))
        self.assertEqual(len(r.evidence), 2)

    def test_conflict(self):
        r = extract_php_version([("X-Powered-By", "PHP/8.3.35"), ("X-Powered-By", "PHP/8.3.36")])
        self.assertEqual(r.status, CONFLICT)
        self.assertEqual(sorted(r.conflicting), ["8.3.35", "8.3.36"])
        self.assertEqual(r.version, "")

    def test_no_evidence_from_other_signals(self):
        headers = [("Set-Cookie", "PHPSESSID=abc"), ("Server", "nginx/1.25.0"), ("X-Powered-By", "WordPress"),
                   ("X-Generator", "Drupal 10"), ("X-Powered-By", "Laravel"), ("Link", "</x.php>; rel=x"),
                   ("Content-Type", "text/html; PHP/8.3.35"), ("X-Debug", "PHP/8.3.35")]
        r = extract_php_version(headers)
        self.assertEqual(r.status, NONE)

    def test_partial_version_not_used(self):
        r = extract_php_version([("X-Powered-By", "PHP/8.3")])
        self.assertEqual(r.status, NONE)
        self.assertTrue(r.ignored)

    def test_malformed_inputs_do_not_crash(self):
        self.assertEqual(extract_php_version(None).status, NONE)
        self.assertEqual(extract_php_version([("X-Powered-By",), 5, ("Server", "PHP/")]).status, NONE)
        self.assertEqual(extract_php_version([("X-Powered-By", "mod_php/8.3.35")]).status, NONE)

    def test_spoofed_header_is_reported_as_is(self):
        # The fingerprint layer cannot know a header is false; limitation documented.
        self.assertEqual(extract_php_version([("X-Powered-By", "PHP/8.5.99")]).version, "8.5.99")

    def test_control_characters_sanitised(self):
        r = extract_php_version([("X-Powered-By", "\x1b[2J PHP/8.3.35\x07")])
        for ev in r.evidence:
            self.assertNotIn("\x1b", ev.value)
            self.assertNotIn("\x07", ev.value)


if __name__ == "__main__":
    unittest.main()
