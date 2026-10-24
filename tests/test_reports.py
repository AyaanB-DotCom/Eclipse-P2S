import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.helpers import load_db
from core import assessment as A
from core.fingerprint import extract_php_version
from core.reports import build_report, export_report, safe_filename, utc_timestamp

REQUIRED = ["tool_name", "tool_version", "assessment_timestamp", "assessment_mode", "target_url", "final_url",
            "http_status", "reported_php_version", "version_evidence_source", "evidence_quality",
            "first_fixed_upstream_version", "risk_score", "risk_classification", "primary_cves",
            "related_advisories", "advisory_database_version", "advisory_last_reviewed", "recommendation",
            "limitations"]
NOW = datetime(2026, 10, 23, 12, 30, 5, tzinfo=timezone.utc)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def url_assessment(self, headers):
        return A.assess_fingerprint(self.db, extract_php_version(headers),
                                    target_url="https://user:secret@Example.com/p?token=abc#x",
                                    final_url="https://example.com/p?token=abc", http_status=200)

    def test_required_fields_and_manual_report(self):
        r = build_report(A.assess_manual(self.db, "8.3.35"), NOW)
        for key in REQUIRED:
            self.assertIn(key, r)
        self.assertEqual(r["assessment_mode"], "manual")
        self.assertEqual(r["version_origin"], "user_supplied")
        self.assertIsNone(r["target_url"])
        self.assertIsNone(r["http_status"])
        self.assertEqual(r["risk_score"], 95)
        self.assertEqual(r["first_fixed_upstream_version"], "8.3.36")
        self.assertEqual(r["related_advisories"][0]["cve"], "CVE-2026-115560")
        self.assertFalse(r["related_advisories"][0]["included_in_primary_score"])
        json.dumps(r)

    def test_url_report_observed_and_redacted(self):
        r = build_report(self.url_assessment([("X-Powered-By", "PHP/8.3.36")]), NOW)
        self.assertEqual(r["version_origin"], "remotely_observed")
        self.assertEqual(r["version_evidence_source"], "X-Powered-By")
        dumped = json.dumps(r)
        for secret in ("secret", "token=abc", "user:"):
            self.assertNotIn(secret, dumped)
        self.assertEqual(r["target_url"], "https://example.com/p")

    def test_unknown_values_are_null(self):
        r = build_report(self.url_assessment([]), NOW)
        self.assertIsNone(r["reported_php_version"])
        self.assertIsNone(r["risk_score"])
        self.assertIsNone(r["first_fixed_upstream_version"])
        self.assertEqual(r["risk_classification"], A.INCONCLUSIVE)
        self.assertIsNone(r["version_origin"])

    def test_timestamp_format(self):
        self.assertEqual(utc_timestamp(NOW), "2026-10-23T12:30:05Z")
        self.assertTrue(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", utc_timestamp()))

    def test_export_is_safe_and_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            out_dir = Path(d) / "exports"
            self.assertFalse(out_dir.exists())
            a = self.url_assessment([("X-Powered-By", "PHP/8.3.35")])
            a.target_url = "https://../../evil name/x"
            p1 = export_report(a, out_dir, NOW)
            p2 = export_report(a, out_dir, NOW)
            self.assertNotEqual(p1, p2)
            self.assertEqual(p1.parent, out_dir)
            self.assertRegex(p1.name, r"^[A-Za-z0-9._-]+$")
            self.assertEqual(json.loads(p1.read_text())["tool_name"], "ECLIPSE // P2S")

    def test_filename_manual(self):
        self.assertEqual(safe_filename(A.assess_manual(self.db, "8.3.35"), NOW),
                         "eclipse-p2s_manual_20261023T123005Z.json")


if __name__ == "__main__":
    unittest.main()
