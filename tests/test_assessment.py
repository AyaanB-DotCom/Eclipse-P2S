import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import DB_PATH, load_db
from core import assessment as A
from core.fingerprint import extract_php_version


class VersionMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = load_db()

    def cls(self, v):
        return A.assess_manual(self.db, v)

    def test_matrix(self):
        cases = {
            "8.2.34": A.POTENTIAL_EXPOSURE, "8.2.35": A.THRESHOLD_MET,
            "8.3.35": A.POTENTIAL_EXPOSURE, "8.3.36": A.THRESHOLD_MET,
            "8.4.26": A.POTENTIAL_EXPOSURE, "8.4.27": A.THRESHOLD_MET,
            "8.5.11": A.POTENTIAL_EXPOSURE, "8.5.12": A.THRESHOLD_MET,
            "8.3.37": A.THRESHOLD_MET, "8.3.9": A.POTENTIAL_EXPOSURE,
            "8.1.34": A.LEGACY_REVIEW, "7.4.33": A.LEGACY_REVIEW, "8.0.30": A.LEGACY_REVIEW,
            "5.6.40": A.LEGACY_REVIEW,
            "8.6.0RC4": A.COVERAGE_UNKNOWN, "9.0.0": A.COVERAGE_UNKNOWN, "8.6.1": A.COVERAGE_UNKNOWN,
            "8.3.36RC1": A.INCONCLUSIVE, "8.3.36.1": A.INCONCLUSIVE,
            "garbage": A.INCONCLUSIVE, "": A.INCONCLUSIVE,
        }
        for version, expected in cases.items():
            self.assertEqual(self.cls(version).classification, expected, version)

    def test_each_branch_uses_its_own_threshold(self):
        self.assertEqual(self.cls("8.3.40").classification, A.THRESHOLD_MET)
        self.assertEqual(self.cls("8.5.11").first_fixed, "8.5.12")
        self.assertEqual(self.cls("8.2.34").first_fixed, "8.2.35")

    def test_scores(self):
        self.assertEqual(self.cls("8.3.35").risk_score, 95)
        self.assertEqual(self.cls("8.3.36").risk_score, 0)
        self.assertEqual(self.cls("8.1.34").risk_score, 90)
        for v in ("junk", "9.0.0", "8.6.0RC4", "8.3.36RC1"):
            self.assertIsNone(self.cls(v).risk_score, v)

    def test_vendor_backport_uncertainty_is_stated(self):
        a = self.cls("8.3.35")
        self.assertTrue(any("backport" in c.lower() for c in a.caveats))
        legacy = self.cls("7.4.33")
        self.assertTrue(any("vendor" in c.lower() for c in legacy.caveats))
        self.assertNotIn("confirmed vulnerable", (a.finding + legacy.finding).lower())

    def test_vendor_suffix_noted(self):
        a = self.cls("8.3.35-1ubuntu1")
        self.assertEqual(a.classification, A.POTENTIAL_EXPOSURE)
        self.assertTrue(any("build suffix" in c for c in a.caveats))

    def test_threshold_met_is_never_a_security_claim(self):
        a = self.cls("8.3.36")
        text = " ".join([a.finding, a.recommendation] + a.caveats).lower()
        self.assertIn("does not establish", text)
        self.assertNotIn("safe", a.omen.lower())

    def test_related_advisory_separate_from_score(self):
        for v in ("8.3.35", "8.3.36", "junk", "9.0.0"):
            a = self.cls(v)
            self.assertEqual([r["cve"] for r in a.related], ["CVE-2026-115560"])
            self.assertNotIn("CVE-2026-115560", a.primary_cves)
        self.assertNotIn("CVE-2026-115560", self.cls("8.3.35").finding)
        self.assertIn("115560", self.cls("8.3.36").finding)  # only as "separate issue" wording
        self.assertIn("separate", self.cls("8.3.36").finding)

    def test_manual_labelled_as_user_supplied(self):
        a = self.cls("8.3.35")
        self.assertEqual(a.evidence_quality, A.QUALITY_MANUAL)
        self.assertEqual(a.mode, "manual")

    def test_manual_mode_makes_no_network_calls(self):
        boom = mock.Mock(side_effect=AssertionError("network used"))
        with mock.patch.object(socket, "socket", boom), mock.patch.object(socket, "getaddrinfo", boom), \
                mock.patch.object(socket, "create_connection", boom):
            self.assertEqual(A.assess_manual(self.db, "8.4.26").classification, A.POTENTIAL_EXPOSURE)

    def test_unknown_never_reported_safe(self):
        for headers in ([], [("X-Powered-By", "PHP/8.3.35"), ("Server", "PHP/8.4.27")]):
            a = A.assess_fingerprint(self.db, extract_php_version(headers), target_url="https://x.test/",
                                     final_url="https://x.test/", http_status=200)
            self.assertEqual(a.classification, A.INCONCLUSIVE)
            self.assertIsNone(a.risk_score)
            self.assertIsNone(a.version)
            self.assertNotEqual(a.risk_score, 0)

    def test_no_version_text(self):
        a = A.assess_fingerprint(self.db, extract_php_version([("Server", "nginx")]), target_url="u",
                                 final_url="u", http_status=200)
        self.assertEqual(a.finding, A.NO_VERSION_FINDING)

    def test_conflict_text(self):
        a = A.assess_fingerprint(
            self.db, extract_php_version([("X-Powered-By", "PHP/8.3.35"), ("Server", "PHP/8.3.36")]),
            target_url="u", final_url="u", http_status=200)
        self.assertIn("CONFLICTING VERSION EVIDENCE", a.finding)
        self.assertIn("8.3.35", a.finding)

    def test_header_evidence_quality(self):
        a = A.assess_fingerprint(self.db, extract_php_version([("X-Powered-By", "PHP/8.3.35")]),
                                 target_url="u", final_url="u", http_status=200)
        self.assertEqual((a.version, a.evidence_quality, a.classification),
                         ("8.3.35", A.QUALITY_HEADER, A.POTENTIAL_EXPOSURE))
        self.assertTrue(any("self-reported" in c for c in a.caveats))


class DatabaseTests(unittest.TestCase):
    def write(self, text):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "a.json"
        p.write_text(text, encoding="utf-8")
        return p

    def test_bundled_database_valid(self):
        db = A.load_advisories(DB_PATH)
        self.assertEqual(db.fixed["8.3"].numeric, "8.3.36")
        self.assertEqual(db.primary_cves, ["CVE-2026-109618", "CVE-2026-109619"])

    def test_missing_file(self):
        with self.assertRaises(A.AdvisoryError):
            A.load_advisories(Path("/nonexistent/advisories.json"))

    def test_malformed_json(self):
        with self.assertRaises(A.AdvisoryError):
            A.load_advisories(self.write("{not json"))

    def test_wrong_schema(self):
        data = json.loads(DB_PATH.read_text())
        data["schema_version"] = 99
        with self.assertRaises(A.AdvisoryError):
            A.load_advisories(self.write(json.dumps(data)))

    def test_bad_fixed_version(self):
        for mutate in (lambda d: d["fixed_upstream_versions"].update({"8.3": "8.4.1"}),
                       lambda d: d["fixed_upstream_versions"].update({"8.3": "oops"}),
                       lambda d: d["scoring"].update({"potential_exposure": 500}),
                       lambda d: d["related_advisories"][0].update({"included_in_primary_score": True}),
                       lambda d: d.pop("primary_scope"),
                       lambda d: d["legacy_policy"].update({"max_branch": "8.3"})):
            data = json.loads(DB_PATH.read_text())
            mutate(data)
            with self.assertRaises(A.AdvisoryError):
                A.load_advisories(self.write(json.dumps(data)))

    def test_root_not_object(self):
        with self.assertRaises(A.AdvisoryError):
            A.load_advisories(self.write("[]"))


if __name__ == "__main__":
    unittest.main()
