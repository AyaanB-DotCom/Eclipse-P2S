import unittest

from tests.helpers import load_db  # noqa: F401  (sets sys.path)
from core.versions import FINAL, PRERELEASE, UNRECOGNIZED, VENDOR_BUILD, compare_release, parse_version


class VersionTests(unittest.TestCase):
    def test_numeric_not_string_comparison(self):
        self.assertLess(compare_release(parse_version("8.3.9"), parse_version("8.3.36")), 0)
        self.assertLess(compare_release(parse_version("8.3.35"), parse_version("8.3.36")), 0)
        self.assertEqual(compare_release(parse_version("8.3.36"), parse_version("8.3.36")), 0)
        self.assertGreater(compare_release(parse_version("8.3.37"), parse_version("8.3.36")), 0)
        self.assertGreater(compare_release(parse_version("8.10.0"), parse_version("8.9.9")), 0)

    def test_parse_fields(self):
        v = parse_version(" 8.3.35 ")
        self.assertEqual((v.major, v.minor, v.patch, v.branch, v.kind), (8, 3, 35, "8.3", FINAL))

    def test_prefixes_accepted(self):
        self.assertEqual(parse_version("PHP/8.3.35").numeric, "8.3.35")
        self.assertEqual(parse_version("php 8.3.35").numeric, "8.3.35")

    def test_suffix_kinds(self):
        self.assertEqual(parse_version("8.3.36RC1").kind, PRERELEASE)
        self.assertEqual(parse_version("8.6.0RC4").kind, PRERELEASE)
        self.assertEqual(parse_version("8.3.36-dev").kind, PRERELEASE)
        self.assertEqual(parse_version("8.3.36-1ubuntu1").kind, VENDOR_BUILD)
        self.assertEqual(parse_version("8.3.36+dfsg-1").kind, VENDOR_BUILD)
        self.assertEqual(parse_version("8.3.36.1").kind, UNRECOGNIZED)
        self.assertEqual(parse_version("8.3.36foo").kind, UNRECOGNIZED)

    def test_malformed(self):
        for bad in ["", "abc", "8", "8.3", "8.3.", "8..3", "-8.3.1", "8.3.x", "8.3.35 8.3.36",
                    "8.3.35\x1b[31m", "٨.٣.٣٥", None, 8.3]:
            self.assertIsNone(parse_version(bad), repr(bad))


if __name__ == "__main__":
    unittest.main()
