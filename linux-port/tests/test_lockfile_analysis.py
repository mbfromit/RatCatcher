import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.lockfile_analysis import analyze_lockfile

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')

class TestAnalyzeLockfile(unittest.TestCase):
    def test_npm_clean(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'CleanProject'))
        self.assertEqual(r.lockfile_type, 'npm')
        self.assertFalse(r.has_vulnerable_axios)
        self.assertFalse(r.has_malicious_plain_crypto)
        self.assertIsNone(r.error)

    def test_npm_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerableNpmProject'))
        self.assertEqual(r.lockfile_type, 'npm')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '1.14.1')
        self.assertTrue(r.has_malicious_plain_crypto)
        self.assertIsNone(r.error)

    def test_yarn_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerableYarnProject'))
        self.assertEqual(r.lockfile_type, 'yarn')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '0.30.4')
        self.assertTrue(r.has_malicious_plain_crypto)

    def test_pnpm_vulnerable(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'VulnerablePnpmProject'))
        self.assertEqual(r.lockfile_type, 'pnpm')
        self.assertTrue(r.has_vulnerable_axios)
        self.assertEqual(r.vulnerable_axios_version, '1.14.1')
        self.assertTrue(r.has_malicious_plain_crypto)

    def test_malformed_sets_error(self):
        r = analyze_lockfile(os.path.join(FIXTURES, 'MalformedProject'))
        self.assertIsNotNone(r.error)
        self.assertFalse(r.has_vulnerable_axios)

    def test_no_lockfile(self):
        with tempfile.TemporaryDirectory() as d:
            r = analyze_lockfile(d)
        self.assertIsNone(r.lockfile_type)
        self.assertFalse(r.has_vulnerable_axios)
        self.assertFalse(r.has_malicious_plain_crypto)

if __name__ == '__main__':
    unittest.main()
