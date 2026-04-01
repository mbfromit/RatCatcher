import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.forensic_artifacts import find_forensic_artifacts

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
VULN = os.path.join(FIXTURES, 'VulnerableNpmProject')
CLEAN = os.path.join(FIXTURES, 'CleanProject')

class TestFindForensicArtifacts(unittest.TestCase):
    def test_finds_malicious_package_dir(self):
        findings = find_forensic_artifacts(VULN)
        self.assertIn('MaliciousPackage', [f.type for f in findings])

    def test_finds_setup_js_high_severity(self):
        findings = find_forensic_artifacts(VULN)
        s = next((f for f in findings if f.type == 'MaliciousScript'), None)
        self.assertIsNotNone(s)
        self.assertEqual(s.severity, 'High')   # fixture hash != known malicious hash
        self.assertIsNotNone(s.hash)

    def test_finds_c2_indicator_in_js(self):
        findings = find_forensic_artifacts(VULN)
        c2 = [f for f in findings if f.type == 'C2Indicator']
        self.assertTrue(len(c2) > 0)
        self.assertEqual(c2[0].severity, 'Critical')

    def test_clean_project_no_findings(self):
        self.assertEqual(find_forensic_artifacts(CLEAN), [])

if __name__ == '__main__':
    unittest.main()
