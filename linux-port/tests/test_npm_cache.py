import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from unittest.mock import MagicMock, patch
from checks.npm_cache import scan_npm_cache


def _mock_run(stdout, returncode=0):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


class TestScanNpmCache(unittest.TestCase):
    def test_finds_malicious_entry_in_cache_index(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            index_dir = os.path.join(cache_dir, '_cacache', 'index-v5', 'ab')
            os.makedirs(index_dir)
            index_file = os.path.join(index_dir, 'abc123')
            with open(index_file, 'w') as f:
                f.write('plain-crypto-js/-/plain-crypto-js-4.2.1.tgz\n')

            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = [
                    _mock_run(cache_dir + '\n'),      # npm config get cache
                    _mock_run('/nonexistent\n'),       # npm root -g
                ]
                findings = scan_npm_cache()

        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].type, 'NpmCacheHit')
        self.assertIn('4.2.1', findings[0].detail)
        self.assertEqual(findings[0].severity, 'High')

    def test_npm_unavailable_returns_empty(self):
        with patch('subprocess.run', side_effect=FileNotFoundError):
            findings = scan_npm_cache()
        self.assertEqual(findings, [])

    def test_empty_cache_returns_empty(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch('subprocess.run') as mock_run:
                mock_run.side_effect = [
                    _mock_run(cache_dir + '\n'),
                    _mock_run('/nonexistent\n'),
                ]
                findings = scan_npm_cache()
        self.assertEqual(findings, [])

if __name__ == '__main__':
    unittest.main()
