import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks import Finding

class TestFinding(unittest.TestCase):
    def test_fields(self):
        f = Finding(
            type='MaliciousPackage', path='/tmp/foo', detail='bar',
            severity='Critical', description='desc', hash='abc123'
        )
        self.assertEqual(f.type, 'MaliciousPackage')
        self.assertEqual(f.severity, 'Critical')
        self.assertIsNone(Finding(
            type='x', path='y', detail=None,
            severity='High', description='d', hash=None
        ).hash)

if __name__ == '__main__':
    unittest.main()
