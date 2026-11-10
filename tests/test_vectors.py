"""Known vectors for the recovered built-in template and ECU signature predicate."""

import hashlib
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from generate_fsc import build_fsc, load_parameters, load_template


class KnownVectors(unittest.TestCase):
    def test_remote_start_app_ids(self):
        expected = {
            0x017C: '24ae475aaf4a7abdf38297c29acc8b50a04b21e53f6641805fdc08e98420379b',
            0x0180: 'da9b523b7029a05b203d9fb8f83a0e15ef74072cda36f353be1b7380d9943f2f',
        }
        params = load_parameters()
        for appid, sha256 in expected.items():
            with self.subTest(appid=f'{appid:04X}'):
                result = build_fsc(load_template(None, params), b'9J29436', appid, params)
                self.assertEqual(len(result.fsc), 188)
                self.assertEqual(hashlib.sha256(result.fsc).hexdigest(), sha256)
                self.assertTrue(result.weak_valid)
                self.assertFalse(result.strict_valid)


if __name__ == '__main__':
    unittest.main()
