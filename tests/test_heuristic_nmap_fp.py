import os
import re
import unittest

import yaml

HEUR = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'kb', 'heuristics.yaml')


class TestDiscoveryNmapFalsePositive(unittest.TestCase):
    """`nmap -sS` dagi 'sS -p' Linux `ss` buyrug'i deb T1057/T1049/T1083 bermasin."""

    def setUp(self):
        rules = yaml.safe_load(open(HEUR, encoding='utf-8'))
        found = [r for r in rules if r['name'].startswith('Discovery — fayl')]
        self.assertEqual(len(found), 1)
        self.rx = re.compile(found[0]['pattern'])

    def test_nmap_syn_scan_not_matched(self):
        for s in ['nmap -sS -p 22,3306,5432 10.0.2.0/24', 'nmap -sS 10.0.0.1']:
            self.assertIsNone(self.rx.search(s), s)

    def test_real_discovery_still_matched(self):
        for s in ['ss -tulpn', 'sudo ss -antp', 'ps aux', 'netstat -ano', 'find / -name id_rsa']:
            self.assertIsNotNone(self.rx.search(s), s)


if __name__ == '__main__':
    unittest.main()
