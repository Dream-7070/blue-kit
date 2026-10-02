import os
import re
import unittest
import yaml
from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.siem.catalog import HUNTS
from bluekit.siem.builder import build_query
from bluekit.siem.dialects import DIALECTS, SOURCE_MAPS


class TestICS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        heur_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit', 'kb', 'heuristics.yaml')
        with open(heur_path, 'r', encoding='utf-8') as f:
            cls.heuristics = yaml.safe_load(f)
            
        cls.ics_heuristics = [h for h in cls.heuristics if any(t.startswith('T0') or t.startswith('T1692') or t.startswith('T1694') for t in h['techniques']) or 'ICS' in h.get('name', '')]
        
    @unittest.skipUnless(os.path.exists(get_kb_path()), 'KB mavjud emas')
    def test_01_all_ics_ids_active(self):
        kb = KB()
        ids = set()
        for h in self.heuristics:
            for t in h.get('techniques', []):
                if t.startswith('T0'):
                    ids.add(t)
        for hid, hunt in HUNTS.items():
            if hid.startswith('ics-'):
                for t in hunt.get('attack', []):
                    if t.startswith('T0'):
                        ids.add(t)
        ids = list(ids)
        res = kb.validate(ids)
        for r in res:
            self.assertTrue(r['found'], f"{r['normalized']} KB da topilmadi")
            self.assertEqual(r['status'], 'active', f"{r['normalized']} statusi active emas")

    def test_02_heuristics_count(self):
        t0_count = len([h for h in self.heuristics if any(t.startswith('T0') for t in h['techniques'])])
        self.assertGreaterEqual(t0_count, 20)

    def test_03_patterns_compile(self):
        for h in self.ics_heuristics:
            try:
                re.compile(h['pattern'])
            except re.error as e:
                self.fail(f"Pattern xato: {h['pattern']} - {e}")

    def test_04_pattern_match_positive(self):
        matched = False
        text = "PLC STOP command sent to station 3"
        for h in self.ics_heuristics:
            if re.search(h['pattern'], text):
                matched = True
                break
        self.assertTrue(matched, "Hech bir naqsh PLC STOP ga mos kelsmadi")

    def test_05_pattern_match_negative(self):
        text1 = "user logged in successfully"
        text2 = "GET /index.html 200"
        for h in self.ics_heuristics:
            self.assertFalse(re.search(h['pattern'], text1), f"Shovqinli naqsh: {h['name']} - {text1}")
            self.assertFalse(re.search(h['pattern'], text2), f"Shovqinli naqsh: {h['name']} - {text2}")

    def test_06_five_hunts_added(self):
        ics_hunts = [hid for hid in HUNTS if hid.startswith('ics-')]
        self.assertEqual(len(ics_hunts), 5)
        self.assertEqual(len(HUNTS), 37)

    def test_07_render_all_dialects(self):
        ics_hunts = [hid for hid in HUNTS if hid.startswith('ics-')]
        for hid in ics_hunts:
            for siem in DIALECTS:
                res = build_query(hid, siem)
                self.assertTrue(res['query'].strip())
                self.assertNotIn('TODO', res['query'])

    def test_08_source_maps(self):
        for siem, smap in SOURCE_MAPS.items():
            self.assertIn('ics', smap, f"{siem} da ics manbasi yo'q")

    def test_09_fieldmap_preset(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit', 'logs', 'fieldmap.yaml')
        with open(path, 'r', encoding='utf-8') as f:
            presets = yaml.safe_load(f).get('presets', {})
        self.assertIn('ics', presets)
        self.assertIn('ts', presets['ics'])
        self.assertIn('src_ip', presets['ics'])
        self.assertIn('dest_ip', presets['ics'])
        self.assertGreaterEqual(len(presets), 8)

if __name__ == '__main__':
    unittest.main()
