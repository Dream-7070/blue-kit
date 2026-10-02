import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

class TestFallbackKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def ev(self, ts, host, user, cmd, code='7045', channel='System', proc='SOMESVC.exe'):
        return {
            '@timestamp': ts, 
            'host': {'name': host}, 
            'user': {'name': user},
            'winlog': {'channel': channel}, 
            'event': {'code': code},
            'process': {'name': proc, 'command_line': cmd}
        }

    # TECH will be T1569.002 or T1543.003
    TECH = 'T1569.002'

    def test_different_actor_not_hidden(self):
        events = [
            self.ev('2026-10-05T02:00:00', 'APP-01', 'corp\\admin.ir', 'SOMESVC approved maintenance CHG-778'),
            self.ev('2026-10-05T05:00:03', 'APP-01', 'SYSTEM', 'SOMESVC service installed')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 2)
        timestamps = [s.timestamp for s in tech_stages]
        self.assertTrue(any('2026-10-05T05:00:03' in ts for ts in timestamps))
        self.assertTrue(any('2026-10-05T02:00:00' in ts for ts in timestamps))

    def test_same_actor_merged(self):
        events = [
            self.ev('2026-10-05T05:00:00', 'APP-01', 'SYSTEM', 'SOMESVC service installed'),
            self.ev('2026-10-05T05:10:00', 'APP-01', 'SYSTEM', 'SOMESVC service installed 2'),
            self.ev('2026-10-05T05:20:00', 'APP-01', 'SYSTEM', 'SOMESVC service installed 3')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 1)
        self.assertEqual(tech_stages[0].iocs['count'], 3)

    def test_actor_normalization(self):
        events = [
            self.ev('2026-10-05T05:00:00', 'APP-01', 'corp\\bob', 'cmd1'),
            self.ev('2026-10-05T05:10:00', 'APP-01', 'BOB@corp.local', 'cmd2'),
            self.ev('2026-10-05T05:20:00', 'APP-01', 'bob', 'cmd3')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 1)

    def test_cap_three_actors(self):
        events = [
            self.ev('2026-10-05T05:00:00', 'APP-01', 'u1', 'cmd1'),
            self.ev('2026-10-05T05:10:00', 'APP-01', 'u2', 'cmd2'),
            self.ev('2026-10-05T05:20:00', 'APP-01', 'u3', 'cmd3'),
            self.ev('2026-10-05T05:30:00', 'APP-01', 'u4', 'cmd4'),
            self.ev('2026-10-05T05:40:00', 'APP-01', 'u5', 'cmd5')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 3)
        self.assertEqual(sum(s.iocs.get('count', 1) for s in tech_stages), 5)

    def test_earliest_event_wins_even_if_later_in_file(self):
        events = [
            self.ev('2026-10-05T05:20:00', 'APP-01', 'u1', 'cmd2'),
            self.ev('2026-10-05T05:00:00', 'APP-01', 'u1', 'cmd1')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 1)
        self.assertEqual(tech_stages[0].timestamp, '2026-10-05T05:00:00+05:00')
        self.assertEqual(tech_stages[0].iocs['last_seen'], '2026-10-05T05:20:00+05:00')

    def test_reverse_order_same_result(self):
        events = [
            self.ev('2026-10-05T05:00:03', 'APP-01', 'SYSTEM', 'SOMESVC service installed'),
            self.ev('2026-10-05T02:00:00', 'APP-01', 'corp\\admin.ir', 'SOMESVC approved maintenance CHG-778')
        ]
        result = correlate_incident(events, self.kb)
        tech_stages = [s for s in result.stages if s.technique_id == self.TECH]
        self.assertEqual(len(tech_stages), 2)

if __name__ == '__main__':
    unittest.main()
