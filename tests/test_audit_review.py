import unittest
from bluekit.resp.fraud import scan
from bluekit.resp.scoring import discover, to_allowlist
from bluekit.resp.triage import analyze


class TestAuditReview(unittest.TestCase):
    def test_portproxy_headers_dropped_dnat_kept(self):
        rules = ['Listen on ipv4:             Connect to ipv4:', 'Address         Port        Address         Port',
                 '--------------- ----------  --------------- ----------', '0.0.0.0         3390        10.10.20.40     3389',
                 'DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:2222 to:10.0.0.5:22']
        res = [r['item'] for r in scan({'portproxy': [{'rule': r} for r in rules]}) if r['category'] == 'portproxy']
        self.assertEqual(res, rules[3:])

    def test_admin_port_inbound_not_allowlisted(self):
        snap = {'meta': {'hostname': 'web01'}, 'listening_ports': [{'port': 22}, {'port': 80}],
                'connections': [{'raddr': '185.215.113.66', 'lport': 22, 'rport': 50123}]}
        cand = discover([snap])['candidates'][0]
        self.assertEqual(cand['kind'], 'inbound_admin')
        self.assertEqual(to_allowlist(discover([snap]))['cidrs'], [])

    def test_no_listening_ports_is_not_checker(self):
        snaps = [{'meta': {'hostname': h}, 'connections': [{'raddr': '185.215.113.66', 'lport': p}]} for h, p in (('a', 50001), ('b', 50002))]
        self.assertEqual(discover(snaps)['candidates'][0]['kind'], 'outbound')

    def test_defender_uses_active_attack_id(self):
        cur = {'meta': {'os': 'windows'}, 'defender': {'realtime': False, 'exclusions': ['C:\\Users\\Public']}}
        ids = {t['id'] for f in analyze(None, cur, None, [])[0] if f['category'] == 'defender' for t in f['techniques']}
        self.assertEqual(ids, {'T1685'})


if __name__ == '__main__':
    unittest.main()
