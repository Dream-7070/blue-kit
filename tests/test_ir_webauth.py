import unittest
from bluekit.ir.webauth import web_auth_stages
from bluekit.ir.correlator import extract_canonical

class TestWebAuth(unittest.TestCase):
    def test_webauth_a(self):
        events = []
        for i in range(40):
            events.append({
                'method': 'POST',
                'path': '/login',
                'status_code': 401 if i < 36 else 200,
                'user_agent': 'my_ua',
                'src_ip': f'8.8.8.{i % 8}',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'host': 'host1'
            })
        events.append({
            'method': 'GET',
            'path': '/account/x',
            'status_code': 200,
            'user_agent': 'my_ua',
            'src_ip': '8.8.8.7',
            'timestamp': '2026-10-01T10:01:00Z',
            'host': 'host1'
        })
        
        def ext(ip): return not ip.startswith('10.')
        stages, _ = web_auth_stages(events, extract_canonical, ext)
        t1110 = [s[0] for s in stages if s[0].technique_id == 'T1110.004']
        self.assertEqual(len(t1110), 1)
        self.assertEqual(t1110[0].iocs.get('attempts'), 40)
        
        t1078 = [s[0] for s in stages if s[0].technique_id == 'T1078']
        self.assertTrue(1 <= len(t1078) <= 4)
        
    def test_webauth_b(self):
        events = []
        for i in range(100):
            events.append({
                'method': 'POST',
                'path': '/login',
                'status_code': 200,
                'user_agent': 'ua',
                'src_ip': '10.0.0.1',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'host': 'host1'
            })
        def ext(ip): return not ip.startswith('10.')
        stages, _ = web_auth_stages(events, extract_canonical, ext)
        self.assertEqual(len(stages), 0)
        
    def test_webauth_c(self):
        events = []
        for i in range(30):
            events.append({
                'method': 'POST',
                'path': '/login',
                'status_code': 401,
                'user_agent': 'ua',
                'src_ip': '8.8.8.8',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'host': 'host1'
            })
        def ext(ip): return not ip.startswith('10.')
        stages, _ = web_auth_stages(events, extract_canonical, ext)
        t1110_001 = [s[0] for s in stages if s[0].technique_id == 'T1110.001']
        t1110_004 = [s[0] for s in stages if s[0].technique_id == 'T1110.004']
        self.assertEqual(len(t1110_001), 1)
        self.assertEqual(len(t1110_004), 0)
        
    def test_webauth_d(self):
        events = []
        for i in range(25):
            events.append({
                'method': 'POST',
                'path': '/login',
                'status_code': 401,
                'user_agent': 'ua',
                'src_ip': f'8.8.8.{i % 2}',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'host': 'host1'
            })
        def ext(ip): return not ip.startswith('10.')
        stages, _ = web_auth_stages(events, extract_canonical, ext)
        t1110_004 = [s[0] for s in stages if s[0].technique_id == 'T1110.004']
        self.assertEqual(len(t1110_004), 0)
        
    def test_webauth_e(self):
        ev1 = [{'message': '"POST /login HTTP/1.1" 401', 'src_ip': '8.8.8.8', 'timestamp': '2026-10-01T10:00:00Z', 'host': 'h1', 'user_agent': 'ua'}]
        ev2 = [{'message': 'POST /login 401 (ua: ua)', 'src_ip': '8.8.8.8', 'timestamp': '2026-10-01T10:00:00Z', 'host': 'h1', 'user_agent': ''}]
        
        def ext(ip): return True
        st1, _ = web_auth_stages(ev1*25, extract_canonical, ext)
        st2, _ = web_auth_stages(ev2*25, extract_canonical, ext)
        self.assertEqual(len(st1), 1)
        self.assertEqual(len(st2), 1)
        
    def test_webauth_f(self):
        events = []
        for i in range(500):
            events.append({
                'method': 'GET',
                'path': '/index.html',
                'status_code': 200,
                'user_agent': 'ua',
                'src_ip': '8.8.8.8',
                'timestamp': '2026-10-01T10:00:00Z',
                'host': 'host1'
            })
        def ext(ip): return True
        stages, _ = web_auth_stages(events, extract_canonical, ext)
        self.assertEqual(len(stages), 0)
        
    def test_webauth_g(self):
        events = []
        for i in range(40):
            events.append({
                'method': 'POST',
                'path': '/login',
                'status_code': 401 if i < 36 else 200,
                'user_agent': 'my_ua',
                'src_ip': f'8.8.8.{i % 8}',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'host': 'host1'
            })
        events_rev = list(reversed(events))
        def ext(ip): return not ip.startswith('10.')
        st_fwd, _ = web_auth_stages(events, extract_canonical, ext)
        st_rev, _ = web_auth_stages(events_rev, extract_canonical, ext)
        self.assertEqual(len(st_fwd), len(st_rev))


class TestWebAuthStringStatus(unittest.TestCase):
    def test_status_codes_as_strings(self):
        events = []
        for i in range(30):
            events.append({'@timestamp': f'2026-10-01T11:00:{i:02d}Z', 'host.name': 'shop', 'source.ip': f'45.9.9.{i % 6}',
                           'message': 'POST /v2/signin HTTP/1.1 401 (ua: curlish)', 'http.response.status_code': '401'})
        stages, handled = web_auth_stages(events, extract_canonical, lambda ip: not ip.startswith(('10.', '192.168.')))
        ids = [s[0].technique_id for s in stages]
        self.assertEqual(ids, ['T1110.004'])
        self.assertEqual(stages[0][0].iocs['attempts'], 30)
        self.assertEqual(len(handled), 30)


class TestWebAuthSessionFromOtherPath(unittest.TestCase):
    def _login(self, i, ip, status):
        return {'@timestamp': f'2026-10-01T12:{i // 60:02d}:{i % 60:02d}Z', 'host.name': 'api1', 'source.ip': ip,
                'message': f'POST /auth/token HTTP/1.1 {status} (ua: bot-7)'}

    def test_followup_from_failed_login_ip_in_auth_area_gives_t1078(self):
        events = [self._login(i, f'77.5.5.{i % 7}', 401) for i in range(30)]
        events.append({'@timestamp': '2026-10-01T12:05:00Z', 'host.name': 'api1', 'source.ip': '77.5.5.3',
                       'message': 'GET /orders/991 HTTP/1.1 200 (ua: browser)'})
        stages, _ = web_auth_stages(events, extract_canonical, lambda ip: True)
        self.assertEqual(sorted(s[0].technique_id for s in stages), ['T1078', 'T1110.004'])
        self.assertEqual([s[1] for s in stages if s[0].technique_id == 'T1078'], ['77.5.5.3'])

    def test_failed_ip_browsing_public_pages_gives_no_t1078(self):
        events = [self._login(i, f'77.5.5.{i % 7}', 401) for i in range(30)]
        events.append({'@timestamp': '2026-10-01T12:05:00Z', 'host.name': 'api1', 'source.ip': '77.5.5.3',
                       'message': 'GET /index.html HTTP/1.1 200 (ua: browser)'})
        stages, _ = web_auth_stages(events, extract_canonical, lambda ip: True)
        self.assertEqual([s[0].technique_id for s in stages], ['T1110.004'])
