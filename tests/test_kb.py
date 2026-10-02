import unittest
import os
from bluekit.kb.query import KB
from bluekit.kb.ioc import classify
from bluekit.paths import get_kb_path

class TestKB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(get_kb_path()):
            raise unittest.SkipTest("KB not built")
        cls.kb = KB()
        
    def test_validate(self):
        v1 = self.kb.validate(["T1003.001"])[0]
        self.assertTrue(v1['found'])
        self.assertEqual(v1['name'], "LSASS Memory")
        self.assertEqual(v1['status'], "active")
        
        v2 = self.kb.validate(["T0803"])[0]
        self.assertTrue(v2['found'])
        self.assertEqual(v2['status'], "revoked")
        self.assertTrue(bool(v2['replacement']))
            
        v3 = self.kb.validate(["T9999"])[0]
        self.assertFalse(v3['found'])
        
        v4 = self.kb.validate(["bad"])[0]
        self.assertFalse(v4['found'])

    def test_lookup(self):
        l1 = self.kb.lookup("T0881")
        if l1:
            self.assertEqual(l1[0]['domain'], "ics")
            self.assertEqual(l1[0]['name'], "Service Stop")
            
        l2 = self.kb.lookup("T1657")
        if l2:
            self.assertEqual(l2[0]['name'], "Financial Theft")
            
    def test_search(self):
        # Assert search_idx row count
        c = self.kb.conn.cursor()
        idx_count = c.execute("SELECT count(*) FROM search_idx").fetchone()[0]
        self.assertGreater(idx_count, 5000)

        s1 = self.kb.search("vssadmin delete shadows /all /quiet")
        self.assertTrue(any(x['attack_id'] == 'T1490' for x in s1[:3]))
        
        s2 = self.kb.search("schtasks /create /sc onlogon /tr evil.exe")
        self.assertTrue(any(x['attack_id'] == 'T1053.005' for x in s2[:3]))
        
        s3 = self.kb.search("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys")
        self.assertTrue(any(x['attack_id'] == 'T1098.004' for x in s3[:3]))

        s4 = self.kb.search("rundll32 comsvcs.dll MiniDump lsass")
        self.assertTrue(any(x['attack_id'] == 'T1003.001' for x in s4[:3]))
        
        s5 = self.kb.search("secretsdump -just-dc")
        self.assertTrue(any(x['attack_id'] == 'T1003.006' for x in s5[:2]))
        
        s6 = self.kb.search("nltest /dclist")
        self.assertTrue(any(x['attack_id'] == 'T1018' for x in s6[:3]))
        
        s7 = self.kb.search("Set-MpPreference -DisableRealtimeMonitoring")
        self.assertTrue(any(x['attack_id'] == 'T1685' for x in s7[:3]))
        
        s8 = self.kb.search("echo x >> C:\\Windows\\System32\\drivers\\etc\\hosts")
        self.assertTrue(any(x['attack_id'] == 'T1565.001' for x in s8[:2]))
        
        s9 = self.kb.search("Get-MpPreference")
        if s9:
            self.assertNotEqual(s9[0].get('confidence'), "high")

    def test_related(self):
        r = self.kb.related(["T1566.001"])
        self.assertGreaterEqual(len(r), 10)
        for x in r:
            self.assertTrue(0 <= x['probability'] <= 1)
            self.assertNotEqual(x['attack_id'], "T1566.001")
            
        # check sorting
        probs = [x['probability'] for x in r]
        self.assertEqual(probs, sorted(probs, reverse=True))

    def test_tactic_coverage(self):
        c = self.kb.tactic_coverage(["T1566.001", "T1003.001"])
        for t in c:
            if t['shortname'] in ('initial-access', 'credential-access'):
                self.assertFalse(t['missing'])

    def test_ioc_classify(self):
        self.assertEqual(classify("hxxp://evil[.]com/a.exe")['type'], 'url')
        self.assertEqual(classify("8.8.8.8")['type'], 'ipv4')
        p = classify("10.0.0.5")
        self.assertEqual(p['type'], 'ipv4')
        self.assertTrue(p['private'])
        self.assertEqual(classify("d41d8cd98f00b204e9800998ecf8427e")['type'], 'md5')
        self.assertEqual(classify("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")['type'], 'registry')
        self.assertEqual(classify("C:\\Users\\a\\x.exe")['type'], 'win_path')

if __name__ == '__main__':
    unittest.main()
