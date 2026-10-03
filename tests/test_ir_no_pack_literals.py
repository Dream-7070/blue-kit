import os
import unittest

# HANDOFF_TESTPACK_GAPS 2-bo'lim: sinov to'plami xabar matnlari, host va fayl nomlari correlator ga qaytib kirmasin
FORBIDDEN = [
    "'spray 43 accounts'", "'service rnstage installed'", "'ransomware staging service'", "'locker_stage'",
    "'idp-log'", "'sp-audit'", "'mail-audit'", "'user consent phishing'", "'malicious oauth consent'",
    "'onedrive enumeration'", "'download deals'", "'mailbox forwarding persistence'", "'password compromise not observed'",
    "'cryptominer process'", "'stratum-like connection'", "'resource anomaly cpu 99%'", "'dns tunnel chunk'",
    "'122 txt queries'", "'exfil-lab'", "'read 327 employee files'", "'hr-confidential'", "'synth-usb'",
    "'copy hr_docs.7z to removable media'", "'usb exfil blocked'", "'cloud upload 188331002 bytes'",
    "'upload completed to personal cloud'", "'backup' in msg_lower", "'bkp_cfg.tgz'", "'rdp logon type 10'",
    "'backup discovery'", "'collection staged'", "'delete requested'", "'sync done'",
]


class TestNoPackLiterals(unittest.TestCase):
    def test_correlator_and_fallback_clean(self):
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bluekit', 'ir')
        found = []
        for name in ('correlator.py', 'fallback.py'):
            with open(os.path.join(root, name), encoding='utf-8') as f:
                text = f.read().lower()
            found += [f"{name}: {lit}" for lit in FORBIDDEN if lit in text]
        self.assertEqual(found, [])


if __name__ == '__main__':
    unittest.main()
