import os
import tempfile
import unittest

from bluekit.logs import parse


class TestParseIsoSyslog(unittest.TestCase):
    """Ubuntu 22.10+ rsyslog / journalctl short-iso: vaqt offset bilan keladi."""

    def _load(self, text):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, 'auth.log')
            with open(p, 'w', encoding='utf-8', newline='\n') as f:
                f.write(text)
            return parse.load(p)

    def test_offset_colon_and_host(self):
        evs = self._load('2026-09-30T10:00:01.123456+05:00 web01 sshd[1234]: Accepted password for root from 10.0.0.9 port 51515 ssh2\n')
        self.assertEqual(len(evs), 1)
        self.assertIsNotNone(evs[0]['ts'])
        self.assertEqual(evs[0]['host'], 'web01')
        self.assertEqual(evs[0]['process'], 'sshd')
        self.assertIn('Accepted password', evs[0]['message'])

    def test_offset_no_colon(self):
        evs = self._load('2026-09-30T10:00:01+0500 web01 sudo:    alice : COMMAND=/usr/bin/id\n')
        self.assertIsNotNone(evs[0]['ts'])
        self.assertEqual(evs[0]['host'], 'web01')
        self.assertEqual(evs[0]['process'], 'sudo')

    def test_same_instant_across_offsets(self):
        evs = self._load('2026-09-30T10:00:01+05:00 a x: m\n2026-09-30T05:00:01Z b y: m\n')
        self.assertEqual(evs[0]['ts'], evs[1]['ts'])

    def test_space_separated_app_log_keeps_no_host(self):
        # "2026-09-30 10:00:01 INFO db: ..." — ilova logi, host deb "INFO" olinmasin
        evs = self._load('2026-09-30 10:00:01 INFO db: connected\n')
        self.assertIsNotNone(evs[0]['ts'])
        self.assertIsNone(evs[0]['host'])


if __name__ == '__main__':
    unittest.main()
