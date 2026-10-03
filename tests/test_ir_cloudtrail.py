import unittest
from bluekit.ir.cloudtrail import cloud_audit_stages
from bluekit.netutil import is_external_ip
from bluekit.ir.correlator import extract_canonical as ext_canon

class TestCloudTrail(unittest.TestCase):
    def test_a(self):
        events = []
        for i in range(12):
            events.append({
                "winlog": {"channel": "cloudtrail"},
                "eventName": "GetObject",
                "sourceIPAddress": "8.8.8.8",
                "userAgent": "aws-cli/2.x",
                "errorCode": "",
                "userIdentity": {"userName": "hacker"},
                "timestamp": f"2026-10-01T10:{i:02d}:00Z"
            })
        stages, h = cloud_audit_stages(events, ext_canon, is_external_ip)
        t1530 = [s for s, _ in stages if s.technique_id == "T1530"]
        t1078 = [s for s, _ in stages if s.technique_id == "T1078.004"]
        self.assertEqual(len(t1530), 1)
        self.assertEqual(t1530[0].iocs['attempts'], 12)
        self.assertEqual(len(t1078), 1)

        stages_9, _ = cloud_audit_stages(events[:9], ext_canon, is_external_ip)
        self.assertEqual(len([s for s, _ in stages_9 if s.technique_id == "T1530"]), 0)
        self.assertEqual(len([s for s, _ in stages_9 if s.technique_id == "T1078.004"]), 0)

    def test_b(self):
        ev1 = {
            "event": {"dataset": "cloudtrail"},
            "eventName": "ListBuckets",
            "sourceIPAddress": "8.8.8.8",
            "userAgent": "aws-cli",
            "userIdentity": {"userName": "hacker"},
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = cloud_audit_stages([ev1], ext_canon, is_external_ip)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1619"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1078.004"]), 1)

        ev2 = ev1.copy()
        ev2['userAgent'] = "aws-sdk-java"
        st2, _ = cloud_audit_stages([ev2], ext_canon, is_external_ip)
        self.assertEqual(len(st2), 0)

        ev3 = ev1.copy()
        ev3['userAgent'] = "Boto3"
        ev3['sourceIPAddress'] = "10.0.0.1"
        st3, _ = cloud_audit_stages([ev3], ext_canon, is_external_ip)
        self.assertEqual(len(st3), 0)

    def test_c(self):
        events = [
            {
                "winlog": {"channel": "cloudtrail"},
                "eventName": "CreateUser",
                "sourceIPAddress": "8.8.8.8",
                "userAgent": "curl",
                "userIdentity": {"userName": "hacker"},
                "timestamp": "2026-10-01T10:00:00Z"
            },
            {
                "winlog": {"channel": "cloudtrail"},
                "eventName": "CreateAccessKey",
                "sourceIPAddress": "8.8.8.8",
                "userAgent": "curl",
                "userIdentity": {"userName": "hacker"},
                "timestamp": "2026-10-01T10:01:00Z"
            }
        ]
        st, h = cloud_audit_stages(events, ext_canon, is_external_ip)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1078.004"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id in ("T1530", "T1619")]), 0)
        self.assertEqual(len(h), 0) # IAM/log events shouldn't be handled

    def test_d(self):
        ev = {
            "winlog": {"channel": "cloudtrail"},
            "eventName": "StopLogging",
            "errorCode": "AccessDenied",
            "sourceIPAddress": "8.8.8.8",
            "userAgent": "aws-cli",
            "userIdentity": {"userName": "hacker"},
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = cloud_audit_stages([ev], ext_canon, is_external_ip)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1078.004"]), 1)

    def test_e(self):
        events = []
        for i in range(500):
            events.append({
                "winlog": {"channel": "cloudtrail"},
                "eventName": "GetObject",
                "sourceIPAddress": "10.0.0.1",
                "userAgent": "aws-sdk",
                "userIdentity": {"userName": "hacker"},
                "timestamp": f"2026-10-01T10:{i%60:02d}:00Z"
            })
        st, _ = cloud_audit_stages(events, ext_canon, is_external_ip)
        self.assertEqual(len(st), 0)
        st_rev, _ = cloud_audit_stages(events[::-1], ext_canon, is_external_ip)
        self.assertEqual(len(st_rev), 0)

    def test_f(self):
        events = [
            {
                "winlog": {"channel": "cloudtrail"},
                "eventName": "CreateUser",
                "sourceIPAddress": "8.8.8.8",
                "userAgent": "curl",
                "userIdentity": {"userName": "hacker1"},
                "timestamp": "2026-10-01T10:00:00Z"
            },
            {
                "winlog": {"channel": "cloudtrail"},
                "eventName": "CreateUser",
                "sourceIPAddress": "8.8.8.8",
                "userAgent": "curl",
                "userIdentity": {"userName": "hacker2"},
                "timestamp": "2026-10-01T10:01:00Z"
            }
        ]
        st, _ = cloud_audit_stages(events, ext_canon, is_external_ip)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1078.004"]), 2)
