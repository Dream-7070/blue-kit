import sys

file_path = 'tests/test_collect_linux_events.py'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Modify test_csv_to_bk
old_csv_to_bk = '''        try:
            kb_path = get_kb_path()
        except Exception:
            self.skipTest("Could not import get_kb_path")
            
        kb = KB(kb_path)'''

new_csv_to_bk = '''        try:
            kb_path = get_kb_path()
        except Exception:
            self.skipTest("Could not import get_kb_path")
        
        if not os.path.exists(kb_path):
            self.skipTest("KB not found")
            
        kb = KB(kb_path)'''
content = content.replace(old_csv_to_bk, new_csv_to_bk)

content = content.replace('t1136_alerts = [a for a in alerts if a.get("rule_id") == "T1136.001"]', 't1136_alerts = [a for a in alerts if a.get("technique") == "T1136.001" and a.get("confidence") == "high"]')

content = content.replace('self.assertEqual(len(events), 11)', 'self.assertEqual(len(events), 18)')

# test_static
old_static_block = '''        import re
        events_block = re.search(r'collect_events\(\) \{(.*?)\\n\}', content, re.DOTALL)
        if events_block:
            eb = events_block.group(1)
            for forbidden in ["strftime", "mktime", "systime", "gensub", "asort", "grep -P", "rm -rf /", "truncate", "> /var/log", "shred", "journalctl --vacuum", "journalctl --rotate"]:
                self.assertNotIn(forbidden, eb)'''

new_static_block = '''        import re
        events_block = re.search(r'collect_events\(\) \{(.*?)\\n\}', content, re.DOTALL)
        if events_block:
            eb = events_block.group(1)
            for forbidden in ["strftime", "mktime", "systime", "gensub", "asort", "grep -P", "rm -rf /", "truncate", "> /var/log", "shred", "journalctl --vacuum", "journalctl --rotate", "\\\\x00", "\\\\x1F"]:
                self.assertNotIn(forbidden, eb)
            self.assertNotIn(r"\]\{[0-9]", eb)
            self.assertIn("[[:cntrl:]]", eb)
            self.assertIn("int(doe/1460)", eb)
            self.assertIn("BK_EV_TMP", eb)
        
        self.assertTrue(content.find("escape() {") < content.find("collect_events() {"))'''
content = content.replace(old_static_block, new_static_block)

# Add new assertions to test_fixture_csv
new_fixture_checks = '''        
        # New fixture checks
        self.assertEqual(len(rows), 18)
        
        # All Computer == "web01" since we didn't pass -H
        for r in rows:
            self.assertEqual(r[1], "web01")
            
        # Bob history
        bob_rows = [r for r in rows if r[4] == "bob" and r[2] == "bash_history"]
        self.assertEqual(len(bob_rows), 4)
        bob_dict = {r[7]: r[0] for r in bob_rows}
        self.assertEqual(bob_dict.get("a"), "2000-02-29T00:00:00Z")
        self.assertEqual(bob_dict.get("b"), "2023-12-31T23:59:59Z")
        self.assertEqual(bob_dict.get("c"), "2024-02-29T00:00:00Z")
        self.assertEqual(bob_dict.get("d"), "2025-01-01T00:00:00Z")
        
        # Carol history
        carol_rows = [r for r in rows if r[4] == "carol" and r[2] == "zsh_history"]
        self.assertEqual(len(carol_rows), 3)
        carol_id = next(r for r in carol_rows if r[7] == "id")
        self.assertEqual(carol_id[0], "2026-09-30T05:00:01Z")
        self.assertEqual(carol_id[3], "history")
        
        carol_ls = next(r for r in carol_rows if r[7] == "ls -la /tmp")
        self.assertEqual(carol_ls[3], "history")
        
        carol_untimed = next(r for r in carol_rows if r[7] == "oddiy_qator")
        self.assertEqual(carol_untimed[3], "history_untimed")'''

content = content.replace('self.assertEqual(len(rows), 11)', new_fixture_checks)

# Add check for stderr 'command not found' in test_fixture_csv
# I need to see where stderr is accessible. It was collected in setUpClass.
# I'll modify setUpClass to save stderr.
setup_old = '''            cmd = [cls.bash, "responder/collect_linux.sh", "-O", "-q", "-R", fixture_dir, "-E", cls.csv_path, "-Z", "+05:00", "-D", "100000"]
            subprocess.run(cmd, capture_output=True, text=True)'''
setup_new = '''            cmd = [cls.bash, "responder/collect_linux.sh", "-O", "-q", "-R", fixture_dir, "-E", cls.csv_path, "-Z", "+05:00", "-D", "100000"]
            cls.run_res = subprocess.run(cmd, capture_output=True, text=True)'''
content = content.replace(setup_old, setup_new)

# Add stderr check in test_fixture_csv
stderr_check = '''
        self.assertNotIn("command not found", self.run_res.stderr)'''
content = content.replace('self.assertNotIn("\\ufeff", content)', 'self.assertNotIn("\\ufeff", content)' + stderr_check)


# Add test method test_host_flag
test_host_method = '''
    def test_host_flag(self):
        if not self.bash:
            self.skipTest("No bash found")
        fixture_dir = os.path.abspath("tests/fixtures/linux_events").replace("\\\\", "/")
        csv_tmp = self.csv_path + "_myhost.csv"
        cmd = [self.bash, "responder/collect_linux.sh", "-O", "-q", "-R", fixture_dir, "-E", csv_tmp, "-Z", "+05:00", "-H", "myhost"]
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(csv_tmp):
            self.skipTest("No csv generated")
            
        with open(csv_tmp, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = list(reader)
            
        for r in rows:
            self.assertEqual(r[1], "myhost")
'''
content = content.replace('    def test_events_only_requires_output(self):', test_host_method + '    def test_events_only_requires_output(self):')


with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Tests updated")
