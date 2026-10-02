import unittest
from bluekit.kb.cve import audit_packages, audit_containers, audit_database_exposure
from bluekit.resp.triage import analyze

class TestCveAndContainerAudits(unittest.TestCase):
    def test_audit_packages_cves(self):
        packages = [
            {'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.1', 'manager': 'dpkg'},
            {'name': 'sudo', 'version': '1.8.31-1ubuntu1.2', 'manager': 'dpkg'},
            {'name': 'policykit-1', 'version': '0.105-26ubuntu0.1', 'manager': 'dpkg'},
            {'name': 'curl', 'version': '7.81.0-1ubuntu1.16', 'manager': 'dpkg'}
        ]
        installed_apps = [
            {'name': 'ConnectWise ScreenConnect Client', 'version': '23.9.5.8800'}
        ]
        
        findings = audit_packages(packages, installed_apps)
        cves = {f.get('cve') for f in findings}
        
        self.assertIn('CVE-2024-6387', cves) # regreSSHion
        self.assertIn('CVE-2021-3156', cves)  # Baron Samedit
        self.assertIn('CVE-2021-4034', cves)  # PwnKit
        self.assertIn('CVE-2024-1709', cves)  # ScreenConnect

    def test_audit_containers(self):
        containers = [
            {
                'id': 'abc123456789',
                'name': 'web_priv',
                'image': 'nginx:latest',
                'privileged': True,
                'mount_risks': ''
            },
            {
                'id': 'def987654321',
                'name': 'ci_runner',
                'image': 'docker:dind',
                'privileged': False,
                'mount_risks': 'docker.sock'
            },
            {
                'id': 'norm12345678',
                'name': 'safe_app',
                'image': 'redis:alpine',
                'privileged': False,
                'mount_risks': ''
            }
        ]
        
        findings = audit_containers(containers)
        self.assertEqual(len(findings), 2)
        
        reasons_flat = ' '.join([' '.join(f.get('reasons', [])) for f in findings])
        self.assertIn('--privileged', reasons_flat)
        self.assertIn('docker.sock', reasons_flat)

    def test_audit_database_exposure(self):
        listening_ports = [
            {'ip': '0.0.0.0', 'port': 6379},
            {'ip': '127.0.0.1', 'port': 3306},
            {'ip': '0.0.0.0:5432', 'port': 5432}
        ]
        
        findings = audit_database_exposure(listening_ports)
        items = [f.get('item', '') for f in findings]
        
        self.assertTrue(any('6379' in it for it in items))
        self.assertTrue(any('5432' in it for it in items))
        self.assertFalse(any('127.0.0.1' in it and '3306' in it for it in items))

    def test_triage_integration(self):
        current_snapshot = {
            'meta': {'os': 'linux', 'hostname': 'target-srv'},
            'packages': [
                {'name': 'openssh-server', 'version': '1:8.9p1-3', 'manager': 'dpkg'}
            ],
            'containers': [
                {'id': 'c1', 'name': 'priv_pod', 'image': 'alpine', 'privileged': True, 'mount_risks': 'docker.sock'}
            ],
            'listening_ports': [
                {'ip': '0.0.0.0', 'port': 27017}
            ]
        }
        
        findings, extra = analyze(None, current_snapshot)
        categories = {f.get('category') for f in findings}
        
        self.assertIn('vulnerabilities', categories)
        self.assertIn('containers', categories)
        self.assertIn('database_exposure', categories)

if __name__ == '__main__':
    unittest.main()
