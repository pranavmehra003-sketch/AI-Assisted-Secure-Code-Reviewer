import unittest
from scanners.secret_scanner import scan_secrets
from scanners.custom_rules import scan_custom_rules
from modules.static_analyzer import run_all_scanners
from modules.severity_classifier import calculate_security_score

class TestScanners(unittest.TestCase):
    def test_secret_scanner_detects_aws(self):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = scan_secrets(code)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["cwe_id"], "CWE-798")

    def test_custom_rules_detects_sqli(self):
        code = 'query = "SELECT * FROM users WHERE name = \'" + user_input + "\'"'
        findings = scan_custom_rules(code, "Python")
        sqli = [f for f in findings if f["cwe_id"] == "CWE-89"]
        self.assertGreaterEqual(len(sqli), 1)
        self.assertEqual(sqli[0]["severity"], "CRITICAL")

    def test_custom_rules_detects_command_injection(self):
        code = 'subprocess.Popen(cmd, shell=True)'
        findings = scan_custom_rules(code, "Python")
        cmdi = [f for f in findings if f["cwe_id"] == "CWE-78"]
        self.assertGreaterEqual(len(cmdi), 1)

    def test_severity_scoring(self):
        # 1 Critical finding should cap score at <= 45
        vulns = [{"severity": "CRITICAL", "cwe_id": "CWE-89"}]
        score, grade, counts = calculate_security_score(vulns)
        self.assertLessEqual(score, 45.0)
        self.assertEqual(counts["CRITICAL"], 1)

    def test_clean_code_score(self):
        score, grade, counts = calculate_security_score([])
        self.assertEqual(score, 100.0)
        self.assertIn("A", grade)

if __name__ == "__main__":
    unittest.main()
