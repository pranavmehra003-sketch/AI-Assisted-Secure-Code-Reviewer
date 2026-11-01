import unittest
from fastapi.testclient import TestClient
from api.index import app

class TestVercelAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "online")
        self.assertIn("Bandit AST", data["scanners"])

    def test_samples_endpoint(self):
        res = self.client.get("/api/samples")
        self.assertEqual(res.status_code, 200)
        samples = res.json().get("samples", [])
        self.assertGreaterEqual(len(samples), 3)

    def test_scan_endpoint_vulnerable(self):
        code = 'import os\nos.system("ping -c 1 127.0.0.1")\nAWS = "AKIAIOSFODNN7EXAMPLE"'
        res = self.client.post("/api/scan", json={
            "code": code,
            "filename": "vuln.py",
            "language": "Python",
            "ai_provider": "offline"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertLessEqual(data["security_score"], 45.0)
        self.assertGreaterEqual(len(data["findings"]), 1)
        self.assertIn("executive_summary", data)

    def test_verify_endpoint(self):
        orig = 'query = "SELECT * FROM users WHERE name = \'" + u + "\'"'
        fixed = 'cursor.execute("SELECT * FROM users WHERE name = ?", (u,))'
        res = self.client.post("/api/verify", json={
            "original_code": orig,
            "fixed_code": fixed,
            "filename": "test.py",
            "language": "Python"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["syntax_valid"])
    def test_scan_endpoint_with_grok_provider(self):
        code = 'import sqlite3\nconn.execute("SELECT * FROM users WHERE id = " + user_id)'
        res = self.client.post("/api/scan", json={
            "code": code,
            "filename": "vuln_sql.py",
            "language": "Python",
            "ai_provider": "grok",
            "api_key": "xai-test-dummy-key"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertLessEqual(data["security_score"], 45.0)
        self.assertGreaterEqual(len(data["findings"]), 1)

if __name__ == "__main__":
    unittest.main()
