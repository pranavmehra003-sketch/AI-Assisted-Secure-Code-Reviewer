import unittest
from modules.database import (
    init_db,
    save_review,
    save_vulnerabilities,
    get_reviews,
    get_review_by_id,
    get_vulnerabilities_by_review,
    delete_review,
    get_security_stats
)

class TestDatabase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_crud_review_flow(self):
        # 1. Save Review
        rev_id = save_review(
            filename="test_app.py",
            file_language="Python",
            code_snippet="print('vulnerable')",
            security_score=45.0,
            total_issues=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            ai_provider="mock",
            executive_summary="Critical findings present."
        )
        self.assertIsNotNone(rev_id)
        self.assertGreater(rev_id, 0)

        # 2. Save Findings
        vulns = [{
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "category": "Injection",
            "cwe_id": "CWE-89",
            "line_number": 5,
            "snippet": "SELECT * FROM users",
            "description": "SQL Injection flaw",
            "why_dangerous": "Data theft",
            "attack_scenario": "Union select injection",
            "fix_recommendation": "Use parameterized queries",
            "secure_code": "cursor.execute('?', (x,))",
            "scanner_source": "Test"
        }]
        save_vulnerabilities(rev_id, vulns)

        # 3. Retrieve
        rev = get_review_by_id(rev_id)
        self.assertEqual(rev["filename"], "test_app.py")
        self.assertEqual(rev["security_score"], 45.0)

        retrieved_vulns = get_vulnerabilities_by_review(rev_id)
        self.assertEqual(len(retrieved_vulns), 1)
        self.assertEqual(retrieved_vulns[0]["severity"], "CRITICAL")

        # 4. Stats
        stats = get_security_stats()
        self.assertGreaterEqual(stats["total_reviews"], 1)

        # 5. Cleanup
        deleted = delete_review(rev_id)
        self.assertTrue(deleted)
        self.assertIsNone(get_review_by_id(rev_id))

if __name__ == "__main__":
    unittest.main()
