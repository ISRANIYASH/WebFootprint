"""
Integration and edge case tests for WebFootprint:
PDF generation, CSV export, empty cases, and Flask routes.
"""

import unittest
import os
from app import app
from database.db import db_session, init_db
from reports.report_generator import ReportGenerator

class TestReportsAndRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()
        cls.client.testing = True

    @classmethod
    def tearDownClass(cls):
        with db_session() as conn:
            conn.execute("DELETE FROM investigations WHERE id IN ('INV-EMPTY-TEST', 'INV-CSV-TEST')")

    def test_empty_investigation_report_pdf(self):
        empty_inv_id = "INV-EMPTY-TEST"
        with db_session() as conn:
            conn.execute("INSERT OR REPLACE INTO investigations (id, title, investigator_name) VALUES (?, ?, ?)",
                         (empty_inv_id, "Empty Test Case", "Auditor"))

        # Generating report on case with 0 records should succeed gracefully without raising exceptions
        pdf_path = ReportGenerator.generate_pdf_report(empty_inv_id)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 500)

    def test_csv_exports(self):
        inv_id = "INV-CSV-TEST"
        with db_session() as conn:
            conn.execute("INSERT OR REPLACE INTO investigations (id, title, investigator_name) VALUES (?, ?, ?)",
                         (inv_id, "CSV Test Case", "Auditor"))

        for exp in ['history', 'downloads', 'suspicious', 'timeline']:
            csv_str = ReportGenerator.export_csv(inv_id, exp)
            self.assertIsInstance(csv_str, str)
            self.assertTrue(len(csv_str.splitlines()) >= 1)

    def test_flask_all_routes_return_200(self):
        routes = [
            '/dashboard',
            '/investigations',
            '/evidence',
            '/history',
            '/website-analysis',
            '/suspicious-urls',
            '/downloads',
            '/timeline',
            '/integrity',
            '/reports',
            '/settings'
        ]
        for route in routes:
            response = self.client.get(route, follow_redirects=True)
            self.assertEqual(response.status_code, 200, f"Route {route} failed with status {response.status_code}")

if __name__ == '__main__':
    unittest.main()
