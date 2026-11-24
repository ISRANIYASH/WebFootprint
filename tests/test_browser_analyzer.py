"""
Unit tests for Browser Detectors and History Analyzers.
Tests valid Chrome, valid Firefox, valid CSV, empty databases, corrupted databases, and missing tables.
"""

import unittest
import os
import sqlite3
import tempfile
from forensic.browser_detector import BrowserDetector
from forensic.chrome_analyzer import ChromeAnalyzer
from forensic.firefox_analyzer import FirefoxAnalyzer
from forensic.download_analyzer import DownloadAnalyzer
from sample_data.generator import to_webkit_timestamp, to_firefox_prtime
from datetime import datetime, timezone

class TestBrowserAnalyzers(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.temp_dir):
            try:
                os.remove(os.path.join(self.temp_dir, f))
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass

    def test_valid_chrome_database(self):
        db_path = os.path.join(self.temp_dir, 'chrome_test.db')
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
            CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER, mime_type TEXT);
        """)
        ts = to_webkit_timestamp(datetime.now(timezone.utc))
        conn.execute("INSERT INTO urls VALUES (1, 'https://github.com', 'GitHub', 5, 2, ?)", (ts,))
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 0)", (ts,))
        conn.execute("INSERT INTO downloads VALUES (1, 'C:\\test.exe', 'C:\\test.exe', ?, ?, 1024, 1, 0, 'application/x-msdownload')", (ts, ts))
        conn.commit()
        conn.close()

        detection = BrowserDetector.detect_evidence_type(db_path)
        self.assertTrue(detection['is_valid'])
        self.assertEqual(detection['browser_family'], 'Chromium')

        history = ChromeAnalyzer.extract_history(db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['domain'], 'github.com')
        self.assertEqual(history[0]['visit_count'], 5)

        downloads = ChromeAnalyzer.extract_downloads(db_path)
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]['filename'], 'test.exe')

    def test_valid_firefox_database(self):
        db_path = os.path.join(self.temp_dir, 'firefox_test.sqlite')
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);
            CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
        """)
        ts = to_firefox_prtime(datetime.now(timezone.utc))
        conn.execute("INSERT INTO moz_places VALUES (1, 'https://wikipedia.org', 'Wikipedia', 10, 3, ?)", (ts,))
        conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1, ?, 1)", (ts,))
        conn.commit()
        conn.close()

        detection = BrowserDetector.detect_evidence_type(db_path)
        self.assertTrue(detection['is_valid'])
        self.assertEqual(detection['browser_family'], 'Firefox')

        history = FirefoxAnalyzer.extract_history(db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['domain'], 'wikipedia.org')
        self.assertEqual(history[0]['visit_count'], 10)

    def test_empty_database(self):
        db_path = os.path.join(self.temp_dir, 'empty.db')
        conn = sqlite3.connect(db_path)
        conn.close()

        detection = BrowserDetector.detect_evidence_type(db_path)
        # Empty database has 0 bytes or 0 tables
        if os.path.getsize(db_path) == 0:
            self.assertFalse(detection['is_valid'])
            self.assertEqual(detection['detected_type'], 'Empty File')
        else:
            self.assertEqual(detection['browser_family'], 'Generic SQLite')

    def test_corrupted_database(self):
        db_path = os.path.join(self.temp_dir, 'corrupt.sqlite')
        with open(db_path, 'wb') as f:
            f.write(b'SQLite format 3\000GARBAGE_DATA_CORRUPTION_HERE' * 20)

        detection = BrowserDetector.detect_evidence_type(db_path)
        self.assertFalse(detection['is_valid'])
        self.assertEqual(detection['detected_type'], 'Corrupted SQLite Database')

    def test_missing_tables_database(self):
        db_path = os.path.join(self.temp_dir, 'no_history.db')
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE users (id INT, username TEXT);")
        conn.commit()
        conn.close()

        detection = BrowserDetector.detect_evidence_type(db_path)
        self.assertEqual(detection['browser_family'], 'Generic SQLite')
        history = ChromeAnalyzer.extract_history(db_path)
        self.assertEqual(history, [])

    def test_download_analyzer_risk_evaluation(self):
        exe_eval = DownloadAnalyzer.evaluate_file_risk("payload.exe")
        self.assertEqual(exe_eval['risk_level'], 'High')

        double_ext_eval = DownloadAnalyzer.evaluate_file_risk("invoice.pdf.exe")
        self.assertEqual(double_ext_eval['risk_level'], 'High')
        self.assertIn("Deceptive double extension", double_ext_eval['reason'])

        pdf_eval = DownloadAnalyzer.evaluate_file_risk("paper.pdf")
        self.assertEqual(pdf_eval['risk_level'], 'Low')

if __name__ == '__main__':
    unittest.main()
