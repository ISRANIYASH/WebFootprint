"""
Unit tests for Evidence Integrity and Tamper Detection.
"""

import unittest
import os
import tempfile
from config import Config
from database.db import db_session, init_db
from forensic.integrity_checker import IntegrityChecker

class TestIntegrityChecker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        init_db()

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

    def test_sha256_calculation_and_verification(self):
        sample_path = os.path.join(self.temp_dir, 'evidence.bin')
        with open(sample_path, 'wb') as f:
            f.write(b"FORENSIC_EVIDENCE_PAYLOAD_ORIGINAL_DATA_12345")

        calculated_hash = IntegrityChecker.calculate_sha256(sample_path)
        self.assertEqual(len(calculated_hash), 64)

        # Ingest into evidence_files
        inv_id = "INV-TEST-001"
        evd_id = "EVD-TEST-001"
        with db_session() as conn:
            conn.execute("INSERT OR IGNORE INTO investigations (id, title, investigator_name) VALUES (?, ?, ?)", (inv_id, "Test Inv", "Tester"))
            conn.execute("""
                INSERT OR REPLACE INTO evidence_files (
                    id, investigation_id, original_filename, stored_filename, file_path,
                    file_size, file_type, sha256_hash, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (evd_id, inv_id, 'evidence.bin', 'evidence.bin', sample_path, len(b"FORENSIC_EVIDENCE_PAYLOAD_ORIGINAL_DATA_12345"), 'Binary', calculated_hash, 'Acquired'))

        # Verify: should be Verified
        result = IntegrityChecker.verify_evidence(evd_id, "Test Auditor")
        self.assertTrue(result['verified'])
        self.assertEqual(result['status'], 'Verified')

        # Tamper with file: modify contents
        with open(sample_path, 'wb') as f:
            f.write(b"FORENSIC_EVIDENCE_PAYLOAD_TAMPERED_DATA_67890")

        # Verify again: should detect Tampered / Mismatch!
        tamper_result = IntegrityChecker.verify_evidence(evd_id, "Test Auditor")
        self.assertFalse(tamper_result['verified'])
        self.assertEqual(tamper_result['status'], 'Mismatch / Tampered')
        self.assertIn("CRITICAL ALERT", tamper_result['message'])

if __name__ == '__main__':
    unittest.main()
