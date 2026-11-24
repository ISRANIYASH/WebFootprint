"""
Evidence Integrity Verification and Chain of Custody Management for WebFootprint.
Calculates and verifies SHA-256 cryptographic hashes to ensure evidence immutability.
"""

import hashlib
import os
from datetime import datetime, timezone
from database.db import db_session, log_analysis

class IntegrityChecker:
    """
    Manages forensic evidence hashing, integrity auditing, and chain of custody tracking.
    """

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """
        Computes SHA-256 hash of a file using buffered streaming reads.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found for hashing: {file_path}")

        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest().lower()

    @classmethod
    def verify_evidence(cls, evidence_id: str, investigator_name: str = "System Auditor") -> dict:
        """
        Re-hashes the stored evidence file, compares with recorded hash,
        and logs the verification in the chain of custody.
        """
        with db_session() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, investigation_id, original_filename, stored_filename, file_path, sha256_hash, upload_timestamp
                FROM evidence_files
                WHERE id = ?
            """, (evidence_id,))
            evd = cursor.fetchone()

            if not evd:
                return {
                    'verified': False,
                    'status': 'Not Found',
                    'message': f"Evidence ID {evidence_id} not found in database."
                }

            file_path = evd['file_path']
            original_hash = evd['sha256_hash']

            if not os.path.exists(file_path):
                status = 'Missing on Disk'
                verified = False
                current_hash = 'FILE_DELETED'
                message = f"Evidence file missing on disk: {file_path}"
            else:
                try:
                    current_hash = cls.calculate_sha256(file_path)
                    if current_hash == original_hash:
                        verified = True
                        status = 'Verified'
                        message = "Cryptographic integrity intact: SHA-256 matches original acquisition hash."
                    else:
                        verified = False
                        status = 'Mismatch / Tampered'
                        message = "CRITICAL ALERT: SHA-256 mismatch detected! File has been altered since acquisition."
                except Exception as e:
                    verified = False
                    status = 'Error'
                    current_hash = 'ERROR'
                    message = f"Hashing error: {str(e)}"

            # Record in chain of custody
            now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                INSERT INTO chain_of_custody (
                    investigation_id, evidence_id, evidence_filename,
                    acquisition_date, acquisition_source, investigator_name,
                    original_sha256, verified_sha256, verification_status,
                    action_performed, action_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evd['investigation_id'], evd['id'], evd['original_filename'],
                evd['upload_timestamp'], 'Cryptographic Audit', investigator_name,
                original_hash, current_hash, status,
                'Integrity Verification Audit', message
            ))

            cursor.execute("""
                INSERT INTO analysis_logs (investigation_id, log_level, module_name, message)
                VALUES (?, ?, ?, ?)
            """, (
                evd['investigation_id'], 'INFO' if verified else 'WARNING', 'IntegrityChecker',
                f"Evidence {evidence_id} verified: {status} (Original: {original_hash[:12]}..., Current: {current_hash[:12]}...)"
            ))

            return {
                'evidence_id': evidence_id,
                'filename': evd['original_filename'],
                'original_hash': original_hash,
                'current_hash': current_hash,
                'verified': verified,
                'status': status,
                'message': message,
                'verification_timestamp': now_str
            }

    @classmethod
    def record_acquisition(cls, investigation_id: str, evidence_id: str, filename: str,
                           source: str, investigator_name: str, sha256_hash: str):
        """
        Creates the initial Chain of Custody record upon evidence acquisition.
        """
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with db_session() as conn:
            conn.execute("""
                INSERT INTO chain_of_custody (
                    investigation_id, evidence_id, evidence_filename,
                    acquisition_date, acquisition_source, investigator_name,
                    original_sha256, verified_sha256, verification_status,
                    action_performed, action_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                investigation_id, evidence_id, filename,
                now_str, source, investigator_name,
                sha256_hash, sha256_hash, 'Verified',
                'Evidence Acquisition & Ingestion', 'Evidence uploaded and SHA-256 computed.'
            ))
