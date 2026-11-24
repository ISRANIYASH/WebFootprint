"""
Sample Demonstration Case Loader for WebFootprint.
Loads pre-packaged synthetic evidence into an investigation for instant examination demos.
"""

import os
import shutil
import uuid
from datetime import datetime, timezone
from config import Config
from database.db import db_session, log_analysis
from forensic.integrity_checker import IntegrityChecker
from forensic.history_analyzer import HistoryAnalyzer
from sample_data.generator import generate_sample_files

def load_demo_investigation(investigation_title="Operation Digital Footprint (Demo Exam Case)",
                            investigator_name="Det. S. Vance (Forensic Examiner)") -> str:
    """
    Creates a full demonstration investigation and ingests synthetic Chrome & Firefox databases.
    Returns the investigation_id.
    """
    sample_dir = Config.SAMPLE_DATA_FOLDER
    os.makedirs(sample_dir, exist_ok=True)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # Ensure sample files exist
    chrome_sample = os.path.join(sample_dir, 'sample_chrome_history.db')
    firefox_sample = os.path.join(sample_dir, 'sample_firefox_places.sqlite')
    if not os.path.exists(chrome_sample) or not os.path.exists(firefox_sample):
        generate_sample_files(sample_dir)

    inv_id = f"INV-DEMO-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    # 1. Create Investigation Record
    with db_session() as conn:
        conn.execute("""
            INSERT INTO investigations (id, title, investigator_name, case_description, status)
            VALUES (?, ?, ?, ?, ?)
        """, (
            inv_id,
            investigation_title,
            investigator_name,
            "Synthetic demonstration case containing multi-browser forensic evidence (Google Chrome SQLite & Firefox places.sqlite) for digital forensics evaluation.",
            "Active"
        ))

    # 2. Ingest Chromium Database
    evd_chrome_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    dest_chrome_name = f"{evd_chrome_id}_Chrome_History.db"
    dest_chrome_path = os.path.join(Config.UPLOAD_FOLDER, dest_chrome_name)
    shutil.copy2(chrome_sample, dest_chrome_path)

    chrome_hash = IntegrityChecker.calculate_sha256(dest_chrome_path)
    chrome_size = os.path.getsize(dest_chrome_path)

    with db_session() as conn:
        conn.execute("""
            INSERT INTO evidence_files (
                id, investigation_id, original_filename, stored_filename, file_path,
                file_size, file_type, sha256_hash, acquisition_source, uploaded_by, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evd_chrome_id, inv_id, 'Chrome_History.db', dest_chrome_name, dest_chrome_path,
            chrome_size, 'Google Chrome / MS Edge (Chromium History)', chrome_hash,
            'Seized Workstation Image #1 (Synthetic Demo)', investigator_name, 'Acquired'
        ))

    IntegrityChecker.record_acquisition(
        inv_id, evd_chrome_id, 'Chrome_History.db',
        'Seized Workstation Image #1 (Synthetic Demo)', investigator_name, chrome_hash
    )
    HistoryAnalyzer.process_evidence_file(evd_chrome_id, inv_id, dest_chrome_path)

    # 3. Ingest Firefox Database
    evd_ff_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    dest_ff_name = f"{evd_ff_id}_Firefox_places.sqlite"
    dest_ff_path = os.path.join(Config.UPLOAD_FOLDER, dest_ff_name)
    shutil.copy2(firefox_sample, dest_ff_path)

    ff_hash = IntegrityChecker.calculate_sha256(dest_ff_path)
    ff_size = os.path.getsize(dest_ff_path)

    with db_session() as conn:
        conn.execute("""
            INSERT INTO evidence_files (
                id, investigation_id, original_filename, stored_filename, file_path,
                file_size, file_type, sha256_hash, acquisition_source, uploaded_by, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evd_ff_id, inv_id, 'Firefox_places.sqlite', dest_ff_name, dest_ff_path,
            ff_size, 'Mozilla Firefox (places.sqlite)', ff_hash,
            'Suspect Laptop Profile (Synthetic Demo)', investigator_name, 'Acquired'
        ))

    IntegrityChecker.record_acquisition(
        inv_id, evd_ff_id, 'Firefox_places.sqlite',
        'Suspect Laptop Profile (Synthetic Demo)', investigator_name, ff_hash
    )
    HistoryAnalyzer.process_evidence_file(evd_ff_id, inv_id, dest_ff_path)

    log_analysis(inv_id, 'DemoLoader', f"Successfully initialized demo investigation {inv_id} with dual browser evidence.")
    return inv_id
