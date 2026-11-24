"""
Database models and schema definitions for WebFootprint.
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS investigators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    badge_number TEXT,
    organization TEXT,
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    investigator_name TEXT NOT NULL,
    case_description TEXT,
    status TEXT DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    acquisition_source TEXT,
    uploaded_by TEXT,
    upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Acquired',
    record_count INTEGER DEFAULT 0,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    page_title TEXT,
    visit_count INTEGER DEFAULT 1,
    typed_count INTEGER DEFAULT 0,
    last_visit_time TEXT NOT NULL,
    browser_type TEXT DEFAULT 'Generic',
    transition_type TEXT,
    classification TEXT DEFAULT 'Normal',
    raw_timestamp TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS download_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT,
    source_url TEXT NOT NULL,
    source_domain TEXT,
    start_time TEXT,
    end_time TEXT,
    download_status TEXT DEFAULT 'Complete',
    file_size INTEGER DEFAULT 0,
    mime_type TEXT,
    danger_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS suspicious_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    detection_reasons TEXT NOT NULL,
    heuristic_score INTEGER DEFAULT 0,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_title TEXT NOT NULL,
    event_description TEXT NOT NULL,
    source_reference TEXT,
    severity TEXT DEFAULT 'Info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    evidence_filename TEXT NOT NULL,
    acquisition_date TEXT NOT NULL,
    acquisition_source TEXT NOT NULL,
    investigator_name TEXT NOT NULL,
    original_sha256 TEXT NOT NULL,
    verified_sha256 TEXT,
    verification_status TEXT DEFAULT 'Verified',
    action_performed TEXT NOT NULL,
    action_details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT,
    log_level TEXT DEFAULT 'INFO',
    module_name TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_history_inv ON browser_history(investigation_id);
CREATE INDEX IF NOT EXISTS idx_history_evd ON browser_history(evidence_id);
CREATE INDEX IF NOT EXISTS idx_history_domain ON browser_history(domain);
CREATE INDEX IF NOT EXISTS idx_history_time ON browser_history(last_visit_time);
CREATE INDEX IF NOT EXISTS idx_downloads_inv ON download_records(investigation_id);
CREATE INDEX IF NOT EXISTS idx_suspicious_inv ON suspicious_urls(investigation_id);
CREATE INDEX IF NOT EXISTS idx_timeline_inv_time ON timeline_events(investigation_id, event_timestamp);
CREATE INDEX IF NOT EXISTS idx_custody_inv ON chain_of_custody(investigation_id);
"""
