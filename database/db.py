"""
Database helper and query utility functions for WebFootprint.
"""

import sqlite3
import os
import contextlib
from config import Config
from database.models import SCHEMA_SQL

def get_db_path():
    return Config.DATABASE_PATH

def get_db_connection(db_path=None):
    """
    Returns a connection to the SQLite database with row_factory set to sqlite3.Row.
    Enables foreign keys.
    """
    if db_path is None:
        db_path = get_db_path()
    
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@contextlib.contextmanager
def db_session(db_path=None):
    """
    Context manager for database sessions that commits on exit or rollbacks on exception.
    """
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db(db_path=None):
    """
    Initializes database tables, indexes, and default investigator if not existing.
    """
    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        
        # Check if default investigator exists
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM investigators")
        if cursor.fetchone()['count'] == 0:
            cursor.execute("""
                INSERT INTO investigators (name, badge_number, organization, email)
                VALUES (?, ?, ?, ?)
            """, ('Officer Alex Mercer', 'DF-7402', 'Cyber Forensics Unit', 'a.mercer@cyberunit.gov'))

def log_analysis(investigation_id, module_name, message, log_level='INFO'):
    """
    Inserts a record into the analysis_logs table.
    """
    try:
        with db_session() as conn:
            conn.execute("""
                INSERT INTO analysis_logs (investigation_id, log_level, module_name, message)
                VALUES (?, ?, ?, ?)
            """, (investigation_id, log_level, module_name, message))
    except Exception as e:
        print(f"[LOG ERROR] {module_name}: {message} (Failed to persist: {e})")
