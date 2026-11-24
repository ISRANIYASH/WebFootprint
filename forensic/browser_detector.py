"""
Browser Database and Evidence Format Detector for WebFootprint.
Inspects file headers, table schemas, and structure to determine the browser family.
"""

import os
import sqlite3
import json
import csv

class BrowserDetector:
    """
    Identifies evidence file format, browser engine, and database schema compatibility.
    """

    @staticmethod
    def is_sqlite_file(file_path: str) -> bool:
        """Checks if the file begins with the standard SQLite header."""
        if not os.path.isfile(file_path) or os.path.getsize(file_path) < 100:
            return False
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                return header.startswith(b'SQLite format 3\000')
        except Exception:
            return False

    @classmethod
    def detect_evidence_type(cls, file_path: str) -> dict:
        """
        Inspects the file and returns a dictionary with format details.
        """
        if not os.path.exists(file_path):
            return {
                'is_valid': False,
                'detected_type': 'Missing File',
                'browser_family': 'Unknown',
                'tables': [],
                'error': 'File not found on disk.'
            }

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                'is_valid': False,
                'detected_type': 'Empty File',
                'browser_family': 'Unknown',
                'tables': [],
                'error': 'The uploaded evidence file has 0 bytes.'
            }

        ext = os.path.splitext(file_path)[1].lower().strip('.')

        # 1. Check for SQLite database
        if cls.is_sqlite_file(file_path) or ext in ['db', 'sqlite', 'sqlite3']:
            return cls._inspect_sqlite_database(file_path)

        # 2. Check for CSV export
        if ext == 'csv':
            return cls._inspect_csv_file(file_path)

        # 3. Check for JSON export
        if ext == 'json':
            return cls._inspect_json_file(file_path)

        # Fallback check if it's text/CSV without extension
        return {
            'is_valid': False,
            'detected_type': 'Unsupported File Format',
            'browser_family': 'Unknown',
            'tables': [],
            'error': f"Unrecognized file format (extension .{ext}). Expected SQLite, CSV, or JSON."
        }

    @classmethod
    def _inspect_sqlite_database(cls, file_path: str) -> dict:
        """Inspects SQLite tables to determine browser source."""
        tables = []
        try:
            # Open with read-only URI
            uri_path = f"file:{os.path.abspath(file_path)}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True, timeout=5.0)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
        except sqlite3.DatabaseError as e:
            return {
                'is_valid': False,
                'detected_type': 'Corrupted SQLite Database',
                'browser_family': 'Unknown',
                'tables': [],
                'error': f"Corrupted or locked SQLite database: {str(e)}"
            }
        except Exception as e:
            return {
                'is_valid': False,
                'detected_type': 'Unreadable SQLite File',
                'browser_family': 'Unknown',
                'tables': [],
                'error': f"Failed to inspect SQLite database: {str(e)}"
            }

        table_set = set(t.lower() for t in tables)

        # Chromium schema check
        if 'urls' in table_set and 'visits' in table_set:
            has_downloads = 'downloads' in table_set
            return {
                'is_valid': True,
                'detected_type': 'Google Chrome / MS Edge (Chromium History)',
                'browser_family': 'Chromium',
                'tables': tables,
                'has_downloads': has_downloads,
                'error': None
            }

        # Firefox schema check
        if 'moz_places' in table_set or 'moz_historyvisits' in table_set:
            has_annos = 'moz_annos' in table_set
            return {
                'is_valid': True,
                'detected_type': 'Mozilla Firefox (places.sqlite)',
                'browser_family': 'Firefox',
                'tables': tables,
                'has_downloads': has_annos or 'moz_historyvisits' in table_set,
                'error': None
            }

        # Generic SQLite with potential history table
        return {
            'is_valid': True,
            'detected_type': 'Generic SQLite Database',
            'browser_family': 'Generic SQLite',
            'tables': tables,
            'has_downloads': 'downloads' in table_set or 'download_records' in table_set,
            'error': None
        }

    @classmethod
    def _inspect_csv_file(cls, file_path: str) -> dict:
        """Inspects CSV headers to verify structure."""
        try:
            with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
                sample = f.read(2048)
                f.seek(0)
                dialect = csv.Sniffer().sniff(sample) if sample else 'excel'
                reader = csv.reader(f, dialect=dialect)
                header = next(reader, None)
                if not header:
                    return {
                        'is_valid': False,
                        'detected_type': 'Empty CSV File',
                        'browser_family': 'Unknown',
                        'tables': [],
                        'error': 'CSV file has no header or rows.'
                    }

                header_lower = [h.strip().lower() for h in header]
                is_history = any(h in header_lower for h in ['url', 'address', 'link', 'website'])
                is_downloads = any(h in header_lower for h in ['filename', 'target_path', 'download_url'])

                if is_downloads:
                    return {
                        'is_valid': True,
                        'detected_type': 'CSV Download History',
                        'browser_family': 'CSV',
                        'tables': ['downloads'],
                        'headers': header_lower,
                        'error': None
                    }
                elif is_history:
                    return {
                        'is_valid': True,
                        'detected_type': 'CSV Browser History Export',
                        'browser_family': 'CSV',
                        'tables': ['history'],
                        'headers': header_lower,
                        'error': None
                    }
                else:
                    return {
                        'is_valid': False,
                        'detected_type': 'Generic CSV File',
                        'browser_family': 'CSV',
                        'tables': [],
                        'headers': header_lower,
                        'error': "CSV does not contain recognized forensic columns (missing 'url' or 'filename')."
                    }
        except Exception as e:
            return {
                'is_valid': False,
                'detected_type': 'Unreadable CSV File',
                'browser_family': 'Unknown',
                'tables': [],
                'error': f"Failed to parse CSV file: {str(e)}"
            }

    @classmethod
    def _inspect_json_file(cls, file_path: str) -> dict:
        """Inspects JSON structure for browser history evidence."""
        try:
            with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)

            if isinstance(data, dict):
                keys = list(data.keys())
                has_history = any(k in keys for k in ['history', 'browser_history', 'visits', 'records'])
                has_downloads = any(k in keys for k in ['downloads', 'download_records'])
                return {
                    'is_valid': True,
                    'detected_type': 'JSON Forensic Evidence Export',
                    'browser_family': 'JSON',
                    'tables': keys,
                    'has_downloads': has_downloads,
                    'error': None
                }
            elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                first_item_keys = list(data[0].keys())
                return {
                    'is_valid': True,
                    'detected_type': 'JSON Browser Record Array',
                    'browser_family': 'JSON',
                    'tables': ['records'],
                    'has_downloads': any('filename' in k.lower() for k in first_item_keys),
                    'error': None
                }
            else:
                return {
                    'is_valid': False,
                    'detected_type': 'Unrecognized JSON Structure',
                    'browser_family': 'JSON',
                    'tables': [],
                    'error': 'JSON must contain an object or array of forensic records.'
                }
        except Exception as e:
            return {
                'is_valid': False,
                'detected_type': 'Invalid JSON File',
                'browser_family': 'Unknown',
                'tables': [],
                'error': f"Failed to parse JSON file: {str(e)}"
            }
