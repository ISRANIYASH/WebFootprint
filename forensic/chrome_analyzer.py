"""
Chromium (Google Chrome / Microsoft Edge) Forensic History & Downloads Analyzer.
Extracts visit records, typed URLs, and download chains from SQLite History databases.
Safely operates on read-only database connections.
"""

import sqlite3
import urllib.parse
from datetime import datetime, timezone
import os

class ChromeAnalyzer:
    """
    Parser for Google Chrome, Microsoft Edge, and Chromium-based browser history databases.
    """

    TRANSITION_TYPES = {
        0: 'Link Click',
        1: 'Typed URL',
        2: 'Auto Bookmark',
        3: 'Auto Subframe',
        4: 'Manual Subframe',
        5: 'Generated',
        6: 'Auto Toplevel',
        7: 'Form Submit',
        8: 'Page Reload',
        9: 'Search Keyword',
        10: 'Keyword Generated'
    }

    DOWNLOAD_STATES = {
        0: 'In Progress',
        1: 'Complete',
        2: 'Cancelled',
        3: 'Interrupted'
    }

    @staticmethod
    def webkit_to_datetime_str(raw_microseconds: int) -> str:
        """
        Converts WebKit microseconds timestamp (since 1601-01-01 UTC) to ISO string.
        """
        if not raw_microseconds or raw_microseconds <= 0:
            return "N/A"
        try:
            unix_seconds = (raw_microseconds / 1_000_000.0) - 11644473600.0
            if unix_seconds < 631152000 or unix_seconds > 4102444800:  # 1990 to 2100
                return "N/A"
            dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return "N/A"

    @classmethod
    def extract_history(cls, db_path: str) -> list:
        """
        Extracts browsing history records from Chromium 'urls' and 'visits' tables.
        """
        records = []
        if not os.path.exists(db_path):
            return records

        uri_path = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = None
        try:
            conn = sqlite3.connect(uri_path, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('urls', 'visits')")
            tables = [row[0] for row in cursor.fetchall()]

            if 'urls' not in tables:
                return records

            if 'visits' in tables:
                # Detailed visits query joined with URLs
                query = """
                    SELECT 
                        u.id AS url_id,
                        u.url,
                        u.title,
                        u.visit_count,
                        u.typed_count,
                        u.last_visit_time,
                        v.visit_time,
                        v.transition
                    FROM urls u
                    LEFT JOIN visits v ON u.id = v.url
                    ORDER BY v.visit_time DESC
                """
                cursor.execute(query)
                rows = cursor.fetchall()

                for row in rows:
                    url = row['url'] or ''
                    if not url:
                        continue

                    parsed_domain = cls._extract_domain(url)
                    raw_ts = row['visit_time'] if row['visit_time'] else row['last_visit_time']
                    formatted_time = cls.webkit_to_datetime_str(raw_ts)
                    
                    # Transition type mapping (first 8 bits represent core transition)
                    raw_transition = row['transition'] or 0
                    core_transition = raw_transition & 0xFF
                    transition_name = cls.TRANSITION_TYPES.get(core_transition, 'Link Click')

                    records.append({
                        'url': url,
                        'domain': parsed_domain,
                        'page_title': row['title'] or 'No Title',
                        'visit_count': row['visit_count'] or 1,
                        'typed_count': row['typed_count'] or 0,
                        'last_visit_time': formatted_time,
                        'browser_type': 'Chrome/Edge',
                        'transition_type': transition_name,
                        'raw_timestamp': str(raw_ts)
                    })
            else:
                # Fallback to urls table only
                cursor.execute("SELECT url, title, visit_count, typed_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                for row in cursor.fetchall():
                    url = row['url'] or ''
                    if not url:
                        continue
                    formatted_time = cls.webkit_to_datetime_str(row['last_visit_time'])
                    records.append({
                        'url': url,
                        'domain': cls._extract_domain(url),
                        'page_title': row['title'] or 'No Title',
                        'visit_count': row['visit_count'] or 1,
                        'typed_count': row['typed_count'] or 0,
                        'last_visit_time': formatted_time,
                        'browser_type': 'Chrome/Edge',
                        'transition_type': 'Recorded URL',
                        'raw_timestamp': str(row['last_visit_time'])
                    })

        except Exception as e:
            print(f"[CHROME ANALYZER ERROR] History extraction failed: {e}")
        finally:
            if conn:
                conn.close()

        return records

    @classmethod
    def extract_downloads(cls, db_path: str) -> list:
        """
        Extracts download records from Chromium 'downloads' and 'downloads_url_chains' tables.
        """
        downloads = []
        if not os.path.exists(db_path):
            return downloads

        uri_path = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = None
        try:
            conn = sqlite3.connect(uri_path, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
            if not cursor.fetchone():
                return downloads

            # Check if downloads_url_chains exists to get source URL
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads_url_chains'")
            has_chains = bool(cursor.fetchone())

            if has_chains:
                query = """
                    SELECT 
                        d.id,
                        d.current_path,
                        d.target_path,
                        d.start_time,
                        d.end_time,
                        d.total_bytes,
                        d.state,
                        d.danger_type,
                        d.mime_type,
                        c.url AS source_url
                    FROM downloads d
                    LEFT JOIN downloads_url_chains c ON d.id = c.id
                    ORDER BY d.start_time DESC
                """
            else:
                query = """
                    SELECT 
                        id,
                        current_path,
                        target_path,
                        start_time,
                        end_time,
                        total_bytes,
                        state,
                        danger_type,
                        mime_type,
                        '' AS source_url
                    FROM downloads
                    ORDER BY start_time DESC
                """

            cursor.execute(query)
            for row in cursor.fetchall():
                target_path = row['target_path'] or row['current_path'] or 'unknown_file'
                filename = os.path.basename(target_path.replace('\\', '/'))
                source_url = row['source_url'] or 'N/A'
                source_domain = cls._extract_domain(source_url) if source_url != 'N/A' else 'Local'

                start_ts = cls.webkit_to_datetime_str(row['start_time'])
                end_ts = cls.webkit_to_datetime_str(row['end_time'])
                status_code = row['state']
                status_str = cls.DOWNLOAD_STATES.get(status_code, 'Complete')

                downloads.append({
                    'filename': filename,
                    'file_path': target_path,
                    'source_url': source_url,
                    'source_domain': source_domain,
                    'start_time': start_ts,
                    'end_time': end_ts,
                    'download_status': status_str,
                    'file_size': row['total_bytes'] or 0,
                    'mime_type': row['mime_type'] or 'application/octet-stream',
                    'danger_type': str(row['danger_type']) if row['danger_type'] is not None else '0'
                })

        except Exception as e:
            print(f"[CHROME ANALYZER ERROR] Downloads extraction failed: {e}")
        finally:
            if conn:
                conn.close()

        return downloads

    @staticmethod
    def _extract_domain(url: str) -> str:
        if not url:
            return 'unknown'
        try:
            parsed = urllib.parse.urlsplit(url)
            domain = parsed.netloc.split(':')[0]
            return domain.lower() if domain else 'unknown'
        except Exception:
            return 'unknown'
