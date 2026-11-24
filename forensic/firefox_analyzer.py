"""
Mozilla Firefox (places.sqlite) Forensic History & Downloads Analyzer.
Extracts visit records, typed URLs, and download metadata from Mozilla's places.sqlite database.
"""

import sqlite3
import urllib.parse
from datetime import datetime, timezone
import os

class FirefoxAnalyzer:
    """
    Parser for Mozilla Firefox places.sqlite database.
    """

    VISIT_TYPES = {
        1: 'Link Click',
        2: 'Typed URL',
        3: 'Bookmark',
        4: 'Embedded Content',
        5: 'Redirect (Permanent)',
        6: 'Redirect (Temporary)',
        7: 'Download',
        8: 'Framed Link',
        9: 'Page Reload'
    }

    @staticmethod
    def prtime_to_datetime_str(raw_microseconds: int) -> str:
        """
        Converts Firefox PRTime microseconds (since 1970-01-01 UTC) to ISO string.
        """
        if not raw_microseconds or raw_microseconds <= 0:
            return "N/A"
        try:
            unix_seconds = raw_microseconds / 1_000_000.0
            if unix_seconds < 631152000 or unix_seconds > 4102444800:
                return "N/A"
            dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return "N/A"

    @classmethod
    def extract_history(cls, db_path: str) -> list:
        """
        Extracts browsing history from moz_places joined with moz_historyvisits.
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

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('moz_places', 'moz_historyvisits')")
            tables = [row[0] for row in cursor.fetchall()]

            if 'moz_places' not in tables:
                return records

            if 'moz_historyvisits' in tables:
                query = """
                    SELECT 
                        p.id AS place_id,
                        p.url,
                        p.title,
                        p.visit_count,
                        p.typed,
                        p.last_visit_date,
                        v.visit_date,
                        v.visit_type
                    FROM moz_places p
                    LEFT JOIN moz_historyvisits v ON p.id = v.place_id
                    ORDER BY v.visit_date DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    url = row['url'] or ''
                    if not url:
                        continue

                    # Filter out browser internal URLs if desired, or keep them with classification
                    raw_ts = row['visit_date'] if row['visit_date'] else row['last_visit_date']
                    formatted_time = cls.prtime_to_datetime_str(raw_ts)
                    v_type = row['visit_type'] or 1
                    transition_name = cls.VISIT_TYPES.get(v_type, 'Link Click')

                    records.append({
                        'url': url,
                        'domain': cls._extract_domain(url),
                        'page_title': row['title'] or 'No Title',
                        'visit_count': row['visit_count'] or 1,
                        'typed_count': row['typed'] or 0,
                        'last_visit_time': formatted_time,
                        'browser_type': 'Mozilla Firefox',
                        'transition_type': transition_name,
                        'raw_timestamp': str(raw_ts)
                    })
            else:
                cursor.execute("SELECT url, title, visit_count, typed, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
                for row in cursor.fetchall():
                    url = row['url'] or ''
                    if not url:
                        continue
                    formatted_time = cls.prtime_to_datetime_str(row['last_visit_date'])
                    records.append({
                        'url': url,
                        'domain': cls._extract_domain(url),
                        'page_title': row['title'] or 'No Title',
                        'visit_count': row['visit_count'] or 1,
                        'typed_count': row['typed'] or 0,
                        'last_visit_time': formatted_time,
                        'browser_type': 'Mozilla Firefox',
                        'transition_type': 'Recorded URL',
                        'raw_timestamp': str(row['last_visit_date'])
                    })

        except Exception as e:
            print(f"[FIREFOX ANALYZER ERROR] History extraction failed: {e}")
        finally:
            if conn:
                conn.close()

        return records

    @classmethod
    def extract_downloads(cls, db_path: str) -> list:
        """
        Extracts download records from Firefox moz_annos or visit_type=7.
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

            # Check if moz_annos and moz_anno_attributes exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('moz_annos', 'moz_anno_attributes', 'moz_places')")
            tables = [row[0] for row in cursor.fetchall()]

            if 'moz_annos' in tables and 'moz_anno_attributes' in tables and 'moz_places' in tables:
                query = """
                    SELECT 
                        p.url AS source_url,
                        p.title,
                        a.content AS destination_path,
                        a.dateAdded,
                        a.lastModified
                    FROM moz_places p
                    JOIN moz_annos a ON p.id = a.place_id
                    JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id
                    WHERE n.name LIKE '%download%' OR n.name LIKE '%destination%'
                    ORDER BY a.dateAdded DESC
                """
                cursor.execute(query)
                rows = cursor.fetchall()

                for row in rows:
                    dest = row['destination_path'] or 'downloaded_file'
                    filename = os.path.basename(dest.replace('\\', '/'))
                    source_url = row['source_url'] or 'N/A'
                    ts = cls.prtime_to_datetime_str(row['dateAdded'] or row['lastModified'])

                    downloads.append({
                        'filename': filename,
                        'file_path': dest,
                        'source_url': source_url,
                        'source_domain': cls._extract_domain(source_url),
                        'start_time': ts,
                        'end_time': ts,
                        'download_status': 'Complete',
                        'file_size': 0,
                        'mime_type': 'application/octet-stream',
                        'danger_type': '0'
                    })

            # Check if there are download visit_types in moz_historyvisits
            if not downloads and 'moz_historyvisits' in tables and 'moz_places' in tables:
                query = """
                    SELECT p.url, p.title, v.visit_date
                    FROM moz_places p
                    JOIN moz_historyvisits v ON p.id = v.place_id
                    WHERE v.visit_type = 7
                    ORDER BY v.visit_date DESC
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    source_url = row['url'] or 'N/A'
                    filename = os.path.basename(urllib.parse.urlsplit(source_url).path) or 'downloaded_file'
                    ts = cls.prtime_to_datetime_str(row['visit_date'])
                    downloads.append({
                        'filename': filename,
                        'file_path': 'Firefox Download Folder/' + filename,
                        'source_url': source_url,
                        'source_domain': cls._extract_domain(source_url),
                        'start_time': ts,
                        'end_time': ts,
                        'download_status': 'Complete',
                        'file_size': 0,
                        'mime_type': 'application/octet-stream',
                        'danger_type': '0'
                    })

        except Exception as e:
            print(f"[FIREFOX ANALYZER ERROR] Downloads extraction failed: {e}")
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
