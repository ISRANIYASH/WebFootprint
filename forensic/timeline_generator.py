"""
Forensic Timeline Generator and Activity Pattern Analyzer for WebFootprint.
Chronologically reconstructs user activities and aggregates browsing patterns.
"""

from database.db import get_db_connection

class TimelineGenerator:
    """
    Constructs and filters chronological event timelines from forensic records.
    """

    @staticmethod
    def get_timeline(investigation_id: str, date_filter: str = None, 
                     event_type: str = None, search_query: str = None, limit: int = 500) -> list:
        """
        Retrieves filtered timeline events ordered chronologically.
        """
        conn = get_db_connection()
        try:
            query = """
                SELECT id, investigation_id, evidence_id, event_timestamp, event_type,
                       event_title, event_description, source_reference, severity
                FROM timeline_events
                WHERE investigation_id = ?
            """
            params = [investigation_id]

            if date_filter and date_filter.strip():
                query += " AND event_timestamp LIKE ?"
                params.append(f"{date_filter.strip()}%")

            if event_type and event_type != 'all':
                query += " AND event_type = ?"
                params.append(event_type)

            if search_query and search_query.strip():
                query += " AND (event_title LIKE ? OR event_description LIKE ?)"
                params.append(f"%{search_query.strip()}%")
                params.append(f"%{search_query.strip()}%")

            query += " ORDER BY event_timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    @staticmethod
    def get_unique_event_dates(investigation_id: str) -> list:
        """
        Returns a list of distinct YYYY-MM-DD dates with timeline activity.
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT SUBSTR(event_timestamp, 1, 10) AS event_date, COUNT(*) AS count
                FROM timeline_events
                WHERE investigation_id = ? AND event_timestamp != 'N/A' AND LENGTH(event_timestamp) >= 10
                GROUP BY event_date
                ORDER BY event_date DESC
            """, (investigation_id,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()


class ActivityAnalyzer:
    """
    Computes statistical and domain-level metrics on browsing activities.
    """

    @staticmethod
    def get_activity_summary(investigation_id: str) -> dict:
        """
        Aggregates complete activity metrics for an investigation.
        """
        conn = get_db_connection()
        summary = {}
        try:
            cursor = conn.cursor()

            # 1. Total Visits and Unique Domains
            cursor.execute("""
                SELECT 
                    COUNT(*) AS total_records,
                    COALESCE(SUM(visit_count), 0) AS total_visits,
                    COUNT(DISTINCT domain) AS unique_domains,
                    COALESCE(SUM(typed_count), 0) AS total_typed
                FROM browser_history
                WHERE investigation_id = ?
            """, (investigation_id,))
            base_stats = dict(cursor.fetchone() or {})
            summary.update(base_stats)

            # 2. Most Frequently Visited Domains (Top 10)
            cursor.execute("""
                SELECT domain, SUM(visit_count) AS visits, COUNT(*) AS url_count
                FROM browser_history
                WHERE investigation_id = ? AND domain != 'unknown'
                GROUP BY domain
                ORDER BY visits DESC
                LIMIT 10
            """, (investigation_id,))
            summary['most_visited'] = [dict(row) for row in cursor.fetchall()]

            # 3. Least Frequently Visited Domains (Visit count = 1)
            cursor.execute("""
                SELECT domain, SUM(visit_count) AS visits, MIN(page_title) AS sample_title
                FROM browser_history
                WHERE investigation_id = ? AND domain != 'unknown'
                GROUP BY domain
                HAVING visits = 1
                LIMIT 10
            """, (investigation_id,))
            summary['least_visited'] = [dict(row) for row in cursor.fetchall()]

            # 4. Websites Visited Multiple Times (Repeated access)
            cursor.execute("""
                SELECT domain, SUM(visit_count) AS visits, COUNT(DISTINCT url) AS distinct_pages
                FROM browser_history
                WHERE investigation_id = ? AND domain != 'unknown'
                GROUP BY domain
                HAVING visits > 1
                ORDER BY visits DESC
                LIMIT 10
            """, (investigation_id,))
            summary['repeat_visits'] = [dict(row) for row in cursor.fetchall()]

            # 5. First and Last Website Visited
            cursor.execute("""
                SELECT domain, url, page_title, last_visit_time
                FROM browser_history
                WHERE investigation_id = ? AND last_visit_time != 'N/A' AND LENGTH(last_visit_time) >= 10
                ORDER BY last_visit_time ASC
                LIMIT 1
            """, (investigation_id,))
            first_row = cursor.fetchone()
            summary['first_visited'] = dict(first_row) if first_row else None

            cursor.execute("""
                SELECT domain, url, page_title, last_visit_time
                FROM browser_history
                WHERE investigation_id = ? AND last_visit_time != 'N/A' AND LENGTH(last_visit_time) >= 10
                ORDER BY last_visit_time DESC
                LIMIT 1
            """, (investigation_id,))
            last_row = cursor.fetchone()
            summary['last_visited'] = dict(last_row) if last_row else None

            # 6. Daily Activity Trend (for Chart.js)
            cursor.execute("""
                SELECT SUBSTR(last_visit_time, 1, 10) AS visit_date, SUM(visit_count) AS visits
                FROM browser_history
                WHERE investigation_id = ? AND last_visit_time != 'N/A' AND LENGTH(last_visit_time) >= 10
                GROUP BY visit_date
                ORDER BY visit_date ASC
            """, (investigation_id,))
            summary['daily_activity'] = [dict(row) for row in cursor.fetchall()]

            # 7. Browser Type Distribution
            cursor.execute("""
                SELECT browser_type, COUNT(*) AS count
                FROM browser_history
                WHERE investigation_id = ?
                GROUP BY browser_type
            """, (investigation_id,))
            summary['browser_distribution'] = [dict(row) for row in cursor.fetchall()]

            # 8. Classification Ratio (Normal vs Suspicious vs High Risk)
            cursor.execute("""
                SELECT classification, COUNT(*) AS count
                FROM browser_history
                WHERE investigation_id = ?
                GROUP BY classification
            """, (investigation_id,))
            summary['classification_ratio'] = [dict(row) for row in cursor.fetchall()]

            # 9. Peak Hourly Browsing Activity (00 to 23)
            cursor.execute("""
                SELECT SUBSTR(last_visit_time, 12, 2) AS hour_str, SUM(visit_count) AS visits
                FROM browser_history
                WHERE investigation_id = ? AND last_visit_time != 'N/A' AND LENGTH(last_visit_time) >= 16
                GROUP BY hour_str
                ORDER BY hour_str ASC
            """, (investigation_id,))
            summary['hourly_activity'] = [dict(row) for row in cursor.fetchall()]

            # 10. Downloads summary count & suspicious URLs count
            cursor.execute("SELECT COUNT(*) AS total_downloads FROM download_records WHERE investigation_id = ?", (investigation_id,))
            summary['total_downloads'] = cursor.fetchone()['total_downloads']

            cursor.execute("SELECT COUNT(*) AS total_suspicious FROM suspicious_urls WHERE investigation_id = ?", (investigation_id,))
            summary['total_suspicious'] = cursor.fetchone()['total_suspicious']

            cursor.execute("SELECT COUNT(*) AS total_evidence FROM evidence_files WHERE investigation_id = ?", (investigation_id,))
            summary['total_evidence'] = cursor.fetchone()['total_evidence']

        finally:
            conn.close()

        return summary
