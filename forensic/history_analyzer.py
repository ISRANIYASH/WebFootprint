"""
Master History and Evidence Analyzer for WebFootprint.
Orchestrates browser detection, record parsing, heuristic URL evaluation, 
and database persistence.
"""

import os
import csv
import json
import urllib.parse
from datetime import datetime, timezone
from database.db import db_session, log_analysis
from forensic.browser_detector import BrowserDetector
from forensic.chrome_analyzer import ChromeAnalyzer
from forensic.firefox_analyzer import FirefoxAnalyzer
from forensic.url_analyzer import URLAnalyzer
from forensic.download_analyzer import DownloadAnalyzer

class HistoryAnalyzer:
    """
    Coordinates extraction of browser artifacts and executes forensic analysis workflows.
    """

    @classmethod
    def process_evidence_file(cls, evidence_id: str, investigation_id: str, file_path: str) -> dict:
        """
        Analyzes an evidence file and populates database tables.
        Returns summary dictionary.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        log_analysis(investigation_id, 'HistoryAnalyzer', f"Initiating processing of evidence ID: {evidence_id}")

        detection = BrowserDetector.detect_evidence_type(file_path)
        if not detection['is_valid']:
            log_analysis(investigation_id, 'HistoryAnalyzer', f"Evidence invalid: {detection.get('error')}", 'ERROR')
            raise ValueError(f"Evidence validation failed: {detection.get('error')}")

        browser_family = detection['browser_family']
        raw_history_records = []
        raw_download_records = []

        # Dispatch based on detected browser family
        if browser_family == 'Chromium':
            raw_history_records = ChromeAnalyzer.extract_history(file_path)
            raw_download_records = ChromeAnalyzer.extract_downloads(file_path)
        elif browser_family == 'Firefox':
            raw_history_records = FirefoxAnalyzer.extract_history(file_path)
            raw_download_records = FirefoxAnalyzer.extract_downloads(file_path)
        elif browser_family == 'CSV':
            parsed = cls._parse_csv_evidence(file_path)
            raw_history_records = parsed['history']
            raw_download_records = parsed['downloads']
        elif browser_family == 'JSON':
            parsed = cls._parse_json_evidence(file_path)
            raw_history_records = parsed['history']
            raw_download_records = parsed['downloads']
        elif browser_family == 'Generic SQLite':
            # Attempt Chrome and Firefox extraction
            raw_history_records = ChromeAnalyzer.extract_history(file_path)
            if not raw_history_records:
                raw_history_records = FirefoxAnalyzer.extract_history(file_path)
            raw_download_records = ChromeAnalyzer.extract_downloads(file_path)

        log_analysis(investigation_id, 'HistoryAnalyzer', 
                     f"Extracted {len(raw_history_records)} history records and {len(raw_download_records)} download records.")

        # Persist extracted records into database
        history_saved_count = 0
        downloads_saved_count = 0
        suspicious_count = 0

        with db_session() as conn:
            # 1. Process History Records
            for rec in raw_history_records:
                url = rec.get('url', '').strip()
                if not url:
                    continue

                domain = rec.get('domain') or cls._extract_domain(url)
                page_title = rec.get('page_title') or 'No Title'
                visit_count = int(rec.get('visit_count', 1))
                typed_count = int(rec.get('typed_count', 0))
                last_visit = rec.get('last_visit_time') or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                b_type = rec.get('browser_type') or detection.get('detected_type', 'Generic')
                transition = rec.get('transition_type', 'Link Click')

                # Run URL heuristic analysis
                url_eval = URLAnalyzer.analyze_url(url)
                risk_level = url_eval['risk_level']
                score = url_eval['heuristic_score']
                reasons = url_eval['reasons']

                # Map risk level to classification
                if risk_level == 'HIGH RISK':
                    classification = 'High Risk'
                elif risk_level == 'MEDIUM RISK':
                    classification = 'Suspicious'
                else:
                    classification = 'Normal'

                # Insert history record
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO browser_history (
                        investigation_id, evidence_id, url, domain, page_title,
                        visit_count, typed_count, last_visit_time, browser_type,
                        transition_type, classification, raw_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    investigation_id, evidence_id, url, domain, page_title,
                    visit_count, typed_count, last_visit, b_type,
                    transition, classification, rec.get('raw_timestamp', '')
                ))
                history_saved_count += 1

                # If suspicious or high risk, save to suspicious_urls
                if risk_level in ['HIGH RISK', 'MEDIUM RISK']:
                    cursor.execute("""
                        INSERT INTO suspicious_urls (
                            investigation_id, evidence_id, url, domain,
                            risk_level, detection_reasons, heuristic_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        investigation_id, evidence_id, url, domain,
                        risk_level, json.dumps(reasons), score
                    ))
                    suspicious_count += 1

                # Create timeline event for history visit
                severity = 'Warning' if risk_level == 'HIGH RISK' else ('Notice' if risk_level == 'MEDIUM RISK' else 'Info')
                event_type = 'Suspicious URL Encountered' if risk_level in ['HIGH RISK', 'MEDIUM RISK'] else (
                    'Website Revisited' if visit_count > 1 else 'Website Visited'
                )
                conn.execute("""
                    INSERT INTO timeline_events (
                        investigation_id, evidence_id, event_timestamp, event_type,
                        event_title, event_description, source_reference, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    investigation_id, evidence_id, last_visit, event_type,
                    f"Visited: {domain}",
                    f"URL: {url} | Title: {page_title} | Visits: {visit_count}",
                    f"Evidence {evidence_id}", severity
                ))

            # 2. Process Download Records
            for dl in raw_download_records:
                filename = dl.get('filename') or 'unknown_file'
                file_path_str = dl.get('file_path') or filename
                source_url = dl.get('source_url') or 'N/A'
                source_domain = dl.get('source_domain') or cls._extract_domain(source_url)
                start_time = dl.get('start_time') or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                end_time = dl.get('end_time') or start_time
                status = dl.get('download_status') or 'Complete'
                file_size = int(dl.get('file_size') or 0)
                mime = dl.get('mime_type') or 'application/octet-stream'

                risk_eval = DownloadAnalyzer.evaluate_file_risk(filename)

                conn.execute("""
                    INSERT INTO download_records (
                        investigation_id, evidence_id, filename, file_path,
                        source_url, source_domain, start_time, end_time,
                        download_status, file_size, mime_type, danger_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    investigation_id, evidence_id, filename, file_path_str,
                    source_url, source_domain, start_time, end_time,
                    status, file_size, mime, risk_eval['risk_level']
                ))
                downloads_saved_count += 1

                # Create timeline event for download
                dl_severity = 'Alert' if risk_eval['risk_level'] == 'High' else ('Warning' if risk_eval['risk_level'] == 'Medium' else 'Notice')
                conn.execute("""
                    INSERT INTO timeline_events (
                        investigation_id, evidence_id, event_timestamp, event_type,
                        event_title, event_description, source_reference, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    investigation_id, evidence_id, start_time, 'File Downloaded',
                    f"Downloaded: {filename}",
                    f"Source: {source_url} | Size: {DownloadAnalyzer.format_bytes(file_size)} | Risk: {risk_eval['risk_level']}",
                    f"Evidence {evidence_id}", dl_severity
                ))

            # Update evidence file record
            conn.execute("""
                UPDATE evidence_files
                SET status = 'Analyzed', record_count = ?
                WHERE id = ?
            """, (history_saved_count + downloads_saved_count, evidence_id))

        log_analysis(investigation_id, 'HistoryAnalyzer',
                     f"Analysis complete. History: {history_saved_count}, Downloads: {downloads_saved_count}, Suspicious: {suspicious_count}")

        return {
            'evidence_id': evidence_id,
            'browser_family': browser_family,
            'detected_type': detection['detected_type'],
            'history_count': history_saved_count,
            'downloads_count': downloads_saved_count,
            'suspicious_count': suspicious_count
        }

    @classmethod
    def _parse_csv_evidence(cls, file_path: str) -> dict:
        """Parses CSV evidence into history and download lists."""
        history = []
        downloads = []

        with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Normalize keys to lowercase
                lower_row = {k.strip().lower(): v.strip() for k, v in row.items() if k}

                # Check if row is a download record
                if 'filename' in lower_row and ('source_url' in lower_row or 'url' in lower_row):
                    downloads.append({
                        'filename': lower_row.get('filename', 'downloaded_file'),
                        'file_path': lower_row.get('file_path') or lower_row.get('path', ''),
                        'source_url': lower_row.get('source_url') or lower_row.get('url', 'N/A'),
                        'source_domain': cls._extract_domain(lower_row.get('source_url') or lower_row.get('url', '')),
                        'start_time': lower_row.get('start_time') or lower_row.get('timestamp') or lower_row.get('date', ''),
                        'end_time': lower_row.get('end_time') or lower_row.get('start_time', ''),
                        'download_status': lower_row.get('status') or lower_row.get('download_status', 'Complete'),
                        'file_size': int(lower_row.get('file_size') or lower_row.get('size', 0) or 0),
                        'mime_type': lower_row.get('mime_type', 'application/octet-stream')
                    })
                elif 'url' in lower_row:
                    history.append({
                        'url': lower_row.get('url', ''),
                        'domain': cls._extract_domain(lower_row.get('url', '')),
                        'page_title': lower_row.get('title') or lower_row.get('page_title', 'No Title'),
                        'visit_count': int(lower_row.get('visit_count') or lower_row.get('count', 1) or 1),
                        'typed_count': int(lower_row.get('typed_count', 0) or 0),
                        'last_visit_time': lower_row.get('last_visit_time') or lower_row.get('visit_time') or lower_row.get('timestamp') or lower_row.get('date', ''),
                        'browser_type': lower_row.get('browser') or lower_row.get('browser_type', 'CSV Import'),
                        'transition_type': lower_row.get('transition') or 'Link Click',
                        'raw_timestamp': lower_row.get('raw_timestamp', '')
                    })

        return {'history': history, 'downloads': downloads}

    @classmethod
    def _parse_json_evidence(cls, file_path: str) -> dict:
        """Parses JSON evidence export."""
        history = []
        downloads = []

        with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        if isinstance(data, dict):
            hist_list = data.get('history') or data.get('browser_history') or data.get('visits') or []
            dl_list = data.get('downloads') or data.get('download_records') or []

            for h in hist_list:
                url = h.get('url', '')
                if url:
                    history.append({
                        'url': url,
                        'domain': cls._extract_domain(url),
                        'page_title': h.get('title') or h.get('page_title', 'No Title'),
                        'visit_count': int(h.get('visit_count', 1)),
                        'typed_count': int(h.get('typed_count', 0)),
                        'last_visit_time': h.get('last_visit_time') or h.get('timestamp', ''),
                        'browser_type': h.get('browser_type') or data.get('browser', 'JSON Import'),
                        'transition_type': h.get('transition_type', 'Link Click'),
                        'raw_timestamp': str(h.get('raw_timestamp', ''))
                    })

            for d in dl_list:
                filename = d.get('filename') or 'unknown_file'
                downloads.append({
                    'filename': filename,
                    'file_path': d.get('file_path', filename),
                    'source_url': d.get('source_url', 'N/A'),
                    'source_domain': cls._extract_domain(d.get('source_url', '')),
                    'start_time': d.get('start_time') or d.get('timestamp', ''),
                    'end_time': d.get('end_time', ''),
                    'download_status': d.get('download_status', 'Complete'),
                    'file_size': int(d.get('file_size', 0)),
                    'mime_type': d.get('mime_type', 'application/octet-stream')
                })

        elif isinstance(data, list):
            for item in data:
                if 'filename' in item:
                    downloads.append({
                        'filename': item.get('filename', 'downloaded_file'),
                        'file_path': item.get('file_path', ''),
                        'source_url': item.get('source_url') or item.get('url', 'N/A'),
                        'source_domain': cls._extract_domain(item.get('source_url') or item.get('url', '')),
                        'start_time': item.get('start_time') or item.get('timestamp', ''),
                        'end_time': item.get('end_time', ''),
                        'download_status': item.get('download_status', 'Complete'),
                        'file_size': int(item.get('file_size', 0)),
                        'mime_type': item.get('mime_type', 'application/octet-stream')
                    })
                elif 'url' in item:
                    history.append({
                        'url': item.get('url', ''),
                        'domain': cls._extract_domain(item.get('url', '')),
                        'page_title': item.get('title') or item.get('page_title', 'No Title'),
                        'visit_count': int(item.get('visit_count', 1)),
                        'typed_count': int(item.get('typed_count', 0)),
                        'last_visit_time': item.get('last_visit_time') or item.get('timestamp', ''),
                        'browser_type': item.get('browser_type', 'JSON Import'),
                        'transition_type': item.get('transition_type', 'Link Click'),
                        'raw_timestamp': str(item.get('raw_timestamp', ''))
                    })

        return {'history': history, 'downloads': downloads}

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
