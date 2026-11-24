"""
Synthetic Forensic Sample Data Generator for WebFootprint.
Generates realistic, court-demonstration ready sample datasets:
- sample_chrome_history.db (Real Chromium SQLite schema with WebKit timestamps)
- sample_firefox_places.sqlite (Real Firefox SQLite schema with PRTime timestamps)
- sample_history.csv
- sample_downloads.csv
- sample_evidence.json
"""

import os
import sys
import sqlite3
import csv
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def to_webkit_timestamp(dt: datetime) -> int:
    """Converts a Python UTC datetime to WebKit microseconds since 1601-01-01."""
    epoch_diff_seconds = 11644473600.0
    unix_seconds = dt.timestamp()
    webkit_seconds = unix_seconds + epoch_diff_seconds
    return int(webkit_seconds * 1_000_000)

def to_firefox_prtime(dt: datetime) -> int:
    """Converts a Python UTC datetime to Firefox PRTime microseconds since 1970-01-01."""
    return int(dt.timestamp() * 1_000_000)

SAMPLE_HISTORY_DATA = [
    # Normal Developer & Academic Activity
    {"url": "https://www.google.com/search?q=sqlite+forensics+tutorial", "title": "sqlite forensics tutorial - Google Search", "count": 14, "typed": 6, "days_ago": 6, "hour": 9},
    {"url": "https://github.com/torvalds/linux", "title": "GitHub - torvalds/linux: Linux kernel source tree", "count": 22, "typed": 8, "days_ago": 6, "hour": 10},
    {"url": "https://stackoverflow.com/questions/1199645/how-to-read-browser-history", "title": "How to read browser history? - Stack Overflow", "count": 8, "typed": 2, "days_ago": 6, "hour": 11},
    {"url": "https://en.wikipedia.org/wiki/Digital_forensics", "title": "Digital forensics - Wikipedia", "count": 18, "typed": 4, "days_ago": 5, "hour": 14},
    {"url": "https://www.python.org/doc/", "title": "Python 3 Documentation", "count": 25, "typed": 10, "days_ago": 5, "hour": 15},
    {"url": "https://docs.github.com/en/rest", "title": "GitHub REST API Documentation", "count": 7, "typed": 1, "days_ago": 5, "hour": 16},
    {"url": "https://news.ycombinator.com/", "title": "Hacker News", "count": 35, "typed": 15, "days_ago": 4, "hour": 8},
    {"url": "https://www.reddit.com/r/cybersecurity/", "title": "Cybersecurity Discussions - Reddit", "count": 19, "typed": 5, "days_ago": 4, "hour": 12},
    {"url": "https://aws.amazon.com/console/", "title": "AWS Management Console", "count": 12, "typed": 3, "days_ago": 4, "hour": 13},
    {"url": "https://www.cloudflare.com/learning/ddos/what-is-ddos-attack/", "title": "What is a DDoS Attack? | Cloudflare", "count": 6, "typed": 1, "days_ago": 4, "hour": 17},
    {"url": "https://medium.com/@forensics/browser-history-investigation-guide", "title": "Browser History Investigation Guide | Medium", "count": 9, "typed": 0, "days_ago": 3, "hour": 10},
    {"url": "https://www.nist.gov/itl/applied-cybersecurity", "title": "Applied Cybersecurity | NIST", "count": 5, "typed": 1, "days_ago": 3, "hour": 11},
    {"url": "https://csrc.nist.gov/publications/detail/sp/800-86/final", "title": "NIST SP 800-86 Guide to Computer Forensics", "count": 11, "typed": 2, "days_ago": 3, "hour": 14},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP", "title": "An overview of HTTP - MDN Web Docs", "count": 16, "typed": 4, "days_ago": 3, "hour": 16},
    {"url": "https://www.sans.org/blog/digital-forensics-and-incident-response/", "title": "SANS DFIR Blog: Artifact Examination", "count": 8, "typed": 0, "days_ago": 2, "hour": 9},
    {"url": "https://flask.palletsprojects.com/en/stable/", "title": "Welcome to Flask - Flask Documentation", "count": 27, "typed": 9, "days_ago": 2, "hour": 10},
    {"url": "https://chartjs.org/docs/latest/", "title": "Chart.js Documentation", "count": 15, "typed": 3, "days_ago": 2, "hour": 13},
    {"url": "https://getbootstrap.com/docs/5.3/getting-started/introduction/", "title": "Bootstrap v5.3 Documentation", "count": 21, "typed": 7, "days_ago": 2, "hour": 15},
    {"url": "https://www.linkedin.com/feed/", "title": "Feed | LinkedIn", "count": 13, "typed": 4, "days_ago": 1, "hour": 8},
    {"url": "https://mail.google.com/mail/u/0/#inbox", "title": "Gmail - Inbox (1,402)", "count": 48, "typed": 20, "days_ago": 1, "hour": 9},
    {"url": "https://calendar.google.com/calendar/u/0/r", "title": "Google Calendar - Weekly Schedule", "count": 10, "typed": 2, "days_ago": 1, "hour": 11},
    {"url": "https://zoom.us/j/9847291048", "title": "Join Zoom Meeting - Forensic Briefing", "count": 4, "typed": 0, "days_ago": 1, "hour": 14},
    {"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "title": "Rick Astley - Never Gonna Give You Up (Official Music Video)", "count": 5, "typed": 0, "days_ago": 1, "hour": 18},
    {"url": "https://www.nytimes.com/section/technology", "title": "Technology News - The New York Times", "count": 6, "typed": 1, "days_ago": 0, "hour": 7},
    {"url": "https://edition.cnn.com/business", "title": "Business & Markets News - CNN", "count": 7, "typed": 2, "days_ago": 0, "hour": 8},

    # Suspicious / Heuristic Trigger Activity
    {"url": "http://192.168.1.185:8080/admin_portal/login.php?session=bypass", "title": "Internal Gateway Authentication Login", "count": 4, "typed": 3, "days_ago": 4, "hour": 22},
    {"url": "https://paypal-security-account.verify-credentials.top/update_password.php?user=target_victim", "title": "PayPal Security Center: Urgent Verification Required", "count": 3, "typed": 1, "days_ago": 3, "hour": 23},
    {"url": "http://free-gift-airdrop.xyz/claim_reward.php?wallet=0x71C69493f0b2f90a&promo=instant_crypto_cash", "title": "Crypto Airdrop Distribution Claim Free Tokens", "count": 2, "typed": 0, "days_ago": 3, "hour": 23},
    {"url": "https://bit.ly/3xUrK8_confidential_company_salary_leak", "title": "Confidential Salary Report Link", "count": 5, "typed": 2, "days_ago": 2, "hour": 1},
    {"url": "http://185.220.101.5/downloads/dropper_payload.exe", "title": "Direct Binary Download Index", "count": 2, "typed": 1, "days_ago": 2, "hour": 2},
    {"url": "https://portal.bank.secure.auth.credential-check.loan/signin.html?auth_token=8f9a2e&redirect=home", "title": "Online Banking Login Secure Portal", "count": 3, "typed": 1, "days_ago": 1, "hour": 3},
    {"url": "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTSGlqYWNrJyk8L3NjcmlwdD4=", "title": "Embedded Base64 Data Payload", "count": 1, "typed": 0, "days_ago": 1, "hour": 4},
    {"url": "http://xn--gogle-qoa.com/login/authentication?id=49201", "title": "Google Security Checkpoint (Punycode Spoof)", "count": 3, "typed": 1, "days_ago": 0, "hour": 2},
    {"url": "http://fileshare.malicious-network.cc/dl/invoice_receipt_march2026.pdf.exe", "title": "Invoice Viewer and Receipt Downloader", "count": 2, "typed": 1, "days_ago": 0, "hour": 3},
    {"url": "https://tinyurl.com/urgent-security-patch-update", "title": "Windows Urgent Security Update Direct", "count": 4, "typed": 2, "days_ago": 0, "hour": 4}
]

SAMPLE_DOWNLOADS_DATA = [
    {
        "filename": "python-3.12.2-amd64.exe",
        "file_path": "C:\\Users\\suspect\\Downloads\\python-3.12.2-amd64.exe",
        "source_url": "https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe",
        "days_ago": 5, "hour": 15, "minute": 10,
        "status": "Complete", "size": 25482912, "mime": "application/x-msdownload", "danger": 0
    },
    {
        "filename": "NIST.SP.800-86.pdf",
        "file_path": "C:\\Users\\suspect\\Downloads\\NIST.SP.800-86.pdf",
        "source_url": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf",
        "days_ago": 3, "hour": 14, "minute": 22,
        "status": "Complete", "size": 1845201, "mime": "application/pdf", "danger": 0
    },
    {
        "filename": "q4_financial_statement.xlsx",
        "file_path": "C:\\Users\\suspect\\Documents\\q4_financial_statement.xlsx",
        "source_url": "https://internal-portal.corp.com/reports/q4_financial_statement.xlsx",
        "days_ago": 2, "hour": 11, "minute": 5,
        "status": "Complete", "size": 894120, "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "danger": 0
    },
    {
        "filename": "invoice_receipt_march2026.pdf.exe",
        "file_path": "C:\\Users\\suspect\\Downloads\\invoice_receipt_march2026.pdf.exe",
        "source_url": "http://fileshare.malicious-network.cc/dl/invoice_receipt_march2026.pdf.exe",
        "days_ago": 0, "hour": 3, "minute": 12,
        "status": "Complete", "size": 348160, "mime": "application/x-msdownload", "danger": 1
    },
    {
        "filename": "dropper_payload.exe",
        "file_path": "C:\\Users\\suspect\\Downloads\\dropper_payload.exe",
        "source_url": "http://185.220.101.5/downloads/dropper_payload.exe",
        "days_ago": 2, "hour": 2, "minute": 45,
        "status": "Complete", "size": 524288, "mime": "application/octet-stream", "danger": 1
    },
    {
        "filename": "quarterly_budget_macro.xlsm",
        "file_path": "C:\\Users\\suspect\\Downloads\\quarterly_budget_macro.xlsm",
        "source_url": "http://external-partner-consulting.net/files/quarterly_budget_macro.xlsm",
        "days_ago": 1, "hour": 16, "minute": 30,
        "status": "Complete", "size": 1205840, "mime": "application/vnd.ms-excel.sheet.macroEnabled.12", "danger": 0
    },
    {
        "filename": "system_patch_update.msi",
        "file_path": "C:\\Users\\suspect\\AppData\\Local\\Temp\\system_patch_update.msi",
        "source_url": "https://tinyurl.com/urgent-security-patch-update",
        "days_ago": 0, "hour": 4, "minute": 15,
        "status": "Complete", "size": 4194304, "mime": "application/x-msi", "danger": 1
    },
    {
        "filename": "backup_archive.zip",
        "file_path": "C:\\Users\\suspect\\Downloads\\backup_archive.zip",
        "source_url": "https://github.com/torvalds/linux/archive/refs/heads/master.zip",
        "days_ago": 4, "hour": 10, "minute": 30,
        "status": "Complete", "size": 245102000, "mime": "application/zip", "danger": 0
    }
]

def generate_sample_files(target_dir: str):
    """Generates synthetic sample files in target directory."""
    os.makedirs(target_dir, exist_ok=True)
    base_date = datetime.now(timezone.utc)

    # 1. Generate sample_history.csv
    csv_history_path = os.path.join(target_dir, 'sample_history.csv')
    with open(csv_history_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'page_title', 'visit_count', 'typed_count', 'last_visit_time', 'browser_type', 'transition_type'])
        for item in SAMPLE_HISTORY_DATA:
            dt = base_date - timedelta(days=item['days_ago'], hours=item['hour'])
            ts_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            b_type = 'Google Chrome' if item['count'] % 2 == 0 else 'Microsoft Edge'
            trans = 'Typed URL' if item['typed'] > 3 else 'Link Click'
            writer.writerow([item['url'], item['title'], item['count'], item['typed'], ts_str, b_type, trans])

    # 2. Generate sample_downloads.csv
    csv_downloads_path = os.path.join(target_dir, 'sample_downloads.csv')
    with open(csv_downloads_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['filename', 'file_path', 'source_url', 'start_time', 'end_time', 'download_status', 'file_size', 'mime_type'])
        for dl in SAMPLE_DOWNLOADS_DATA:
            dt = base_date - timedelta(days=dl['days_ago'], hours=dl['hour'], minutes=dl['minute'])
            ts_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            writer.writerow([dl['filename'], dl['file_path'], dl['source_url'], ts_str, ts_str, dl['status'], dl['size'], dl['mime']])

    # 3. Generate sample_evidence.json
    json_path = os.path.join(target_dir, 'sample_evidence.json')
    json_data = {
        "metadata": {
            "evidence_type": "Synthetic Demonstration Package",
            "source": "WebFootprint Forensic Suite",
            "generated_date": base_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "label": "SYNTHETIC_DEMO_DATA"
        },
        "history": [],
        "downloads": []
    }
    for item in SAMPLE_HISTORY_DATA:
        dt = base_date - timedelta(days=item['days_ago'], hours=item['hour'])
        json_data["history"].append({
            "url": item['url'],
            "title": item['title'],
            "visit_count": item['count'],
            "typed_count": item['typed'],
            "last_visit_time": dt.strftime('%Y-%m-%d %H:%M:%S'),
            "browser_type": "Google Chrome",
            "transition_type": "Link Click"
        })
    for dl in SAMPLE_DOWNLOADS_DATA:
        dt = base_date - timedelta(days=dl['days_ago'], hours=dl['hour'], minutes=dl['minute'])
        json_data["downloads"].append({
            "filename": dl['filename'],
            "file_path": dl['file_path'],
            "source_url": dl['source_url'],
            "start_time": dt.strftime('%Y-%m-%d %H:%M:%S'),
            "download_status": dl['status'],
            "file_size": dl['size'],
            "mime_type": dl['mime']
        })
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)

    # 4. Generate sample_chrome_history.db (Real Chromium SQLite Database)
    chrome_db_path = os.path.join(target_dir, 'sample_chrome_history.db')
    if os.path.exists(chrome_db_path):
        try:
            os.remove(chrome_db_path)
        except Exception:
            pass

    c_conn = sqlite3.connect(chrome_db_path)
    c_cursor = c_conn.cursor()
    c_cursor.executescript("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url LONGVARCHAR NOT NULL,
            title LONGVARCHAR,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            typed_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0 NOT NULL,
            segment_id INTEGER,
            visit_duration INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            guid VARCHAR(64) NOT NULL,
            current_path LONGVARCHAR NOT NULL,
            target_path LONGVARCHAR NOT NULL,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            state INTEGER NOT NULL,
            danger_type INTEGER NOT NULL,
            interrupt_reason INTEGER NOT NULL,
            raw_hash BLOB,
            end_time INTEGER NOT NULL,
            opened INTEGER NOT NULL,
            last_access_time INTEGER NOT NULL,
            transient INTEGER NOT NULL,
            referrer VARCHAR NOT NULL,
            site_url VARCHAR NOT NULL,
            tab_url VARCHAR NOT NULL,
            tab_referrer_url VARCHAR NOT NULL,
            http_method VARCHAR NOT NULL,
            by_ext_id VARCHAR NOT NULL,
            by_ext_name VARCHAR NOT NULL,
            etag VARCHAR NOT NULL,
            last_modified VARCHAR NOT NULL,
            mime_type VARCHAR(255) NOT NULL,
            original_mime_type VARCHAR(255) NOT NULL
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url LONGVARCHAR NOT NULL,
            PRIMARY KEY (id, chain_index)
        );
    """)

    for idx, item in enumerate(SAMPLE_HISTORY_DATA, start=1):
        dt = base_date - timedelta(days=item['days_ago'], hours=item['hour'])
        webkit_ts = to_webkit_timestamp(dt)
        c_cursor.execute("""
            INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (idx, item['url'], item['title'], item['count'], item['typed'], webkit_ts))

        trans_code = 1 if item['typed'] > 3 else 0
        c_cursor.execute("""
            INSERT INTO visits (url, visit_time, transition)
            VALUES (?, ?, ?)
        """, (idx, webkit_ts, trans_code))

    for idx, dl in enumerate(SAMPLE_DOWNLOADS_DATA, start=1):
        dt = base_date - timedelta(days=dl['days_ago'], hours=dl['hour'], minutes=dl['minute'])
        webkit_ts = to_webkit_timestamp(dt)
        c_cursor.execute("""
            INSERT INTO downloads (
                id, guid, current_path, target_path, start_time, received_bytes, total_bytes,
                state, danger_type, interrupt_reason, end_time, opened, last_access_time,
                transient, referrer, site_url, tab_url, tab_referrer_url, http_method,
                by_ext_id, by_ext_name, etag, last_modified, mime_type, original_mime_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            idx, f"guid-{idx:04d}", dl['file_path'], dl['file_path'],
            webkit_ts, dl['size'], dl['size'], 1, dl['danger'], 0,
            webkit_ts + 60_000_000, 1, webkit_ts, 0, '', '', '', '', 'GET',
            '', '', '', '', dl['mime'], dl['mime']
        ))
        c_cursor.execute("""
            INSERT INTO downloads_url_chains (id, chain_index, url)
            VALUES (?, ?, ?)
        """, (idx, 0, dl['source_url']))

    c_conn.commit()
    c_conn.close()

    # 5. Generate sample_firefox_places.sqlite (Real Firefox SQLite Database)
    firefox_db_path = os.path.join(target_dir, 'sample_firefox_places.sqlite')
    if os.path.exists(firefox_db_path):
        try:
            os.remove(firefox_db_path)
        except Exception:
            pass

    f_conn = sqlite3.connect(firefox_db_path)
    f_cursor = f_conn.cursor()
    f_cursor.executescript("""
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url LONGVARCHAR NOT NULL,
            title LONGVARCHAR,
            rev_host LONGVARCHAR,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0 NOT NULL,
            typed INTEGER DEFAULT 0 NOT NULL,
            favicon_id INTEGER,
            frecency INTEGER DEFAULT -1 NOT NULL,
            last_visit_date INTEGER,
            guid TEXT,
            foreign_count INTEGER DEFAULT 0 NOT NULL,
            url_hash INTEGER DEFAULT 0 NOT NULL,
            description TEXT,
            preview_image_url TEXT,
            origin_id INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_visit INTEGER,
            place_id INTEGER NOT NULL,
            visit_date INTEGER,
            visit_type INTEGER,
            session INTEGER
        );
        CREATE TABLE moz_annos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id INTEGER NOT NULL,
            anno_attribute_id INTEGER NOT NULL,
            content LONGVARCHAR,
            flags INTEGER DEFAULT 0,
            expiration INTEGER DEFAULT 4,
            type INTEGER DEFAULT 3,
            dateAdded INTEGER,
            lastModified INTEGER
        );
        CREATE TABLE moz_anno_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(32) UNIQUE NOT NULL
        );
        INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'downloads/destinationFileURI');
        INSERT INTO moz_anno_attributes (id, name) VALUES (2, 'downloads/metaData');
    """)

    for idx, item in enumerate(SAMPLE_HISTORY_DATA, start=1):
        dt = base_date - timedelta(days=item['days_ago'], hours=item['hour'])
        prtime_ts = to_firefox_prtime(dt)
        f_cursor.execute("""
            INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (idx, item['url'], item['title'], item['count'], item['typed'], prtime_ts))

        f_cursor.execute("""
            INSERT INTO moz_historyvisits (place_id, visit_date, visit_type)
            VALUES (?, ?, ?)
        """, (idx, prtime_ts, 2 if item['typed'] > 3 else 1))

    # Add downloads in Firefox annotations
    for idx, dl in enumerate(SAMPLE_DOWNLOADS_DATA[:4], start=100):
        dt = base_date - timedelta(days=dl['days_ago'], hours=dl['hour'])
        prtime_ts = to_firefox_prtime(dt)
        f_cursor.execute("""
            INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date)
            VALUES (?, ?, ?, 1, 0, ?)
        """, (idx, dl['source_url'], dl['filename'], prtime_ts))

        f_cursor.execute("""
            INSERT INTO moz_historyvisits (place_id, visit_date, visit_type)
            VALUES (?, ?, 7)
        """, (idx, prtime_ts))

        f_cursor.execute("""
            INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded, lastModified)
            VALUES (?, 1, ?, ?, ?)
        """, (idx, dl['file_path'], prtime_ts, prtime_ts))

    f_conn.commit()
    f_conn.close()

    print(f"Sample evidence dataset successfully written to {target_dir}")

if __name__ == '__main__':
    from config import Config
    generate_sample_files(Config.SAMPLE_DATA_FOLDER)
