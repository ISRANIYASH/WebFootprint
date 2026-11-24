# WebFootprint – Browser Forensics & Activity Analyzer

WebFootprint is a Python-based Digital Forensics project designed to analyze browser history, investigate website activity, detect suspicious URLs, examine download records, and reconstruct browsing timelines. It features SHA-256 evidence integrity verification, forensic analysis, and automated PDF report generation using Flask, SQLite, and Python.

**WebFootprint** is a comprehensive, college-level digital forensics web application engineered to parse, reconstruct, evaluate, and report on web browsing artifacts extracted from suspect devices during forensic examinations.

Designed for forensic investigators, cybersecurity analysts, and academic examinations, WebFootprint provides automated evidence hashing, multi-browser database parsing (Chromium & Mozilla Gecko), heuristic threat analysis, visual timeline reconstruction, and court-grade PDF reporting.

---

## 1. Key Forensic Capabilities

- **Evidence Ingestion & Cryptographic Chain of Custody:**
  - Automated **SHA-256** hash generation upon acquisition.
  - Immutability assurance: Original evidence files are preserved in read-only containers.
  - Interactive re-verification audit tool to detect tampering or accidental modifications.
- **Multi-Browser Artifact Decoding:**
  - **Google Chrome & Microsoft Edge:** Analyzes Chromium SQLite `History` databases (`urls`, `visits`, and `downloads` tables), converting WebKit timestamps (microseconds since `1601-01-01 UTC`).
  - **Mozilla Firefox:** Analyzes Gecko `places.sqlite` databases (`moz_places`, `moz_historyvisits`, and `moz_annos`), converting PRTime timestamps (microseconds since `1970-01-01 UTC`).
  - **Tabular Exports:** Ingests triage CSV and JSON evidence exports.
- **Rule-Based Suspicious URL Detection Engine:**
  - Non-intrusive static heuristic evaluation (never executes or visits target sites).
  - Flags direct IP addressing, punycode/IDN homograph spoofing, URL shorteners, deceptive credentials (`@`), high-risk TLDs (`.top`, `.xyz`, `.buzz`), and brand-spoofing keywords (`paypal`, `login`, `verify`).
  - Categorizes risk into **LOW RISK**, **MEDIUM RISK**, and **HIGH RISK** with explicit rationales.
- **Payload & Download Artifact Extraction:**
  - Evaluates downloaded file extensions (binaries, macro-enabled documents, compressed archives).
  - Extracts origin URLs, local destination paths, and download completion status.
- **Digital Forensic Activity Timeline:**
  - Unified chronological activity reconstruction across browsing, revisits, downloads, and threat alerts.
  - Single-day drilldown and multi-attribute event filtering.
- **Court-Grade Reporting & Export:**
  - Professional PDF examination reports generated dynamically via **ReportLab** (featuring cryptographic hashes, artifact tables, forensic observations, and ISO/IEC 27037 disclaimers).
  - Raw tabular CSV export for history, downloads, threats, and timeline sequences.

---

## 2. Technology Stack

- **Backend:** Python 3 (Flask, Werkzeug)
- **Database:** SQLite3 (Native Python `sqlite3`, PRAGMA foreign keys, indexed queries)
- **Forensic Processing:** `hashlib` (SHA-256), `datetime` (UTC conversion), `urllib.parse`, `csv`, `json`
- **PDF Report Engine:** ReportLab 5.x with custom `NumberedCanvas` (Dynamic two-pass page numbering)
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5.3, Font Awesome 6.5
- **Visualizations:** Chart.js 4.4 (Dark cybersecurity theme)

---

## 3. Project Directory Structure

```text
df_project/
├── app.py                      # Flask application server & route controllers
├── config.py                   # Central configuration & heuristic thresholds
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
│
├── database/                   # Database access & persistence
│   ├── __init__.py
│   ├── models.py               # SQL schema definitions & indexes
│   └── db.py                   # Connection management & transaction handlers
│
├── forensic/                   # Forensic parsing & analysis engines
│   ├── __init__.py
│   ├── browser_detector.py     # SQLite header & table schema detector
│   ├── chrome_analyzer.py      # Chromium History & WebKit timestamp parser
│   ├── firefox_analyzer.py     # Firefox places.sqlite & PRTime parser
│   ├── history_analyzer.py     # Master analysis coordinator
│   ├── download_analyzer.py    # Download evaluation & danger classifier
│   ├── url_analyzer.py         # Static heuristic threat engine
│   ├── timeline_generator.py   # Chronological activity builder
│   └── integrity_checker.py    # SHA-256 hashing & Chain of Custody
│
├── reports/                    # Formal reporting
│   ├── __init__.py
│   └── report_generator.py     # ReportLab PDF & CSV exports
│
├── sample_data/                # Synthetic examination demonstration datasets
│   ├── generator.py            # Synthetic dataset generator
│   ├── loader.py               # One-click demo case initializer
│   ├── sample_chrome_history.db
│   ├── sample_firefox_places.sqlite
│   ├── sample_history.csv
│   ├── sample_downloads.csv
│   └── sample_evidence.json
│
├── static/                     # Web assets
│   ├── css/style.css           # Custom dark cybersecurity UI theme
│   └── js/dashboard.js         # Chart.js integrations & table filtering
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Master layout with sidebar & topbar
│   ├── dashboard.html          # Executive summary & charts
│   ├── investigations.html     # Case management & switcher
│   ├── evidence.html           # File acquisition & hashing
│   ├── history.html            # Searchable browser history
│   ├── website_analysis.html   # Frequency & temporal patterns
│   ├── suspicious_urls.html    # Threat heuristics table
│   ├── downloads.html          # Downloaded payload analysis
│   ├── timeline.html           # Visual activity timeline
│   ├── integrity.html          # SHA-256 audit & custody register
│   ├── reports.html            # PDF & CSV download portal
│   └── settings.html           # System telemetry & ethics
│
└── tests/                      # Automated unit & integration tests
    ├── __init__.py
    ├── test_browser_analyzer.py
    ├── test_integrity.py
    ├── test_url_analyzer.py
    └── test_reports_and_edge_cases.py
```

---

## 4. Installation & Local Setup

### Step 1: Clone or Navigate to Project Directory
```powershell
cd c:\Users\yashi\OneDrive\Desktop\df_project
```

### Step 2: (Optional) Set up Python Virtual Environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Required Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 4: Run the Application
```powershell
python app.py
```

Open your browser and navigate to:
**http://127.0.0.1:5000**

---

## 5. College Practical Exam Demonstration Guide

When demonstrating this project to examiners, follow this 5-minute practical workflow:

1. **Dashboard Overview:**
   - Launch the portal at `http://127.0.0.1:5000`.
   - Point out that the metrics (Total Visits, Unique Domains, Downloads, Threat Indicators) and Chart.js graphs are calculated live from the SQLite database.
2. **One-Click Demo Ingestion:**
   - Click the **"Load Demo Case"** button in the sidebar or top bar.
   - Show that a synthetic multi-device investigation is created, automatically ingesting both a **Google Chrome `History` database** and a **Mozilla Firefox `places.sqlite` database**.
3. **Evidence Acquisition & Chain of Custody:**
   - Navigate to **Evidence Acquisition** (`/evidence`).
   - Demonstrate the SHA-256 cryptographic digest calculated for each file.
   - Click the copy button to show hash handling.
   - Explain that original files are preserved read-only under ISO/IEC 27037 standards.
4. **Browser History & Website Frequency Analysis:**
   - Navigate to **Browser History** (`/history`) and demonstrate live filtering by Browser (Chrome vs. Firefox), Classification (Normal, Suspicious, High Risk), or search query.
   - Navigate to **Website Analysis** (`/website-analysis`) to show initial access point, most frequent domains, and peak hourly browsing times.
5. **Suspicious URL Heuristic Engine:**
   - Navigate to **Suspicious URLs** (`/suspicious-urls`).
   - Explain how rule-based heuristics caught:
     - Direct IP addresses (`http://192.168.1.185:8080/admin_portal/login.php`).
     - Brand spoofing with high-risk TLDs (`paypal-security-account.verify-credentials.top`).
     - Punycode IDN homograph spoofing (`http://xn--gogle-qoa.com/login`).
     - Double-extension deceptive payloads (`invoice_receipt_march2026.pdf.exe`).
   - Highlight that target URLs are displayed in defanged format (`hxxp://`) for examiner safety.
6. **Digital Forensic Timeline:**
   - Navigate to **Forensic Timeline** (`/timeline`).
   - Filter by date or event type (e.g., "File Downloaded" or "Suspicious URL Encountered") to reconstruct the user's step-by-step actions chronologically.
7. **Evidence Integrity Verification:**
   - Navigate to **Evidence Integrity** (`/integrity`).
   - Click **"Re-Verify Hash Now"**.
   - Show the green verification confirmation proving that no bytes have been modified since acquisition.
8. **Forensic Report Generation:**
   - Navigate to **Forensic Reports** (`/reports`).
   - Click **"Generate & Download PDF Report"**.
   - Open the resulting PDF report to demonstrate the formal, court-admissible layout with executive summary, evidence hashes, tables, observations, and legal limitations.
   - Demonstrate CSV exports for tabular data.

---

## 6. Running Automated Tests

Run the complete automated unit test suite covering Chrome parsing, Firefox parsing, SQLite corruption, tamper detection, heuristic triggers, PDF generation, and CSV exports:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

All 18 test cases run and pass in under one second.

---

## 7. Forensic Principles & Ethical Compliance

- **No Active Probing:** WebFootprint does not establish outgoing network connections to target websites found in browser history.
- **Authorization:** Only analyze evidence files lawfully acquired from systems with proper authorization or consent.
- **Heuristic Transparency:** Heuristic scores provide investigative leads and are not presented as definitive proof of malware infection without file-level corroboration.
