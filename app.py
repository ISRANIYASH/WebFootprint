"""
WebFootprint – Browser Forensics & Activity Analyzer
Main Flask Application and Controller Layer.
"""

import os
import sys
import uuid
import json
import sqlite3
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, Response, jsonify
)
from werkzeug.utils import secure_filename

# Ensure root directory in sys.path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import Config
from database.db import get_db_connection, db_session, init_db, log_analysis
from forensic.browser_detector import BrowserDetector
from forensic.integrity_checker import IntegrityChecker
from forensic.history_analyzer import HistoryAnalyzer
from forensic.timeline_generator import TimelineGenerator, ActivityAnalyzer
from reports.report_generator import ReportGenerator
from sample_data.loader import load_demo_investigation

app = Flask(__name__)
app.config.from_object(Config)

# Ensure essential runtime folders exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.REPORT_FOLDER, exist_ok=True)
os.makedirs(Config.SAMPLE_DATA_FOLDER, exist_ok=True)

# Helper: Get current active investigation
def get_current_investigation_id():
    """Returns active investigation ID from session or defaults to the latest active case."""
    active_id = session.get('active_investigation_id')
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if active_id:
            cursor.execute("SELECT id FROM investigations WHERE id = ?", (active_id,))
            if cursor.fetchone():
                return active_id

        # Fallback to latest investigation
        cursor.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            session['active_investigation_id'] = row['id']
            return row['id']
    finally:
        conn.close()
    return None

# Context processor for global template variables
@app.context_processor
def inject_global_data():
    conn = get_db_connection()
    all_invs = []
    current_inv = None
    investigator = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, investigator_name, status, created_at FROM investigations ORDER BY created_at DESC")
        all_invs = [dict(r) for r in cursor.fetchall()]

        active_id = get_current_investigation_id()
        if active_id:
            cursor.execute("SELECT * FROM investigations WHERE id = ?", (active_id,))
            inv_row = cursor.fetchone()
            if inv_row:
                current_inv = dict(inv_row)

        cursor.execute("SELECT * FROM investigators ORDER BY id ASC LIMIT 1")
        inv_user = cursor.fetchone()
        if inv_user:
            investigator = dict(inv_user)
    except Exception as e:
        print(f"[CONTEXT PROCESSOR ERROR] {e}")
    finally:
        conn.close()

    return {
        'all_investigations': all_invs,
        'current_investigation': current_inv,
        'current_investigator': investigator,
        'app_version': Config.VERSION,
        'app_name': Config.APP_NAME
    }

# ----------------- ROUTE CONTROLLERS -----------------

@app.route('/')
@app.route('/dashboard')
def dashboard():
    inv_id = get_current_investigation_id()
    if not inv_id:
        # If no investigations exist, automatically load the demo case for instant demo
        inv_id = load_demo_investigation()
        session['active_investigation_id'] = inv_id
        flash("Demonstration case initialized with Chrome and Firefox forensic evidence.", "success")

    stats = ActivityAnalyzer.get_activity_summary(inv_id)

    # Format Chart.js telemetry
    daily_dates = [item['visit_date'] for item in stats.get('daily_activity', [])]
    daily_counts = [item['visits'] for item in stats.get('daily_activity', [])]

    top_domains = [item['domain'] for item in stats.get('most_visited', [])[:7]]
    top_visits = [item['visits'] for item in stats.get('most_visited', [])[:7]]

    browser_labels = [item['browser_type'] for item in stats.get('browser_distribution', [])]
    browser_data = [item['count'] for item in stats.get('browser_distribution', [])]

    risk_labels = [item['classification'] for item in stats.get('classification_ratio', [])]
    risk_data = [item['count'] for item in stats.get('classification_ratio', [])]

    hourly_labels = [item['hour_str'] for item in stats.get('hourly_activity', [])]
    hourly_data = [item['visits'] for item in stats.get('hourly_activity', [])]

    # Recent investigations with primary evidence name
    conn = get_db_connection()
    recent_investigations = []
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.id, i.title, i.investigator_name, i.status, i.created_at,
                   (SELECT original_filename FROM evidence_files WHERE investigation_id = i.id LIMIT 1) AS evidence_filename,
                   (SELECT file_type FROM evidence_files WHERE investigation_id = i.id LIMIT 1) AS file_type
            FROM investigations i
            ORDER BY i.created_at DESC
            LIMIT 5
        """)
        recent_investigations = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        stats=stats,
        daily_dates=daily_dates,
        daily_counts=daily_counts,
        top_domains=top_domains,
        top_visits=top_visits,
        browser_labels=browser_labels,
        browser_data=browser_data,
        risk_labels=risk_labels,
        risk_data=risk_data,
        hourly_labels=hourly_labels,
        hourly_data=hourly_data,
        recent_investigations=recent_investigations
    )

@app.route('/investigations')
def investigations_page():
    conn = get_db_connection()
    cases = []
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.*,
                   (SELECT COUNT(*) FROM evidence_files WHERE investigation_id = i.id) AS evidence_count,
                   (SELECT COUNT(*) FROM browser_history WHERE investigation_id = i.id) AS history_count
            FROM investigations i
            ORDER BY i.created_at DESC
        """)
        cases = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return render_template('investigations.html', active_page='investigations', investigations=cases)

@app.route('/investigations/new', methods=['POST'])
def create_investigation():
    title = request.form.get('title', '').strip()
    investigator = request.form.get('investigator_name', '').strip() or 'Det. S. Vance'
    description = request.form.get('case_description', '').strip()

    if not title:
        flash("Case title cannot be empty.", "error")
        return redirect(url_for('investigations_page'))

    inv_id = f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    with db_session() as conn:
        conn.execute("""
            INSERT INTO investigations (id, title, investigator_name, case_description, status)
            VALUES (?, ?, ?, ?, ?)
        """, (inv_id, title, investigator, description, 'Active'))

    session['active_investigation_id'] = inv_id
    flash(f"Investigation {inv_id} created successfully and set to active.", "success")
    return redirect(url_for('evidence_page'))

@app.route('/investigations/select', methods=['POST'])
def set_active_investigation():
    inv_id = request.form.get('investigation_id')
    if inv_id:
        session['active_investigation_id'] = inv_id
        flash(f"Active investigation switched to {inv_id}.", "success")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/investigations/<inv_id>/delete', methods=['POST'])
def delete_investigation(inv_id):
    with db_session() as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))

    if session.get('active_investigation_id') == inv_id:
        session.pop('active_investigation_id', None)

    flash(f"Investigation {inv_id} and all associated records have been removed.", "success")
    return redirect(url_for('investigations_page'))

@app.route('/evidence')
def evidence_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        flash("Please create or select an investigation case first.", "error")
        return redirect(url_for('investigations_page'))

    conn = get_db_connection()
    evidence_list = []
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY upload_timestamp DESC", (inv_id,))
        evidence_list = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return render_template('evidence.html', active_page='evidence', evidence_list=evidence_list)

@app.route('/evidence/upload', methods=['POST'])
def upload_evidence():
    inv_id = get_current_investigation_id()
    if not inv_id:
        flash("No active investigation selected.", "error")
        return redirect(url_for('investigations_page'))

    if 'evidence_file' not in request.files:
        flash("No file part provided in the request.", "error")
        return redirect(url_for('evidence_page'))

    file = request.files['evidence_file']
    if file.filename == '':
        flash("No file selected for upload.", "error")
        return redirect(url_for('evidence_page'))

    original_filename = file.filename
    source_desc = request.form.get('acquisition_source', '').strip() or 'Direct Evidence Ingestion'
    uploaded_by = request.form.get('uploaded_by', '').strip() or 'Forensic Examiner'

    # Secure storage naming
    evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    safe_name = secure_filename(original_filename) or 'evidence.bin'
    stored_filename = f"{evidence_id}_{safe_name}"
    dest_path = os.path.join(Config.UPLOAD_FOLDER, stored_filename)

    file.save(dest_path)

    # 1. Compute SHA-256 Hash
    try:
        sha256_hash = IntegrityChecker.calculate_sha256(dest_path)
        file_size = os.path.getsize(dest_path)
    except Exception as e:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        flash(f"Failed to calculate cryptographic hash: {str(e)}", "error")
        return redirect(url_for('evidence_page'))

    # 2. Inspect File Structure
    detection = BrowserDetector.detect_evidence_type(dest_path)
    if not detection['is_valid']:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        flash(f"Evidence validation error: {detection.get('error')}", "error")
        return redirect(url_for('evidence_page'))

    detected_type = detection['detected_type']

    # 3. Save Evidence File Metadata
    with db_session() as conn:
        conn.execute("""
            INSERT INTO evidence_files (
                id, investigation_id, original_filename, stored_filename, file_path,
                file_size, file_type, sha256_hash, acquisition_source, uploaded_by, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id, inv_id, original_filename, stored_filename, dest_path,
            file_size, detected_type, sha256_hash, source_desc, uploaded_by, 'Acquired'
        ))

    # 4. Record Initial Chain of Custody
    IntegrityChecker.record_acquisition(
        inv_id, evidence_id, original_filename, source_desc, uploaded_by, sha256_hash
    )

    # 5. Execute Forensic Extraction Pipeline
    try:
        result = HistoryAnalyzer.process_evidence_file(evidence_id, inv_id, dest_path)
        flash(
            f"Evidence '{original_filename}' ingested and analyzed successfully! "
            f"Extracted {result['history_count']} history records, {result['downloads_count']} downloads, "
            f"and detected {result['suspicious_count']} suspicious URLs.", "success"
        )
    except Exception as e:
        flash(f"File uploaded, but forensic artifact extraction encountered an error: {str(e)}", "error")

    return redirect(url_for('evidence_page'))

@app.route('/evidence/<evidence_id>/reprocess', methods=['POST'])
def reprocess_evidence(evidence_id):
    inv_id = get_current_investigation_id()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_files WHERE id = ?", (evidence_id,))
        evd = cursor.fetchone()
        if not evd:
            flash(f"Evidence {evidence_id} not found.", "error")
            return redirect(url_for('evidence_page'))

        # Purge existing records for this evidence to prevent duplication
        with db_session() as sess:
            sess.execute("DELETE FROM browser_history WHERE evidence_id = ?", (evidence_id,))
            sess.execute("DELETE FROM download_records WHERE evidence_id = ?", (evidence_id,))
            sess.execute("DELETE FROM suspicious_urls WHERE evidence_id = ?", (evidence_id,))
            sess.execute("DELETE FROM timeline_events WHERE evidence_id = ?", (evidence_id,))

        result = HistoryAnalyzer.process_evidence_file(evidence_id, inv_id, evd['file_path'])
        flash(f"Re-analysis of {evd['original_filename']} complete! Processed {result['history_count']} records.", "success")
    except Exception as e:
        flash(f"Re-analysis failed: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('evidence_page'))

@app.route('/history')
def history_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    search_query = request.args.get('q', '').strip()
    browser_filter = request.args.get('browser', '').strip()
    class_filter = request.args.get('classification', '').strip()
    date_filter = request.args.get('date', '').strip()
    page = int(request.args.get('page', 1))
    per_page = 25

    conn = get_db_connection()
    records = []
    total_count = 0
    try:
        cursor = conn.cursor()

        # Build dynamic query
        query_base = "FROM browser_history WHERE investigation_id = ?"
        params = [inv_id]

        if search_query:
            query_base += " AND (url LIKE ? OR page_title LIKE ? OR domain LIKE ?)"
            term = f"%{search_query}%"
            params.extend([term, term, term])

        if browser_filter:
            query_base += " AND browser_type LIKE ?"
            params.append(f"%{browser_filter}%")

        if class_filter:
            query_base += " AND classification = ?"
            params.append(class_filter)

        if date_filter:
            query_base += " AND last_visit_time LIKE ?"
            params.append(f"{date_filter}%")

        # Total matching count
        cursor.execute(f"SELECT COUNT(*) AS count {query_base}", params)
        total_count = cursor.fetchone()['count']

        # Paginated fetch
        offset = (page - 1) * per_page
        query_select = f"""
            SELECT id, domain, url, page_title, visit_count, typed_count,
                   last_visit_time, browser_type, transition_type, classification
            {query_base}
            ORDER BY last_visit_time DESC
            LIMIT ? OFFSET ?
        """
        params.extend([per_page, offset])
        cursor.execute(query_select, params)
        records = [dict(r) for r in cursor.fetchall()]

    finally:
        conn.close()

    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

    return render_template(
        'history.html',
        active_page='history',
        history_records=records,
        total_count=total_count,
        current_page=page,
        total_pages=total_pages,
        search_query=search_query,
        browser_filter=browser_filter,
        class_filter=class_filter,
        date_filter=date_filter
    )

@app.route('/website-analysis')
def website_analysis_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    summary = ActivityAnalyzer.get_activity_summary(inv_id)

    daily_dates = [item['visit_date'] for item in summary.get('daily_activity', [])]
    daily_counts = [item['visits'] for item in summary.get('daily_activity', [])]

    hourly_labels = [item['hour_str'] for item in summary.get('hourly_activity', [])]
    hourly_data = [item['visits'] for item in summary.get('hourly_activity', [])]

    return render_template(
        'website_analysis.html',
        active_page='website_analysis',
        summary=summary,
        daily_dates=daily_dates,
        daily_counts=daily_counts,
        hourly_labels=hourly_labels,
        hourly_data=hourly_data
    )

@app.route('/suspicious-urls')
def suspicious_urls_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    search_query = request.args.get('q', '').strip()
    risk_filter = request.args.get('risk', '').strip()

    conn = get_db_connection()
    records = []
    high_count = 0
    med_count = 0
    total_susp = 0
    try:
        cursor = conn.cursor()

        # Counts
        cursor.execute("SELECT COUNT(*) FROM suspicious_urls WHERE investigation_id = ? AND risk_level = 'HIGH RISK'", (inv_id,))
        high_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM suspicious_urls WHERE investigation_id = ? AND risk_level = 'MEDIUM RISK'", (inv_id,))
        med_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM suspicious_urls WHERE investigation_id = ?", (inv_id,))
        total_susp = cursor.fetchone()[0]

        query = "SELECT * FROM suspicious_urls WHERE investigation_id = ?"
        params = [inv_id]

        if search_query:
            query += " AND (url LIKE ? OR domain LIKE ?)"
            term = f"%{search_query}%"
            params.extend([term, term])

        if risk_filter:
            query += " AND risk_level = ?"
            params.append(risk_filter)

        query += " ORDER BY heuristic_score DESC"
        cursor.execute(query, params)
        for r in cursor.fetchall():
            item = dict(r)
            try:
                item['reasons_list'] = json.loads(item['detection_reasons'])
            except Exception:
                item['reasons_list'] = [item['detection_reasons']]
            records.append(item)

    finally:
        conn.close()

    return render_template(
        'suspicious_urls.html',
        active_page='suspicious_urls',
        suspicious_records=records,
        high_risk_count=high_count,
        medium_risk_count=med_count,
        total_suspicious=total_susp,
        search_query=search_query,
        risk_filter=risk_filter
    )

@app.route('/downloads')
def downloads_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    search_query = request.args.get('q', '').strip()
    cat_filter = request.args.get('category', '').strip()
    status_filter = request.args.get('status', '').strip()

    conn = get_db_connection()
    downloads = []
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM download_records WHERE investigation_id = ?"
        params = [inv_id]

        if search_query:
            query += " AND (filename LIKE ? OR source_url LIKE ? OR source_domain LIKE ?)"
            term = f"%{search_query}%"
            params.extend([term, term, term])

        if status_filter:
            query += " AND download_status = ?"
            params.append(status_filter)

        if cat_filter == 'exe':
            query += " AND (filename LIKE '%.exe' OR filename LIKE '%.msi' OR filename LIKE '%.bat')"
        elif cat_filter == 'doc':
            query += " AND (filename LIKE '%.pdf' OR filename LIKE '%.docx' OR filename LIKE '%.xlsx')"
        elif cat_filter == 'archive':
            query += " AND (filename LIKE '%.zip' OR filename LIKE '%.rar' OR filename LIKE '%.tar%')"

        query += " ORDER BY start_time DESC"
        cursor.execute(query, params)
        downloads = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return render_template(
        'downloads.html',
        active_page='downloads',
        downloads=downloads,
        search_query=search_query,
        cat_filter=cat_filter,
        status_filter=status_filter
    )

@app.route('/timeline')
def timeline_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    search_query = request.args.get('q', '').strip()
    type_filter = request.args.get('type', 'all').strip()
    date_filter = request.args.get('date', '').strip()

    events = TimelineGenerator.get_timeline(
        investigation_id=inv_id,
        date_filter=date_filter,
        event_type=type_filter,
        search_query=search_query
    )
    unique_dates = TimelineGenerator.get_unique_event_dates(inv_id)

    return render_template(
        'timeline.html',
        active_page='timeline',
        events=events,
        unique_dates=unique_dates,
        search_query=search_query,
        type_filter=type_filter,
        date_filter=date_filter
    )

@app.route('/integrity')
def integrity_page():
    inv_id = get_current_investigation_id()
    if not inv_id:
        return redirect(url_for('investigations_page'))

    conn = get_db_connection()
    evidence_files = []
    logs = []
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_files WHERE investigation_id = ?", (inv_id,))
        evidence_files = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM chain_of_custody WHERE investigation_id = ? ORDER BY timestamp DESC", (inv_id,))
        logs = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return render_template(
        'integrity.html',
        active_page='integrity',
        evidence_files=evidence_files,
        logs=logs
    )

@app.route('/integrity/verify/<evidence_id>', methods=['POST'])
def verify_evidence_route(evidence_id):
    investigator = session.get('investigator_name', 'System Auditor')
    result = IntegrityChecker.verify_evidence(evidence_id, investigator)

    if result['verified']:
        flash(f"Integrity check for {result['filename']}: VERIFIED! SHA-256 matched original acquisition baseline.", "success")
    else:
        flash(f"Integrity check for {result['filename']}: {result['message']}", "error")

    return redirect(url_for('integrity_page'))

@app.route('/reports')
def reports_page():
    inv_id = get_current_investigation_id()
    stats = ActivityAnalyzer.get_activity_summary(inv_id) if inv_id else {}
    return render_template('reports.html', active_page='reports', stats=stats)

@app.route('/reports/pdf', methods=['POST'])
def download_pdf_report():
    inv_id = get_current_investigation_id()
    if not inv_id:
        flash("No active case to generate report for.", "error")
        return redirect(url_for('investigations_page'))

    try:
        pdf_path = ReportGenerator.generate_pdf_report(inv_id)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=os.path.basename(pdf_path),
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"PDF report generation failed: {str(e)}", "error")
        return redirect(url_for('reports_page'))

@app.route('/reports/export/<export_type>')
def export_csv_route(export_type):
    inv_id = get_current_investigation_id()
    if not inv_id:
        flash("No active case to export data from.", "error")
        return redirect(url_for('investigations_page'))

    valid_types = ['history', 'downloads', 'suspicious', 'timeline']
    if export_type not in valid_types:
        flash(f"Invalid export type '{export_type}'.", "error")
        return redirect(url_for('reports_page'))

    try:
        csv_content = ReportGenerator.export_csv(inv_id, export_type)
        filename = f"{inv_id}_{export_type}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        flash(f"CSV export failed: {str(e)}", "error")
        return redirect(url_for('reports_page'))

@app.route('/settings')
def settings_page():
    db_size = os.path.getsize(Config.DATABASE_PATH) if os.path.exists(Config.DATABASE_PATH) else 0

    uploads_size = 0
    if os.path.exists(Config.UPLOAD_FOLDER):
        for f in os.listdir(Config.UPLOAD_FOLDER):
            fp = os.path.join(Config.UPLOAD_FOLDER, f)
            if os.path.isfile(fp):
                uploads_size += os.path.getsize(fp)

    return render_template(
        'settings.html',
        active_page='settings',
        python_version=sys.version.split()[0],
        db_path=Config.DATABASE_PATH,
        db_size=db_size,
        uploads_size=uploads_size
    )

@app.route('/settings/investigator', methods=['POST'])
def update_investigator():
    name = request.form.get('name', '').strip()
    badge = request.form.get('badge_number', '').strip()
    org = request.form.get('organization', '').strip()

    if not name:
        flash("Investigator name cannot be empty.", "error")
        return redirect(url_for('settings_page'))

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM investigators ORDER BY id ASC LIMIT 1")
        row = cursor.fetchone()
        if row:
            conn.execute("""
                UPDATE investigators SET name = ?, badge_number = ?, organization = ? WHERE id = ?
            """, (name, badge, org, row['id']))
        else:
            conn.execute("""
                INSERT INTO investigators (name, badge_number, organization) VALUES (?, ?, ?)
            """, (name, badge, org))

    flash("Investigator profile updated successfully.", "success")
    return redirect(url_for('settings_page'))

@app.route('/load-demo', methods=['POST'])
def load_demo_route():
    try:
        inv_id = load_demo_investigation()
        session['active_investigation_id'] = inv_id
        flash(f"Demonstration case {inv_id} loaded successfully with Chrome and Firefox forensic evidence!", "success")
    except Exception as e:
        flash(f"Failed to load demonstration case: {str(e)}", "error")
    return redirect(url_for('dashboard'))

# ----------------- APPLICATION INITIALIZER -----------------
init_db()

if __name__ == '__main__':
    print(f"[*] Starting {Config.APP_NAME}")
    print(f"[*] Database: {Config.DATABASE_PATH}")
    print("[*] Local Forensic Portal: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
