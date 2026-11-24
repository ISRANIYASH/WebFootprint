import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'webfootprint-forensic-secret-key-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'webfootprint.db')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORT_FOLDER = os.path.join(BASE_DIR, 'generated_reports')
    SAMPLE_DATA_FOLDER = os.path.join(BASE_DIR, 'sample_data')
    MAX_CONTENT_LENGTH = 150 * 1024 * 1024  # 150 MB max upload
    ALLOWED_EXTENSIONS = {'db', 'sqlite', 'sqlite3', 'csv', 'json', 'data', 'bak'}
    APP_NAME = "WebFootprint – Browser Forensics & Activity Analyzer"
    VERSION = "2.1.0"
    DEBUG = False
    TESTING = False

    # Heuristic detection thresholds
    SUSPICIOUS_URL_MAX_LENGTH = 120
    SUSPICIOUS_SUBDOMAIN_COUNT = 3
    COMMON_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 
        'ow.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc', 'shorte.st'
    }
    HIGH_RISK_TLDS = {
        '.top', '.xyz', '.buzz', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', 
        '.work', '.date', '.loan', '.stream', '.review', '.trade', '.accountant'
    }
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'banking', 'secure', 'update',
        'wallet', 'paypal', 'admin', 'password', 'credential', 'auth', 'recover',
        'free-gift', 'free-crypto', 'airdrop', 'invoice-download', 'wire-transfer'
    ]
