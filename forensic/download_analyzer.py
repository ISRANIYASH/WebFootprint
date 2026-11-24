"""
Download History Analyzer for WebFootprint.
Classifies downloaded file types, evaluates file safety risk, and parses CSV/JSON download logs.
"""

import os
import urllib.parse
from datetime import datetime

class DownloadAnalyzer:
    """
    Assesses downloaded files and extracts downloads from various evidence formats.
    """

    EXECUTABLE_EXTENSIONS = {
        '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar', 
        '.hta', '.pif', '.reg', '.dll', '.com', '.cpl', '.apk'
    }

    ARCHIVE_EXTENSIONS = {
        '.zip', '.rar', '.7z', '.iso', '.tar', '.gz', '.bz2', '.cab', '.dmg'
    }

    DOCUMENT_EXTENSIONS = {
        '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.txt', 
        '.rtf', '.odt', '.csv', '.json', '.xml', '.html'
    }

    MEDIA_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.mp4', '.mp3', 
        '.mkv', '.avi', '.mov', '.wav', '.flac'
    }

    MACRO_ENABLED_DOCS = {
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm'
    }

    @classmethod
    def evaluate_file_risk(cls, filename: str) -> dict:
        """
        Assesses the forensic risk level of a downloaded file by extension and naming.
        """
        ext = os.path.splitext(filename)[1].lower() if filename else ''
        category = 'Other'
        risk = 'Low'
        reason = 'Standard file download'

        if ext in cls.EXECUTABLE_EXTENSIONS:
            category = 'Executable / Script'
            risk = 'High'
            reason = f"Executable or script binary ({ext}), potential payload execution"
        elif ext in cls.MACRO_ENABLED_DOCS:
            category = 'Macro Document'
            risk = 'Medium'
            reason = f"Macro-enabled office document ({ext}), potential VBA payload"
        elif ext in cls.ARCHIVE_EXTENSIONS:
            category = 'Compressed Archive / Image'
            risk = 'Medium'
            reason = f"Archive package ({ext}), may contain nested executable content"
        elif ext in cls.DOCUMENT_EXTENSIONS:
            category = 'Document'
            risk = 'Low'
            reason = f"Common document format ({ext})"
        elif ext in cls.MEDIA_EXTENSIONS:
            category = 'Media'
            risk = 'Low'
            reason = f"Standard multimedia file ({ext})"

        # Double extension check (e.g., invoice.pdf.exe)
        parts = filename.split('.') if filename else []
        if len(parts) > 2 and parts[-1].lower() in [e.strip('.') for e in cls.EXECUTABLE_EXTENSIONS]:
            risk = 'High'
            reason = f"Deceptive double extension detected ({filename}), classic malware masquerade"

        return {
            'extension': ext or 'none',
            'category': category,
            'risk_level': risk,
            'reason': reason
        }

    @staticmethod
    def format_bytes(num_bytes: int) -> str:
        """Converts raw byte count into human-readable string (KB, MB, GB)."""
        if not num_bytes or num_bytes <= 0:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"
