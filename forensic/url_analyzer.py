"""
Suspicious URL Heuristic Detection Engine for WebFootprint.
Performs rule-based, non-intrusive heuristic analysis on extracted URLs.
Never visits or executes target URLs.
"""

import re
import urllib.parse
from config import Config

class URLAnalyzer:
    """
    Analyzes URLs for forensic risk indicators using deterministic heuristic rules.
    """

    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$')
    PUNYCODE_PATTERN = re.compile(r'xn--[a-z0-9]+', re.IGNORECASE)

    @classmethod
    def analyze_url(cls, url: str) -> dict:
        """
        Analyzes a URL and returns risk level, heuristic score, and detailed detection reasons.
        """
        reasons = []
        score = 0

        if not url or not isinstance(url, str):
            return {
                'url': url or '',
                'domain': '',
                'risk_level': 'LOW RISK',
                'heuristic_score': 0,
                'reasons': ['Empty or invalid URL format']
            }

        url = url.strip()

        try:
            parsed = urllib.parse.urlsplit(url)
        except Exception as e:
            return {
                'url': url,
                'domain': 'invalid',
                'risk_level': 'HIGH RISK',
                'heuristic_score': 60,
                'reasons': [f'Malformed URL structure could not be parsed: {str(e)}']
            }

        scheme = (parsed.scheme or '').lower()
        netloc = (parsed.netloc or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
        
        # Extract host without port
        host = netloc.split(':')[0] if netloc else ''

        # 1. Scheme Check
        if scheme in ['javascript', 'data', 'vbscript']:
            score += 50
            reasons.append(f"High-risk URI scheme detected: '{scheme}:' (often used for code execution/XSS)")
        elif scheme in ['file']:
            score += 35
            reasons.append("Local file scheme accessed via browser ('file://')")
        elif scheme not in ['http', 'https', 'ftp', '']:
            score += 20
            reasons.append(f"Unusual browser protocol scheme: '{scheme}:'")

        # 2. IP address used instead of domain name
        if cls.IP_PATTERN.match(host):
            score += 40
            reasons.append(f"Direct IP address used as host ({host}) instead of registered domain")

        # 3. Punycode / Internationalized Domain Name (IDN Homograph attack indicator)
        if cls.PUNYCODE_PATTERN.search(netloc):
            score += 35
            reasons.append("Punycode domain detected ('xn--'), indicator of potential IDN homograph spoofing")

        # 4. URL Length Check
        if len(url) > Config.SUSPICIOUS_URL_MAX_LENGTH:
            score += 15
            reasons.append(f"Unusually long URL ({len(url)} characters; threshold is {Config.SUSPICIOUS_URL_MAX_LENGTH})")
        if len(query) > 100:
            score += 10
            reasons.append(f"Excessively long query string ({len(query)} characters), possible payload encoding")

        # 5. Suspicious URL Shorteners
        for shortener in Config.COMMON_SHORTENERS:
            if host == shortener or host.endswith('.' + shortener):
                score += 20
                reasons.append(f"URL shortener domain detected: '{shortener}' (masks true destination)")
                break

        # 6. High-risk Top Level Domains (TLDs)
        for tld in Config.HIGH_RISK_TLDS:
            if host.endswith(tld):
                score += 25
                reasons.append(f"High-risk / frequently abused top-level domain detected: '{tld}'")
                break

        # 7. Excessive Subdomains (Domain shadowing or evasion)
        parts = [p for p in host.split('.') if p]
        if len(parts) > Config.SUSPICIOUS_SUBDOMAIN_COUNT + 2:
            score += 20
            reasons.append(f"Excessive subdomain nesting detected ({len(parts)-2} subdomains: '{host}')")

        # 8. Misleading credentials or '@' in authority
        if '@' in url.split('?')[0]:
            score += 40
            reasons.append("Embedded '@' symbol in URL authority, common credential/phishing deception technique")

        # 9. Suspicious keywords in domain host (Brand spoofing / Phishing indicators)
        host_keywords = [kw for kw in Config.SUSPICIOUS_KEYWORDS if kw in host]
        if host_keywords:
            weight = min(len(host_keywords) * 15, 35)
            score += weight
            reasons.append(f"Sensitive or brand keyword(s) detected in domain hostname: {', '.join(host_keywords[:4])}")

        # 10. Suspicious keywords in URL path or parameters
        path_query_text = (path + '?' + query).lower()
        matched_path_keywords = [kw for kw in Config.SUSPICIOUS_KEYWORDS if kw in path_query_text and kw not in host_keywords]
        if matched_path_keywords:
            weight = min(len(matched_path_keywords) * 10, 30)
            score += weight
            reasons.append(f"Sensitive or suspicious keyword(s) detected in path/query: {', '.join(matched_path_keywords[:4])}")

        # 10. Obfuscated or hexadecimal characters in path
        if re.search(r'%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}', url, re.IGNORECASE):
            score += 15
            reasons.append("Multiple consecutive percent-encoded bytes, potential obfuscation")

        # 12. Command injection or script patterns in query
        if re.search(r'(?:cmd=|exec=|system=|eval\(|base64_decode|<script)', path_query_text, re.IGNORECASE):
            score += 35
            reasons.append("Potential code execution or command payload pattern identified in URL parameter")

        # Classification mapping
        if score >= 50:
            risk_level = "HIGH RISK"
        elif score >= 25:
            risk_level = "MEDIUM RISK"
        elif score > 0:
            risk_level = "LOW RISK"
        else:
            risk_level = "NORMAL"

        return {
            'url': url,
            'domain': host or 'unknown-domain',
            'risk_level': risk_level,
            'heuristic_score': score,
            'reasons': reasons if reasons else ['No significant suspicious indicators detected']
        }
