"""
Unit tests for Suspicious URL Heuristic Detection Engine.
"""

import unittest
from forensic.url_analyzer import URLAnalyzer

class TestURLAnalyzer(unittest.TestCase):

    def test_normal_url(self):
        res = URLAnalyzer.analyze_url("https://www.google.com/search?q=forensics")
        self.assertEqual(res['risk_level'], 'NORMAL')
        self.assertEqual(res['domain'], 'www.google.com')
        self.assertEqual(res['heuristic_score'], 0)

    def test_direct_ip_address_host(self):
        res = URLAnalyzer.analyze_url("http://192.168.1.150:8080/admin/index.php")
        self.assertIn(res['risk_level'], ['MEDIUM RISK', 'HIGH RISK'])
        self.assertTrue(any("Direct IP address" in r for r in res['reasons']))

    def test_high_risk_schemes(self):
        res_data = URLAnalyzer.analyze_url("data:text/html;base64,PHNjcmlwdD4=")
        self.assertEqual(res_data['risk_level'], 'HIGH RISK')
        self.assertTrue(any("High-risk URI scheme" in r for r in res_data['reasons']))

        res_js = URLAnalyzer.analyze_url("javascript:alert(1)")
        self.assertEqual(res_js['risk_level'], 'HIGH RISK')

        res_file = URLAnalyzer.analyze_url("file:///C:/Windows/System32/cmd.exe")
        self.assertIn(res_file['risk_level'], ['MEDIUM RISK', 'HIGH RISK'])

    def test_url_shorteners(self):
        res = URLAnalyzer.analyze_url("https://bit.ly/3xUrK8_confidential_leak")
        self.assertIn(res['risk_level'], ['LOW RISK', 'MEDIUM RISK'])
        self.assertTrue(any("shortener" in r.lower() for r in res['reasons']))

    def test_punycode_domain(self):
        res = URLAnalyzer.analyze_url("http://xn--gogle-qoa.com/login")
        self.assertIn(res['risk_level'], ['MEDIUM RISK', 'HIGH RISK'])
        self.assertTrue(any("Punycode" in r for r in res['reasons']))

    def test_excessive_subdomains(self):
        res = URLAnalyzer.analyze_url("http://a.b.c.d.e.f.example.com/portal")
        self.assertTrue(any("Excessive subdomain" in r for r in res['reasons']))

    def test_high_risk_tld_and_sensitive_keywords(self):
        res = URLAnalyzer.analyze_url("https://paypal-update-credentials.account-verify.top/login.php?password=123")
        self.assertEqual(res['risk_level'], 'HIGH RISK')
        self.assertTrue(any("top-level domain" in r for r in res['reasons']))
        self.assertTrue(any("keyword" in r.lower() for r in res['reasons']))

    def test_empty_and_malformed_url(self):
        res_empty = URLAnalyzer.analyze_url("")
        self.assertEqual(res_empty['risk_level'], 'LOW RISK')
        self.assertEqual(res_empty['domain'], '')

if __name__ == '__main__':
    unittest.main()
