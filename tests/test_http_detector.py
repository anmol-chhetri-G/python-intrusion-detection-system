"""
Unit tests for HTTP Detector module.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from http_detector import HTTPDetector


class TestHTTPDetector(unittest.TestCase):
    """Test cases for HTTPDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = HTTPDetector()

    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection."""
        malicious_requests = [
            "GET /index.php?id=1' OR '1'='1",
            "POST /login union select * from users",
            "GET /delete.php?id=1; DROP TABLE users--",
        ]
        for req in malicious_requests:
            self.assertTrue(
                self.detector.detect_sql_injection(req),
                f"Failed to detect SQL injection in: {req}"
            )

    def test_sql_injection_false_positive(self):
        """Test SQL injection false positive prevention."""
        benign_requests = [
            "GET /index.php?id=1",
            "GET /products/123",
            "POST /api/submit form=data",
        ]
        for req in benign_requests:
            self.assertFalse(
                self.detector.detect_sql_injection(req),
                f"False positive for: {req}"
            )

    def test_xss_detection(self):
        """Test XSS pattern detection."""
        malicious_requests = [
            "GET /search?q=<script>alert('XSS')</script>",
            "GET /img src='javascript:alert(1)'",
            "GET /div onerror='alert(1)'",
        ]
        for req in malicious_requests:
            self.assertTrue(
                self.detector.detect_xss(req),
                f"Failed to detect XSS in: {req}"
            )

    def test_path_traversal_detection(self):
        """Test path traversal detection."""
        malicious_requests = [
            "GET /files/../../etc/passwd",
            "GET /images\\..\\..\\windows\\system32",
            "GET /../../etc/shadow",
        ]
        for req in malicious_requests:
            self.assertTrue(
                self.detector.detect_path_traversal(req),
                f"Failed to detect path traversal in: {req}"
            )

    def test_command_injection_detection(self):
        """Test command injection detection."""
        malicious_requests = [
            "GET /exec?cmd=;cat /etc/passwd",
            "GET /download|ls",
            "GET /test`whoami`",
        ]
        for req in malicious_requests:
            self.assertTrue(
                self.detector.detect_command_injection(req),
                f"Failed to detect command injection in: {req}"
            )

    def test_analyze_request_returns_attack_info(self):
        """Test analyze_request returns attack details when attack detected."""
        result = self.detector.analyze_request(
            "192.168.1.100",
            "GET /index.php?id=1' OR '1'='1"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], "192.168.1.100")
        self.assertIn("SQL_INJECTION", result['attack_types'])
        self.assertIn('threat_level', result)

    def test_analyze_request_returns_none_for_benign(self):
        """Test analyze_request returns None for benign requests."""
        result = self.detector.analyze_request(
            "192.168.1.100",
            "GET /index.php?id=1"
        )
        self.assertIsNone(result)

    def test_multiple_attack_types(self):
        """Test detection of multiple attack types in single request."""
        result = self.detector.analyze_request(
            "192.168.1.100",
            "GET /test';cat /etc/passwd<script>alert(1)</script>"
        )
        self.assertIsNotNone(result)
        self.assertGreater(len(result['attack_types']), 1)

    def test_threat_level_calculation(self):
        """Test threat level calculation based on attack types."""
        self.assertEqual(
            self.detector._calculate_threat_level(["SQL_INJECTION"]),
            "HIGH"
        )
        self.assertEqual(
            self.detector._calculate_threat_level(["XSS"]),
            "MEDIUM"
        )
        self.assertEqual(
            self.detector._calculate_threat_level(
                ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL"]
            ),
            "CRITICAL"
        )

    def test_attack_tracking_in_hash_table(self):
        """Test that attacks are tracked in custom hash table."""
        self.detector.analyze_request("192.168.1.100", "GET /test' OR '1'='1")
        self.assertEqual(self.detector.attack_tracker.get("192.168.1.100"), 1)

        self.detector.analyze_request("192.168.1.100", "GET /test2' OR '1'='1")
        self.assertEqual(self.detector.attack_tracker.get("192.168.1.100"), 2)

    def test_get_attack_summary(self):
        """Test attack summary generation."""
        self.detector.analyze_request("192.168.1.100", "GET /test' OR '1'='1")
        self.detector.analyze_request("192.168.1.101", "GET /search?q=<script>")

        summary = self.detector.get_attack_summary()

        self.assertEqual(summary['total_attacks'], 2)
        self.assertEqual(summary['unique_ips'], 2)
        self.assertIn('SQL_INJECTION', summary['by_type'])
        self.assertIn('XSS', summary['by_type'])


if __name__ == '__main__':
    unittest.main()
