"""
Unit tests for Detector module.
"""

import unittest
import sys
sys.path.insert(0, '../src')

from detector import Detector


class TestDetector(unittest.TestCase):
    """Test cases for Detector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = Detector(threshold=5)
    
    def test_detect_threats_above_threshold(self):
        """Test detection of IPs above threshold."""
        failed_attempts = {'192.168.1.100': 7}
        threats = self.detector.detect_threats(failed_attempts)
        
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]['ip'], '192.168.1.100')
        self.assertEqual(threats[0]['attempts'], 7)
    
    def test_detect_no_threats_below_threshold(self):
        """Test no detection for IPs below threshold."""
        failed_attempts = {'192.168.1.100': 3}
        threats = self.detector.detect_threats(failed_attempts)
        
        self.assertEqual(len(threats), 0)
    
    def test_is_malicious(self):
        """Test malicious IP identification."""
        self.assertTrue(self.detector.is_malicious('192.168.1.1', 6))
        self.assertFalse(self.detector.is_malicious('192.168.1.1', 3))
    
    def test_threat_level_calculation(self):
        """Test threat level assignment."""
        test_cases = [
            (3, 'LOW'),
            (7, 'MEDIUM'),
            (12, 'HIGH'),
            (25, 'CRITICAL')
        ]
        
        for attempts, expected_level in test_cases:
            level = self.detector._calculate_threat_level(attempts)
            self.assertEqual(level, expected_level)
    
    def test_multiple_threats(self):
        """Test detecting multiple threats."""
        failed_attempts = {
            '192.168.1.100': 7,
            '192.168.1.101': 15,
            '192.168.1.102': 3,
            '10.0.0.50': 25
        }
        
        threats = self.detector.detect_threats(failed_attempts)
        self.assertEqual(len(threats), 3)  # Only 3 above threshold
    
    def test_custom_hash_table_integration(self):
        """Test custom hash table usage."""
        failed_attempts = {'192.168.1.100': 7}
        self.detector.detect_threats(failed_attempts)
        
        # Should be stored in custom hash table
        attempts = self.detector.get_ip_attempts('192.168.1.100')
        self.assertEqual(attempts, 7)
    
    def test_threat_summary(self):
        """Test threat summary statistics."""
        failed_attempts = {
            '192.168.1.100': 7,   # MEDIUM
            '192.168.1.101': 15,  # HIGH
            '10.0.0.50': 25       # CRITICAL
        }
        
        self.detector.detect_threats(failed_attempts)
        summary = self.detector.get_threat_summary()
        
        self.assertEqual(summary['total'], 3)
        self.assertEqual(summary['by_level']['MEDIUM'], 1)
        self.assertEqual(summary['by_level']['HIGH'], 1)
        self.assertEqual(summary['by_level']['CRITICAL'], 1)
    
    def test_threshold_edge_case(self):
        """Test exactly at threshold."""
        failed_attempts = {'192.168.1.100': 5}
        threats = self.detector.detect_threats(failed_attempts)
        
        self.assertEqual(len(threats), 1)  # Should trigger at threshold


if __name__ == '__main__':
    unittest.main()
