"""
Unit tests for Database module.
"""

import unittest
import sys
import os
sys.path.insert(0, '../src')

from database import Database


class TestDatabase(unittest.TestCase):
    """Test cases for Database class."""
    
    def setUp(self):
        """Set up test fixtures with temporary database."""
        self.test_db_path = 'data/test_ids.db'
        self.db = Database(db_path=self.test_db_path)
    
    def tearDown(self):
        """Clean up test database."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_database_creation(self):
        """Test database and tables are created."""
        self.assertTrue(os.path.exists(self.test_db_path))
    
    def test_save_threat(self):
        """Test saving threat to database."""
        threat_id = self.db.save_threat('192.168.1.100', 7, 'MEDIUM')
        self.assertIsNotNone(threat_id)
        self.assertGreater(threat_id, 0)
    
    def test_retrieve_threats(self):
        """Test retrieving saved threats."""
        self.db.save_threat('192.168.1.100', 7, 'MEDIUM')
        self.db.save_threat('192.168.1.101', 15, 'HIGH')
        
        threats = self.db.get_all_threats()
        self.assertEqual(len(threats), 2)
    
    def test_mark_as_blocked(self):
        """Test marking threat as blocked."""
        self.db.save_threat('192.168.1.100', 7, 'MEDIUM')
        self.db.mark_as_blocked('192.168.1.100')
        
        threats = self.db.get_all_threats()
        # Check if blocked flag is set (threats[0][5] is blocked field)
        self.assertEqual(threats[0][5], 1)
    
    def test_save_blocked_ip(self):
        """Test saving blocked IP."""
        self.db.save_blocked_ip('192.168.1.100', 'Test block')
        blocked = self.db.get_blocked_ips()
        
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0][1], '192.168.1.100')
    
    def test_duplicate_blocked_ip(self):
        """Test handling duplicate blocked IP."""
        self.db.save_blocked_ip('192.168.1.100', 'Test block')
        self.db.save_blocked_ip('192.168.1.100', 'Duplicate')
        
        blocked = self.db.get_blocked_ips()
        self.assertEqual(len(blocked), 1)  # Should not duplicate
    
    def test_log_activity(self):
        """Test activity logging."""
        self.db.log_activity('TEST', 'Test message')
        # If no exception, test passes
        self.assertTrue(True)
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        self.db.save_threat('192.168.1.100', 7, 'MEDIUM')
        self.db.save_threat('192.168.1.101', 15, 'HIGH')
        self.db.save_blocked_ip('192.168.1.100', 'Test')
        
        stats = self.db.get_statistics()
        
        self.assertEqual(stats['total_threats'], 2)
        self.assertEqual(stats['total_blocked'], 1)
        self.assertIn('MEDIUM', stats['by_level'])


if __name__ == '__main__':
    unittest.main()
