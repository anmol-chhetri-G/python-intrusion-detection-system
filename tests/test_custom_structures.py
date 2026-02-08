"""
Unit tests for custom data structures.
"""

import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from custom_structures import CustomLinkedList, CustomHashTable, CustomQueue


class TestCustomLinkedList(unittest.TestCase):
    """Test cases for CustomLinkedList."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ll = CustomLinkedList()
    
    def test_append(self):
        """Test appending elements."""
        self.ll.append("192.168.1.1")
        self.ll.append("192.168.1.2")
        self.assertEqual(len(self.ll), 2)
        self.assertEqual(self.ll.to_list(), ["192.168.1.1", "192.168.1.2"])
    
    def test_search_found(self):
        """Test searching for existing element."""
        self.ll.append("192.168.1.1")
        self.ll.append("192.168.1.2")
        self.assertTrue(self.ll.search("192.168.1.1"))
    
    def test_search_not_found(self):
        """Test searching for non-existing element."""
        self.ll.append("192.168.1.1")
        self.assertFalse(self.ll.search("192.168.1.99"))
    
    def test_remove_existing(self):
        """Test removing existing element."""
        self.ll.append("192.168.1.1")
        self.ll.append("192.168.1.2")
        result = self.ll.remove("192.168.1.1")
        self.assertTrue(result)
        self.assertEqual(len(self.ll), 1)
        self.assertFalse(self.ll.search("192.168.1.1"))
    
    def test_remove_non_existing(self):
        """Test removing non-existing element."""
        self.ll.append("192.168.1.1")
        result = self.ll.remove("192.168.1.99")
        self.assertFalse(result)
    
    def test_empty_list(self):
        """Test operations on empty list."""
        self.assertEqual(len(self.ll), 0)
        self.assertFalse(self.ll.search("anything"))
        self.assertEqual(self.ll.to_list(), [])


class TestCustomHashTable(unittest.TestCase):
    """Test cases for CustomHashTable."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ht = CustomHashTable(size=10)
    
    def test_insert_and_get(self):
        """Test inserting and retrieving values."""
        self.ht.insert("192.168.1.1", 5)
        self.assertEqual(self.ht.get("192.168.1.1"), 5)
    
    def test_update_existing_key(self):
        """Test updating existing key."""
        self.ht.insert("192.168.1.1", 5)
        self.ht.insert("192.168.1.1", 10)
        self.assertEqual(self.ht.get("192.168.1.1"), 10)
        self.assertEqual(len(self.ht), 1)
    
    def test_contains(self):
        """Test contains method."""
        self.ht.insert("192.168.1.1", 5)
        self.assertTrue(self.ht.contains("192.168.1.1"))
        self.assertFalse(self.ht.contains("192.168.1.99"))
    
    def test_delete(self):
        """Test deleting key."""
        self.ht.insert("192.168.1.1", 5)
        result = self.ht.delete("192.168.1.1")
        self.assertTrue(result)
        self.assertIsNone(self.ht.get("192.168.1.1"))
    
    def test_delete_non_existing(self):
        """Test deleting non-existing key."""
        result = self.ht.delete("192.168.1.99")
        self.assertFalse(result)
    
    def test_keys_values_items(self):
        """Test keys, values, and items methods."""
        self.ht.insert("ip1", 5)
        self.ht.insert("ip2", 10)
        
        self.assertIn("ip1", self.ht.keys())
        self.assertIn(5, self.ht.values())
        self.assertIn(("ip1", 5), self.ht.items())
    
    def test_collision_handling(self):
        """Test hash collision handling."""
        for i in range(20):
            self.ht.insert(f"ip{i}", i)
        
        for i in range(20):
            self.assertEqual(self.ht.get(f"ip{i}"), i)


class TestCustomQueue(unittest.TestCase):
    """Test cases for CustomQueue."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.q = CustomQueue()
    
    def test_enqueue_dequeue(self):
        """Test basic enqueue and dequeue."""
        self.q.enqueue("log1")
        self.q.enqueue("log2")
        
        self.assertEqual(self.q.dequeue(), "log1")
        self.assertEqual(self.q.dequeue(), "log2")
    
    def test_peek(self):
        """Test peek without removing."""
        self.q.enqueue("log1")
        self.q.enqueue("log2")
        
        self.assertEqual(self.q.peek(), "log1")
        self.assertEqual(len(self.q), 2)
    
    def test_is_empty(self):
        """Test empty check."""
        self.assertTrue(self.q.is_empty())
        self.q.enqueue("log1")
        self.assertFalse(self.q.is_empty())
    
    def test_dequeue_empty(self):
        """Test dequeue on empty queue."""
        result = self.q.dequeue()
        self.assertIsNone(result)
    
    def test_fifo_order(self):
        """Test FIFO ordering."""
        items = ["first", "second", "third"]
        for item in items:
            self.q.enqueue(item)
        
        for expected in items:
            self.assertEqual(self.q.dequeue(), expected)
    
    def test_to_list(self):
        """Test converting queue to list."""
        self.q.enqueue("log1")
        self.q.enqueue("log2")
        self.q.enqueue("log3")
        
        self.assertEqual(self.q.to_list(), ["log1", "log2", "log3"])


if __name__ == '__main__':
    unittest.main()
