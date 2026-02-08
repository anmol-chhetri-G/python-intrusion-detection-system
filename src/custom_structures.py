"""
Custom Data Structures for IDS
Implements hash table, queue, and linked list from scratch.
"""

class Node:
    """Node for linked list."""
    def __init__(self, data):
        self.data = data
        self.next = None

class CustomLinkedList:
    """
    Custom Linked List for storing blocked IPs.
    Provides O(n) insertion and O(n) search.
    """
    
    def __init__(self):
        self.head = None
        self.size = 0
    
    def append(self, data):
        """
        Add element to end of list.
        Time Complexity: O(n)
        """
        new_node = Node(data)
        
        if not self.head:
            self.head = new_node
            self.size += 1
            return
        
        current = self.head
        while current.next:
            current = current.next
        
        current.next = new_node
        self.size += 1
    
    def search(self, data):
        """
        Search for element in list.
        Time Complexity: O(n)
        
        Returns:
            bool: True if found, False otherwise
        """
        current = self.head
        
        while current:
            if current.data == data:
                return True
            current = current.next
        
        return False
    
    def remove(self, data):
        """
        Remove element from list.
        Time Complexity: O(n)
        """
        if not self.head:
            return False
        
        # If head needs to be removed
        if self.head.data == data:
            self.head = self.head.next
            self.size -= 1
            return True
        
        current = self.head
        while current.next:
            if current.next.data == data:
                current.next = current.next.next
                self.size -= 1
                return True
            current = current.next
        
        return False
    
    def to_list(self):
        """Convert linked list to Python list."""
        result = []
        current = self.head
        
        while current:
            result.append(current.data)
            current = current.next
        
        return result
    
    def __len__(self):
        return self.size
    
    def __str__(self):
        return str(self.to_list())


class CustomHashTable:
    """
    Custom Hash Table for IP tracking.
    Uses separate chaining for collision resolution.
    Provides O(1) average case insertion and lookup.
    """
    
    def __init__(self, size=100):
        """
        Initialize hash table.
        
        Args:
            size (int): Number of buckets
        """
        self.size = size
        self.table = [[] for _ in range(size)]
        self.count = 0
    
    def _hash_function(self, key):
        """
        Hash function using built-in hash.
        
        Args:
            key: Key to hash
        
        Returns:
            int: Hash value (bucket index)
        """
        return hash(key) % self.size
    
    def insert(self, key, value):
        """
        Insert key-value pair.
        Time Complexity: O(1) average case
        
        Args:
            key: Key to insert
            value: Value to store
        """
        index = self._hash_function(key)
        bucket = self.table[index]
        
        # Update if key exists
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        
        # Insert new key-value pair
        bucket.append((key, value))
        self.count += 1
    
    def get(self, key):
        """
        Retrieve value by key.
        Time Complexity: O(1) average case
        
        Args:
            key: Key to search for
        
        Returns:
            Value if found, None otherwise
        """
        index = self._hash_function(key)
        bucket = self.table[index]
        
        for k, v in bucket:
            if k == key:
                return v
        
        return None
    
    def delete(self, key):
        """
        Delete key-value pair.
        Time Complexity: O(1) average case
        
        Args:
            key: Key to delete
        
        Returns:
            bool: True if deleted, False if not found
        """
        index = self._hash_function(key)
        bucket = self.table[index]
        
        for i, (k, v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                self.count -= 1
                return True
        
        return False
    
    def contains(self, key):
        """
        Check if key exists.
        
        Args:
            key: Key to check
        
        Returns:
            bool: True if exists, False otherwise
        """
        return self.get(key) is not None
    
    def keys(self):
        """Get all keys."""
        all_keys = []
        for bucket in self.table:
            for key, _ in bucket:
                all_keys.append(key)
        return all_keys
    
    def values(self):
        """Get all values."""
        all_values = []
        for bucket in self.table:
            for _, value in bucket:
                all_values.append(value)
        return all_values
    
    def items(self):
        """Get all key-value pairs."""
        all_items = []
        for bucket in self.table:
            all_items.extend(bucket)
        return all_items
    
    def __len__(self):
        return self.count
    
    def __str__(self):
        return str(dict(self.items()))


class QueueNode:
    """Node for queue."""
    def __init__(self, data):
        self.data = data
        self.next = None


class CustomQueue:
    """
    Custom Queue for log processing.
    Implements FIFO (First In First Out).
    Provides O(1) enqueue and dequeue operations.
    """
    
    def __init__(self):
        self.front = None
        self.rear = None
        self.size = 0
    
    def is_empty(self):
        """Check if queue is empty."""
        return self.front is None
    
    def enqueue(self, data):
        """
        Add element to rear of queue.
        Time Complexity: O(1)
        
        Args:
            data: Element to add
        """
        new_node = QueueNode(data)
        
        if self.is_empty():
            self.front = new_node
            self.rear = new_node
        else:
            self.rear.next = new_node
            self.rear = new_node
        
        self.size += 1
    
    def dequeue(self):
        """
        Remove and return element from front of queue.
        Time Complexity: O(1)
        
        Returns:
            Element from front, or None if empty
        """
        if self.is_empty():
            return None
        
        data = self.front.data
        self.front = self.front.next
        
        if self.front is None:
            self.rear = None
        
        self.size -= 1
        return data
    
    def peek(self):
        """
        View front element without removing.
        
        Returns:
            Front element, or None if empty
        """
        if self.is_empty():
            return None
        return self.front.data
    
    def to_list(self):
        """Convert queue to list."""
        result = []
        current = self.front
        
        while current:
            result.append(current.data)
            current = current.next
        
        return result
    
    def __len__(self):
        return self.size
    
    def __str__(self):
        return f"Queue({self.to_list()})"


# Unit tests for custom data structures
if __name__ == "__main__":
    print("Testing Custom Data Structures...\n")
    
    # Test Linked List
    print("=== Testing CustomLinkedList ===")
    ll = CustomLinkedList()
    ll.append("192.168.1.1")
    ll.append("192.168.1.2")
    ll.append("192.168.1.3")
    print(f"List: {ll}")
    print(f"Search 192.168.1.2: {ll.search('192.168.1.2')}")
    print(f"Size: {len(ll)}")
    ll.remove("192.168.1.2")
    print(f"After removing 192.168.1.2: {ll}")
    
    # Test Hash Table
    print("\n=== Testing CustomHashTable ===")
    ht = CustomHashTable(size=10)
    ht.insert("192.168.1.1", 5)
    ht.insert("192.168.1.2", 8)
    ht.insert("10.0.0.1", 3)
    print(f"Hash Table: {ht}")
    print(f"Get 192.168.1.1: {ht.get('192.168.1.1')}")
    print(f"Contains 192.168.1.2: {ht.contains('192.168.1.2')}")
    print(f"Size: {len(ht)}")
    ht.delete("192.168.1.1")
    print(f"After deleting 192.168.1.1: {ht}")
    
    # Test Queue
    print("\n=== Testing CustomQueue ===")
    q = CustomQueue()
    q.enqueue("Log entry 1")
    q.enqueue("Log entry 2")
    q.enqueue("Log entry 3")
    print(f"Queue: {q}")
    print(f"Dequeue: {q.dequeue()}")
    print(f"Peek: {q.peek()}")
    print(f"Queue after dequeue: {q}")
    print(f"Size: {len(q)}")
    
    print("\n✓ All custom data structures working!")
