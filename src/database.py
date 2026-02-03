import sqlite3
from datetime import datetime
import os

class Database:
    """
    Manages persistent storage of threat data using SQLite.
    """
    
    def __init__(self, db_path='data/ids.db'):
        """
        Initialize database connection and setup tables.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.setup_database()
    
    def setup_database(self):
        """Create necessary tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                threat_level TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                blocked INTEGER DEFAULT 0,
                notes TEXT
            )
        ''')
        
        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                block_timestamp TEXT NOT NULL,
                reason TEXT
            )
        ''')
        
        # Activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_threat(self, ip, attempts, threat_level, notes=None):
        """
        Save detected threat to database.
        
        Args:
            ip (str): IP address
            attempts (int): Number of failed attempts
            threat_level (str): Severity level
            notes (str, optional): Additional notes
        
        Returns:
            int: ID of inserted record
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threats (ip_address, attempts, threat_level, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, attempts, threat_level, datetime.now().isoformat(), notes))
        
        threat_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return threat_id
    
    def mark_as_blocked(self, ip):
        """
        Mark an IP as blocked in the threats table.
        
        Args:
            ip (str): IP address
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE threats 
            SET blocked = 1 
            WHERE ip_address = ?
        ''', (ip,))
        
        conn.commit()
        conn.close()
    
    def save_blocked_ip(self, ip, reason="Exceeded failed login threshold"):
        """
        Record blocked IP in dedicated table.
        
        Args:
            ip (str): IP address
            reason (str): Reason for blocking
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blocked_ips (ip_address, block_timestamp, reason)
                VALUES (?, ?, ?)
            ''', (ip, datetime.now().isoformat(), reason))
            conn.commit()
        except sqlite3.IntegrityError:
            # IP already blocked
            pass
        
        conn.close()
    
    def get_all_threats(self, limit=100):
        """
        Retrieve all detected threats.
        
        Args:
            limit (int): Maximum number of records to return
        
        Returns:
            list: List of threat tuples
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threats 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def get_blocked_ips(self):
        """
        Get list of all blocked IPs.
        
        Returns:
            list: List of blocked IP records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM blocked_ips ORDER BY block_timestamp DESC')
        results = cursor.fetchall()
        
        conn.close()
        return results
    
    def log_activity(self, event_type, message):
        """
        Log system activity.
        
        Args:
            event_type (str): Type of event (SYSTEM, THREAT, BLOCK, etc.)
            message (str): Event description
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_log (event_type, message, timestamp)
            VALUES (?, ?, ?)
        ''', (event_type, message, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self):
        """
        Get database statistics.
        
        Returns:
            dict: Statistics summary
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threats')
        stats['total_threats'] = cursor.fetchone()[0]
        
        # Total blocked
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        stats['total_blocked'] = cursor.fetchone()[0]
        
        # Threats by level
        cursor.execute('''
            SELECT threat_level, COUNT(*) 
            FROM threats 
            GROUP BY threat_level
        ''')
        stats['by_level'] = dict(cursor.fetchall())
        
        conn.close()
        return stats

# Test the database
if __name__ == "__main__":
    db = Database()
    
    print("Testing Database...")
    
    # Save test threat
    threat_id = db.save_threat('192.168.1.100', 7, 'MEDIUM', 'Test threat')
    print(f"Saved threat with ID: {threat_id}")
    
    # Get all threats
    threats = db.get_all_threats()
    print(f"\nTotal threats in DB: {len(threats)}")
    
    # Save blocked IP
    db.save_blocked_ip('192.168.1.100', 'Testing')
    db.mark_as_blocked('192.168.1.100')
    
    # Get statistics
    stats = db.get_statistics()
    print(f"\nDatabase Statistics:")
    print(f"  Total Threats: {stats['total_threats']}")
    print(f"  Total Blocked: {stats['total_blocked']}")
    print(f"  By Level: {stats['by_level']}")
