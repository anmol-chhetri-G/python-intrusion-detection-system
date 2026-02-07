from datetime import datetime
from custom_structures import CustomHashTable

class Detector:
    """
    Detects malicious activity based on failed login attempts.
    Uses custom hash table for O(1) IP tracking.
    """
    
    def __init__(self, threshold=5):
        """
        Initialize detector with custom data structures.
        
        Args:
            threshold (int): Number of failed attempts to trigger alert
        """
        self.threshold = threshold
        # Using custom hash table instead of dict
        self.ip_tracker = CustomHashTable(size=100)
        self.threat_history = []
    
    def detect_threats(self, failed_attempts):
        """
        Analyze failed attempts and identify threats.
        Uses custom hash table for efficient O(1) lookup.
        
        Args:
            failed_attempts (dict): Dictionary of {ip: attempt_count}
        
        Returns:
            list: List of threat dictionaries
        """
        threats = []
        
        for ip, count in failed_attempts.items():
            # Store in custom hash table
            self.ip_tracker.insert(ip, count)
            
            if count >= self.threshold:
                threat = {
                    'ip': ip,
                    'attempts': count,
                    'threat_level': self._calculate_threat_level(count),
                    'timestamp': datetime.now().isoformat()
                }
                threats.append(threat)
                self.threat_history.append(threat)
        
        return threats
    
    def _calculate_threat_level(self, attempts):
        """
        Calculate threat severity based on attempt count.
        
        Args:
            attempts (int): Number of failed attempts
        
        Returns:
            str: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if attempts >= 20:
            return "CRITICAL"
        elif attempts >= 10:
            return "HIGH"
        elif attempts >= 7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def is_malicious(self, ip, attempt_count):
        """
        Check if an IP should be considered malicious.
        Uses custom hash table for O(1) lookup.
        
        Args:
            ip (str): IP address
            attempt_count (int): Number of failed attempts
        
        Returns:
            bool: True if malicious, False otherwise
        """
        return attempt_count >= self.threshold
    
    def get_ip_attempts(self, ip):
        """
        Get attempt count for specific IP using custom hash table.
        
        Args:
            ip (str): IP address
        
        Returns:
            int: Number of attempts, or 0 if not found
        """
        result = self.ip_tracker.get(ip)
        return result if result is not None else 0
    
    def get_threat_summary(self):
        """
        Get summary statistics of detected threats.
        
        Returns:
            dict: Summary containing total threats and breakdown by level
        """
        if not self.threat_history:
            return {
                'total': 0,
                'by_level': {}
            }
        
        # Use custom hash table for counting
        level_counts = CustomHashTable(size=10)
        
        for threat in self.threat_history:
            level = threat['threat_level']
            current = level_counts.get(level)
            level_counts.insert(level, (current or 0) + 1)
        
        summary = {
            'total': len(self.threat_history),
            'by_level': dict(level_counts.items())
        }
        
        return summary

# Test the detector
if __name__ == "__main__":
    detector = Detector(threshold=5)
    
    # Test data
    test_data = {
        '192.168.1.100': 7,
        '192.168.1.101': 15,
        '192.168.1.102': 3,
        '10.0.0.50': 25
    }
    
    print("Testing Detector with Custom Hash Table...")
    threats = detector.detect_threats(test_data)
    
    print(f"\nDetected {len(threats)} threats:")
    for threat in threats:
        print(f"  {threat['ip']}: {threat['attempts']} attempts - {threat['threat_level']}")
    
    print("\nTesting IP lookup from custom hash table:")
    print(f"  192.168.1.100: {detector.get_ip_attempts('192.168.1.100')} attempts")
    print(f"  192.168.1.102: {detector.get_ip_attempts('192.168.1.102')} attempts")
    
    print("\nThreat Summary:")
    summary = detector.get_threat_summary()
    print(f"  Total: {summary['total']}")
    print(f"  By Level: {summary['by_level']}")
