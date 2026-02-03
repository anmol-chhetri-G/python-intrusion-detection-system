from collections import defaultdict
from datetime import datetime

class Detector:
    """
    Detects malicious activity based on failed login attempts.
    Uses threshold-based detection algorithm.
    """
    
    def __init__(self, threshold=5):
        """
        Initialize detector with configurable threshold.
        
        Args:
            threshold (int): Number of failed attempts to trigger alert
        """
        self.threshold = threshold
        self.threat_history = []
    
    def detect_threats(self, failed_attempts):
        """
        Analyze failed attempts and identify threats.
        
        Args:
            failed_attempts (dict): Dictionary of {ip: attempt_count}
        
        Returns:
            list: List of threat dictionaries
        """
        threats = []
        
        for ip, count in failed_attempts.items():
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
        
        Args:
            ip (str): IP address
            attempt_count (int): Number of failed attempts
        
        Returns:
            bool: True if malicious, False otherwise
        """
        return attempt_count >= self.threshold
    
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
        
        summary = {
            'total': len(self.threat_history),
            'by_level': defaultdict(int)
        }
        
        for threat in self.threat_history:
            level = threat['threat_level']
            summary['by_level'][level] += 1
        
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
    
    print("Testing Detector...")
    threats = detector.detect_threats(test_data)
    
    print(f"\nDetected {len(threats)} threats:")
    for threat in threats:
        print(f"  {threat['ip']}: {threat['attempts']} attempts - {threat['threat_level']}")
    
    print("\nThreat Summary:")
    summary = detector.get_threat_summary()
    print(f"  Total: {summary['total']}")
    print(f"  By Level: {dict(summary['by_level'])}")
