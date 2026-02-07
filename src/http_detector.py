"""
HTTP Attack Detector
Detects common HTTP-based attacks including:
- SQL Injection attempts
- XSS (Cross-Site Scripting) attempts
- Path traversal attacks
- Command injection attempts
"""

import re
from datetime import datetime
from custom_structures import CustomHashTable


class HTTPDetector:
    """
    Detects HTTP-based attacks by analyzing HTTP request logs.
    """
    
    # Attack patterns
    SQL_INJECTION_PATTERNS = [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from)",
        r"(?i)(drop\s+table|update\s+.*\s+set|--|\#|\/\*)",
        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|'.*or.*')"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*="
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r";\s*cat\s+",
        r";\s*ls\s+",
        r";\s*rm\s+",
        r"\|\s*cat\s+",
        r"`.*`",
        r"\$\(.*\)"
    ]
    
    def __init__(self):
        """Initialize HTTP attack detector."""
        # Using custom hash table for tracking IPs
        self.attack_tracker = CustomHashTable(size=100)
        self.detected_attacks = []
    
    def detect_sql_injection(self, request_string):
        """
        Detect SQL injection attempts.
        
        Args:
            request_string (str): HTTP request content
        
        Returns:
            bool: True if SQL injection detected
        """
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, request_string, re.IGNORECASE):
                return True
        return False
    
    def detect_xss(self, request_string):
        """
        Detect XSS attempts.
        
        Args:
            request_string (str): HTTP request content
        
        Returns:
            bool: True if XSS detected
        """
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, request_string, re.IGNORECASE):
                return True
        return False
    
    def detect_path_traversal(self, request_string):
        """
        Detect path traversal attempts.
        
        Args:
            request_string (str): HTTP request content
        
        Returns:
            bool: True if path traversal detected
        """
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, request_string):
                return True
        return False
    
    def detect_command_injection(self, request_string):
        """
        Detect command injection attempts.
        
        Args:
            request_string (str): HTTP request content
        
        Returns:
            bool: True if command injection detected
        """
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, request_string):
                return True
        return False
    
    def analyze_request(self, ip_address, request_string):
        """
        Analyze HTTP request for various attack types.
        
        Args:
            ip_address (str): Source IP address
            request_string (str): HTTP request content
        
        Returns:
            dict: Attack details if detected, None otherwise
        """
        attack_types = []
        
        if self.detect_sql_injection(request_string):
            attack_types.append("SQL_INJECTION")
        
        if self.detect_xss(request_string):
            attack_types.append("XSS")
        
        if self.detect_path_traversal(request_string):
            attack_types.append("PATH_TRAVERSAL")
        
        if self.detect_command_injection(request_string):
            attack_types.append("COMMAND_INJECTION")
        
        if attack_types:
            # Track in custom hash table
            current_count = self.attack_tracker.get(ip_address) or 0
            self.attack_tracker.insert(ip_address, current_count + 1)
            
            attack_info = {
                'ip': ip_address,
                'attack_types': attack_types,
                'request': request_string[:200],  # First 200 chars
                'timestamp': datetime.now().isoformat(),
                'threat_level': self._calculate_threat_level(attack_types)
            }
            
            self.detected_attacks.append(attack_info)
            return attack_info
        
        return None
    
    def _calculate_threat_level(self, attack_types):
        """
        Calculate threat level based on attack types.
        
        Args:
            attack_types (list): List of detected attack types
        
        Returns:
            str: Threat level
        """
        if len(attack_types) >= 3:
            return "CRITICAL"
        elif "SQL_INJECTION" in attack_types or "COMMAND_INJECTION" in attack_types:
            return "HIGH"
        elif len(attack_types) >= 2:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def get_attack_summary(self):
        """
        Get summary of detected HTTP attacks.
        
        Returns:
            dict: Summary statistics
        """
        if not self.detected_attacks:
            return {
                'total_attacks': 0,
                'unique_ips': 0,
                'by_type': {}
            }
        
        attack_types_count = {}
        for attack in self.detected_attacks:
            for attack_type in attack['attack_types']:
                attack_types_count[attack_type] = attack_types_count.get(attack_type, 0) + 1
        
        return {
            'total_attacks': len(self.detected_attacks),
            'unique_ips': len(self.attack_tracker),
            'by_type': attack_types_count
        }


# Test the HTTP detector
if __name__ == "__main__":
    detector = HTTPDetector()
    
    print("Testing HTTP Attack Detector...\n")
    
    # Test cases
    test_requests = [
        ("192.168.1.100", "GET /index.php?id=1' OR '1'='1 HTTP/1.1"),
        ("192.168.1.101", "GET /search?q=<script>alert('XSS')</script> HTTP/1.1"),
        ("192.168.1.102", "GET /files/../../etc/passwd HTTP/1.1"),
        ("192.168.1.103", "GET /exec?cmd=;cat /etc/shadow HTTP/1.1"),
        ("192.168.1.100", "POST /login.php union select * from users"),
    ]
    
    for ip, request in test_requests:
        result = detector.analyze_request(ip, request)
        if result:
            print(f"🚨 Attack Detected!")
            print(f"   IP: {result['ip']}")
            print(f"   Types: {', '.join(result['attack_types'])}")
            print(f"   Threat Level: {result['threat_level']}")
            print(f"   Request: {result['request'][:80]}...")
            print()
    
    print("Summary:")
    summary = detector.get_attack_summary()
    print(f"   Total Attacks: {summary['total_attacks']}")
    print(f"   Unique IPs: {summary['unique_ips']}")
    print(f"   By Type: {summary['by_type']}")
