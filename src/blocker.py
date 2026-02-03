import subprocess
import os
from datetime import datetime

class Blocker:
    """
    Handles IP blocking using iptables (Linux firewall).
    Maintains persistent record of blocked IPs.
    """
    
    def __init__(self, blocked_ips_file='data/blocked_ips.txt'):
        """
        Initialize blocker.
        
        Args:
            blocked_ips_file (str): Path to file storing blocked IPs
        """
        self.blocked_ips_file = blocked_ips_file
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(blocked_ips_file), exist_ok=True)
        
        # Create file if doesn't exist
        if not os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, 'w') as f:
                f.write(f"# Blocked IPs - Started {datetime.now()}\n")
    
    def block_ip(self, ip):
        """
        Block IP address using iptables.
        
        Args:
            ip (str): IP address to block
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if already blocked
            if self._is_blocked(ip):
                print(f"[INFO] IP {ip} is already blocked")
                return True
            
            # Block using iptables
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Save to file
                self._save_to_file(ip)
                print(f"[SUCCESS] Blocked IP: {ip}")
                return True
            else:
                print(f"[ERROR] Failed to block {ip}: {result.stderr}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Command failed: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return False
    
    def _is_blocked(self, ip):
        """
        Check if IP is already blocked.
        
        Args:
            ip (str): IP address
        
        Returns:
            bool: True if blocked, False otherwise
        """
        blocked_ips = self.get_blocked_ips()
        return ip in blocked_ips
    
    def _save_to_file(self, ip):
        """
        Save blocked IP to persistent file.
        
        Args:
            ip (str): IP address
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.blocked_ips_file, 'a') as f:
            f.write(f"{ip} | {timestamp}\n")
    
    def get_blocked_ips(self):
        """
        Read list of blocked IPs from file.
        
        Returns:
            list: List of blocked IP addresses
        """
        try:
            with open(self.blocked_ips_file, 'r') as f:
                ips = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract IP (first part before |)
                        ip = line.split('|')[0].strip()
                        ips.append(ip)
                return ips
        except FileNotFoundError:
            return []
    
    def unblock_ip(self, ip):
        """
        Unblock an IP address (for testing/management).
        
        Args:
            ip (str): IP address to unblock
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[SUCCESS] Unblocked IP: {ip}")
                return True
            else:
                print(f"[ERROR] Failed to unblock {ip}")
                return False
                
        except Exception as e:
            print(f"[ERROR] {e}")
            return False
    
    def list_iptables_rules(self):
        """
        List current iptables rules (for verification).
        
        Returns:
            str: iptables rules output
        """
        try:
            result = subprocess.run(
                ['sudo', 'iptables', '-L', 'INPUT', '-v', '-n'],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

# Test the blocker (BE CAREFUL!)
if __name__ == "__main__":
    blocker = Blocker()
    
    print("Testing Blocker...")
    print("\nCurrent blocked IPs:")
    blocked = blocker.get_blocked_ips()
    print(blocked if blocked else "None")
    
    # WARNING: Only uncomment if you want to test actual blocking
    # test_ip = '192.168.99.99'
    # blocker.block_ip(test_ip)
    # blocker.unblock_ip(test_ip)
    
    print("\nBlocker initialized successfully!")
