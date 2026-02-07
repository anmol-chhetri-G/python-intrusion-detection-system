import subprocess
import os
from datetime import datetime
from custom_structures import CustomLinkedList

class Blocker:
    """
    Handles IP blocking using iptables (Linux firewall).
    Uses custom linked list for maintaining blocked IPs.
    """
    
    def __init__(self, blocked_ips_file='data/blocked_ips.txt'):
        """
        Initialize blocker with custom linked list.
        
        Args:
            blocked_ips_file (str): Path to file storing blocked IPs
        """
        self.blocked_ips_file = blocked_ips_file
        # Using custom linked list instead of Python list
        self.blocked_ips_list = CustomLinkedList()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(blocked_ips_file), exist_ok=True)
        
        # Create file if doesn't exist
        if not os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, 'w') as f:
                f.write(f"# Blocked IPs - Started {datetime.now()}\n")
        
        # Load existing blocked IPs into custom linked list
        self._load_blocked_ips()
    
    def _load_blocked_ips(self):
        """Load existing blocked IPs into custom linked list."""
        try:
            with open(self.blocked_ips_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip = line.split('|')[0].strip()
                        self.blocked_ips_list.append(ip)
        except FileNotFoundError:
            pass
    
    def block_ip(self, ip):
        """
        Block IP address using iptables.
        Updates custom linked list.
        
        Args:
            ip (str): IP address to block
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if already blocked using custom linked list
            if self.blocked_ips_list.search(ip):
                print(f"[INFO] IP {ip} is already blocked")
                return True
            
            # Block using iptables
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Add to custom linked list
                self.blocked_ips_list.append(ip)
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
        Get list of blocked IPs from custom linked list.
        
        Returns:
            list: List of blocked IP addresses
        """
        return self.blocked_ips_list.to_list()
    
    def is_blocked(self, ip):
        """
        Check if IP is blocked using custom linked list.
        
        Args:
            ip (str): IP address
        
        Returns:
            bool: True if blocked, False otherwise
        """
        return self.blocked_ips_list.search(ip)
    
    def unblock_ip(self, ip):
        """
        Unblock an IP address.
        Removes from custom linked list.
        
        Args:
            ip (str): IP address to unblock
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Remove from custom linked list
                self.blocked_ips_list.remove(ip)
                print(f"[SUCCESS] Unblocked IP: {ip}")
                return True
            else:
                print(f"[ERROR] Failed to unblock {ip}")
                return False
                
        except Exception as e:
            print(f"[ERROR] {e}")
            return False
    
    def get_blocked_count(self):
        """Get number of blocked IPs using custom linked list."""
        return len(self.blocked_ips_list)
    
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

# Test the blocker
if __name__ == "__main__":
    blocker = Blocker()
    
    print("Testing Blocker with Custom Linked List...")
    print(f"\nCurrent blocked IPs: {blocker.get_blocked_ips()}")
    print(f"Total blocked: {blocker.get_blocked_count()}")
    
    # Test search
    test_ip = '192.168.1.100'
    print(f"\nIs {test_ip} blocked? {blocker.is_blocked(test_ip)}")
    
    print("\n✓ Blocker with custom linked list working!")
