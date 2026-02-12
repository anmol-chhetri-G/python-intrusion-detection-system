import subprocess
import os
from datetime import datetime
from custom_structures import CustomLinkedList

class Blocker:
    """
    Handles IP blocking/unblocking using iptables.
    Uses custom linked list for maintaining blocked IPs.
    """
    
    def __init__(self, blocked_ips_file='data/blocked_ips.txt'):
        self.blocked_ips_file = blocked_ips_file
        self.blocked_ips_list = CustomLinkedList()
        
        os.makedirs(os.path.dirname(blocked_ips_file), exist_ok=True)
        
        if not os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, 'w') as f:
                f.write(f"# Blocked IPs - Started {datetime.now()}\n")
        
        # Load existing blocked IPs
        self._load_blocked_ips()
    
    def _load_blocked_ips(self):
        """Load existing blocked IPs into custom linked list"""
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
        
        Args:
            ip (str): IP address to block
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if already blocked
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
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return False
    
    def unblock_ip(self, ip):
        """
        Unblock an IP address.
        
        Args:
            ip (str): IP address to unblock
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if IP is actually blocked
            if not self.blocked_ips_list.search(ip):
                print(f"[INFO] IP {ip} is not in blocked list")
                return False
            
            # Remove from iptables
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Remove from custom linked list
                self.blocked_ips_list.remove(ip)
                # Remove from file
                self._remove_from_file(ip)
                print(f"[SUCCESS] Unblocked IP: {ip}")
                return True
            else:
                print(f"[ERROR] Failed to unblock {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[ERROR] {e}")
            return False
    
    def unblock_all(self):
        """
        Unblock ALL blocked IPs.
        
        Returns:
            int: Number of IPs unblocked
        """
        blocked_ips = self.get_blocked_ips()
        count = 0
        
        print(f"Unblocking {len(blocked_ips)} IP(s)...")
        
        for ip in blocked_ips:
            if self.unblock_ip(ip):
                count += 1
        
        print(f"✓ Unblocked {count} IP(s)")
        return count
    
    def flush_iptables(self):
        """
        Flush all iptables INPUT rules (DANGEROUS - use carefully!)
        
        Returns:
            bool: True if successful
        """
        try:
            cmd = ['sudo', 'iptables', '-F', 'INPUT']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Clear our tracking
                self.blocked_ips_list = CustomLinkedList()
                # Clear file
                with open(self.blocked_ips_file, 'w') as f:
                    f.write(f"# Blocked IPs - Flushed {datetime.now()}\n")
                
                print("[SUCCESS] Flushed all iptables INPUT rules")
                return True
            else:
                print(f"[ERROR] Failed to flush: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ERROR] {e}")
            return False
    
    def _save_to_file(self, ip):
        """Save blocked IP to persistent file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.blocked_ips_file, 'a') as f:
            f.write(f"{ip} | {timestamp}\n")
    
    def _remove_from_file(self, ip):
        """Remove IP from blocked IPs file"""
        try:
            with open(self.blocked_ips_file, 'r') as f:
                lines = f.readlines()
            
            with open(self.blocked_ips_file, 'w') as f:
                for line in lines:
                    if not line.strip().startswith(ip):
                        f.write(line)
        except Exception as e:
            print(f"[ERROR] Failed to update file: {e}")
    
    def get_blocked_ips(self):
        """Get list of blocked IPs from custom linked list"""
        return self.blocked_ips_list.to_list()
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return self.blocked_ips_list.search(ip)
    
    def get_blocked_count(self):
        """Get number of blocked IPs"""
        return len(self.blocked_ips_list)
    
    def list_iptables_rules(self):
        """
        List current iptables INPUT rules.
        
        Returns:
            str: iptables rules output
        """
        try:
            result = subprocess.run(
                ['sudo', 'iptables', '-L', 'INPUT', '-v', '-n', '--line-numbers'],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"


if __name__ == "__main__":
    import sys
    
    blocker = Blocker()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'list':
            # List blocked IPs
            blocked = blocker.get_blocked_ips()
            print(f"\nBlocked IPs ({len(blocked)}):")
            for ip in blocked:
                print(f"  • {ip}")
            
            print("\nIPTables Rules:")
            print(blocker.list_iptables_rules())
        
        elif command == 'unblock' and len(sys.argv) > 2:
            # Unblock specific IP
            ip = sys.argv[2]
            blocker.unblock_ip(ip)
        
        elif command == 'unblock-all':
            # Unblock all IPs
            blocker.unblock_all()
        
        elif command == 'flush':
            # Flush all iptables
            confirm = input("⚠️  This will flush ALL iptables INPUT rules. Continue? (yes/no): ")
            if confirm.lower() == 'yes':
                blocker.flush_iptables()
        
        else:
            print("""
Usage:
    python3 blocker.py list              # List blocked IPs
    python3 blocker.py unblock <IP>      # Unblock specific IP
    python3 blocker.py unblock-all       # Unblock all IPs
    python3 blocker.py flush             # Flush all iptables rules
            """)
    else:
        print("Testing Blocker with Custom Linked List...")
        print(f"\nCurrent blocked IPs: {blocker.get_blocked_ips()}")
        print(f"Total blocked: {blocker.get_blocked_count()}")
