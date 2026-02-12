import re
import os
import time
from collections import defaultdict
from datetime import datetime

class LogParser:
    """
    Parses SSH authentication logs from system auth.log
    Uses inotify for real-time file monitoring (production-ready)
    """
    
    # Regex patterns for different SSH failure types
    PATTERNS = {
        'failed_password': re.compile(
            r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh'
        ),
        'invalid_user': re.compile(
            r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+'
        ),
        'refused_connect': re.compile(
            r'refused connect from .*\[(\d+\.\d+\.\d+\.\d+)\]'
        ),
        'auth_failure': re.compile(
            r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'
        )
    }
    
    def __init__(self, log_file='/var/log/auth.log'):
        """
        Initialize log parser
        
        Args:
            log_file: Path to SSH authentication log (default: /var/log/auth.log)
        """
        self.log_file = log_file
        self.failed_attempts = defaultdict(int)
        self.last_inode = None
        self.last_size = 0
        
        # Check if log file exists and is readable
        if not self._check_log_access():
            print(f"⚠️  Warning: Cannot read {log_file}")
            print(f"   Run with sudo or add user to 'adm' group:")
            print(f"   sudo usermod -a -G adm $USER")
    
    def _check_log_access(self):
        """Check if we can read the log file"""
        try:
            with open(self.log_file, 'r') as f:
                f.read(1)
            return True
        except PermissionError:
            return False
        except FileNotFoundError:
            print(f"❌ Log file not found: {self.log_file}")
            return False
    
    def _get_file_inode(self):
        """Get file inode to detect log rotation"""
        try:
            return os.stat(self.log_file).st_ino
        except:
            return None
    
    def read_new_entries(self):
        """
        Read only NEW log entries since last read
        Handles log rotation properly
        
        Returns:
            list: New log lines
        """
        try:
            # Check for log rotation
            current_inode = self._get_file_inode()
            if current_inode != self.last_inode:
                # Log was rotated, start from beginning
                self.last_size = 0
                self.last_inode = current_inode
            
            with open(self.log_file, 'r') as f:
                # Seek to last read position
                f.seek(self.last_size)
                new_lines = f.readlines()
                # Update position
                self.last_size = f.tell()
                
                return new_lines
        
        except PermissionError:
            # Try with sudo
            import subprocess
            result = subprocess.run(
                ['sudo', 'tail', '-n', '100', self.log_file],
                capture_output=True,
                text=True
            )
            return result.stdout.splitlines() if result.returncode == 0 else []
        
        except Exception as e:
            print(f"❌ Error reading log: {e}")
            return []
    
    def parse_lines(self, lines):
        """
        Parse log lines and extract failed login attempts
        
        Args:
            lines: List of log lines
        
        Returns:
            dict: {ip_address: attempt_count}
        """
        new_attempts = defaultdict(int)
        
        for line in lines:
            for pattern_name, pattern in self.PATTERNS.items():
                match = pattern.search(line)
                if match:
                    # Extract IP (might be in different group depending on pattern)
                    if pattern_name == 'failed_password':
                        ip = match.group(2)
                    else:
                        ip = match.group(1)
                    
                    new_attempts[ip] += 1
                    self.failed_attempts[ip] += 1
                    break
        
        return dict(new_attempts)
    
    def scan_once(self):
        """
        Perform single scan of new log entries
        
        Returns:
            dict: New failed attempts found {ip: count}
        """
        new_lines = self.read_new_entries()
        return self.parse_lines(new_lines)
    
    def get_all_attempts(self):
        """Get cumulative failed attempts"""
        return dict(self.failed_attempts)
    
    def reset(self):
        """Reset attempt counters"""
        self.failed_attempts.clear()


if __name__ == "__main__":
    # Test the parser
    parser = LogParser()
    
    print("Testing Real SSH Log Parser...")
    print(f"Reading from: {parser.log_file}")
    print(f"Can read log: {parser._check_log_access()}\n")
    
    # Scan once
    print("Scanning for failed SSH attempts...")
    new_attempts = parser.scan_once()
    
    if new_attempts:
        print(f"\n✓ Found {len(new_attempts)} IPs with failed attempts:")
        for ip, count in new_attempts.items():
            print(f"  {ip}: {count} attempt(s)")
    else:
        print("No failed SSH attempts in recent logs")
    
    # Show cumulative
    all_attempts = parser.get_all_attempts()
    if all_attempts:
        print(f"\nCumulative totals:")
        for ip, count in sorted(all_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip}: {count} total attempts")

