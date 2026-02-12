import re
import os
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

class LogParser:
    """
    Parses SSH authentication logs from either:
    - /var/log/auth.log (traditional syslog)
    - journalctl (systemd)
    
    Automatically detects which system is in use
    """
    
    # Regex patterns for SSH failures
    PATTERNS = {
        'failed_password': re.compile(
            r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'invalid_user': re.compile(
            r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
        ),
        'auth_failure': re.compile(
            r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'
        ),
        'connection_closed': re.compile(
            r'Connection closed by (?:authenticating user \S+ )?(\d+\.\d+\.\d+\.\d+).*\[preauth\]'
        )
    }
    
    def __init__(self, log_file='/var/log/auth.log', lookback_minutes=10):
        """
        Initialize log parser
        
        Args:
            log_file: Path to auth.log (fallback option)
            lookback_minutes: How many minutes back to check on startup
        """
        self.log_file = log_file
        self.lookback_minutes = lookback_minutes
        self.failed_attempts = defaultdict(int)
        self.use_journalctl = False
        self.last_timestamp = None
        
        # Detect logging system
        self._detect_logging_system()
    
    def _detect_logging_system(self):
        """Detect whether to use journalctl or auth.log"""
        # Check if journalctl is available and SSH service exists
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'sshd'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                self.use_journalctl = True
                print(f"✓ Using journalctl for SSH logs")
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Try alternative SSH service names
        for service in ['ssh', 'openssh']:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    self.use_journalctl = True
                    self.ssh_service = service
                    print(f"✓ Using journalctl for {service} logs")
                    return
            except:
                continue
        
        # Fall back to auth.log
        if os.path.exists(self.log_file):
            print(f"✓ Using traditional log file: {self.log_file}")
            self.use_journalctl = False
        else:
            print(f"⚠️  No SSH logs found. Defaulting to journalctl.")
            self.use_journalctl = True
    
    def _read_from_journalctl(self):
        """
        Read SSH logs from journalctl
        
        Returns:
            list: Log lines
        """
        try:
            # Calculate time range
            if self.last_timestamp:
                # Get logs since last check
                since_str = self.last_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                # Initial read - get last N minutes
                since_time = datetime.now() - timedelta(minutes=self.lookback_minutes)
                since_str = since_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Update timestamp for next read
            self.last_timestamp = datetime.now()
            
            # Query journalctl for SSH logs
            # Try different service names
            for service in ['sshd', 'ssh', 'openssh']:
                cmd = [
                    'journalctl',
                    '-u', service,
                    '--since', since_str,
                    '--no-pager'
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.splitlines()
            
            return []
        
        except subprocess.TimeoutExpired:
            print("⚠️  journalctl timeout")
            return []
        except Exception as e:
            print(f"⚠️  journalctl error: {e}")
            return []
    
    def _read_from_file(self):
        """
        Read from traditional auth.log file
        
        Returns:
            list: New log lines
        """
        try:
            with open(self.log_file, 'r') as f:
                # Read last 200 lines
                lines = f.readlines()
                return lines[-200:]
        except PermissionError:
            # Try with sudo
            try:
                result = subprocess.run(
                    ['sudo', 'tail', '-n', '200', self.log_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.stdout.splitlines()
            except:
                return []
        except FileNotFoundError:
            return []
    
    def read_new_entries(self):
        """
        Read new log entries from appropriate source
        
        Returns:
            list: New log lines
        """
        if self.use_journalctl:
            return self._read_from_journalctl()
        else:
            return self._read_from_file()
    
    def parse_lines(self, lines):
        """
        Parse log lines and extract failed login attempts
        
        Args:
            lines: List of log lines
        
        Returns:
            dict: {ip_address: new_attempt_count}
        """
        new_attempts = defaultdict(int)
        
        for line in lines:
            # Try each pattern
            for pattern_name, pattern in self.PATTERNS.items():
                match = pattern.search(line)
                if match:
                    # Extract IP based on pattern
                    if pattern_name == 'failed_password':
                        ip = match.group(2)
                    elif pattern_name == 'invalid_user':
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
            dict: New failed attempts {ip: count}
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
    
    print("\nTesting SSH Log Parser...")
    print(f"Log source: {'journalctl' if parser.use_journalctl else parser.log_file}")
    print("\nScanning for failed SSH attempts...\n")
    
    # Scan once
    new_attempts = parser.scan_once()
    
    if new_attempts:
        print(f"✓ Found {len(new_attempts)} IP(s) with NEW failed attempts:")
        for ip, count in new_attempts.items():
            print(f"  {ip}: {count} new attempt(s)")
    else:
        print("No NEW failed SSH attempts found")
    
    # Show cumulative
    all_attempts = parser.get_all_attempts()
    if all_attempts:
        print(f"\nCumulative totals:")
        for ip, count in sorted(all_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip}: {count} total attempts")
    
    print("\n✓ Parser test complete!")
