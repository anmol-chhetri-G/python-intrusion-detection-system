import re
import time
import threading
import subprocess
from collections import defaultdict

class LogParser:
    """
    Monitors SSH authentication logs and extracts failed login attempts.
    """
    FAILED_SSH_PATTERN = re.compile(
        r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )
    
    def __init__(self, interval=5, log_path="/var/log/auth.log"):
        self.interval = interval
        self.log_path = log_path
        self.attempts = defaultdict(int)
        self._running = False
        self._last_position = 0  # Track file position
    
    def _read_logs(self):
        """
        Reads recent SSH authentication log entries.
        Properly tracks file position to avoid re-reading.
        """
        try:
            with open(self.log_path, 'r') as f:
                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = f.tell()
                return new_lines
        except (FileNotFoundError, PermissionError):
            try:
                result = subprocess.run(
                    ['sudo', 'tail', '-n', '100', self.log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.stdout.splitlines()
            except (subprocess.TimeoutExpired, Exception):
                return []
    
    def _parse_logs(self, lines):
        """
        Parses log lines and updates failed attempt counts.
        """
        for line in lines:
            match = self.FAILED_SSH_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                self.attempts[ip] += 1
    
    def scan_once(self):
        """
        Perform a single scan of the logs.
        Useful for testing and one-time checks.
        """
        lines = self._read_logs()
        self._parse_logs(lines)
        return dict(self.attempts)
    
    def run(self):
        """
        Starts continuous log monitoring.
        """
        self._running = True
        while self._running:
            lines = self._read_logs()
            self._parse_logs(lines)
            time.sleep(self.interval)
    
    def stop(self):
        """
        Stops log monitoring.
        """
        self._running = False


# Test the log parser
if __name__ == "__main__":
    parser = LogParser(interval=2)
    
    print("Testing Log Parser...")
    print("Reading SSH auth logs...\n")
    
    # Do a single scan
    attempts = parser.scan_once()
    
    if attempts:
        print(f"Found {len(attempts)} IPs with failed login attempts:")
        for ip, count in attempts.items():
            print(f"  {ip}: {count} attempts")
    else:
        print("No failed login attempts found in logs")
    
    print("\nLog parser test complete!")
