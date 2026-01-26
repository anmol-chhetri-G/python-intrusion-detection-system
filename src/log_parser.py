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

    def __init__(self, interval=5):
        self.interval = interval
        self.attempts = defaultdict(int)
        self._running = False

    def _read_logs(self):
        """
        Reads recent SSH authentication log entries.
        """
        try:
            output = subprocess.getoutput(
                "tail -n 20 /var/log/auth.log"
            )
            return output.splitlines()
        except Exception:
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

