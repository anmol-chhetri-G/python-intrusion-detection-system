import re
import os
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

class LogParser:
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
        self.log_file = log_file
        self.lookback_minutes = lookback_minutes
        self.failed_attempts = defaultdict(int)

        # journalctl mode
        self.use_journalctl = False
        self.journal_unit = None
        self.journal_cursor = None  # key fix: prevents duplicates + missed events

        self._detect_logging_system()

    # -------------------------
    # Detection
    # -------------------------
    def _detect_logging_system(self):
        """Prefer journalctl if available and sshd unit exists; otherwise fallback to file."""
        if self._has_cmd('journalctl') and self._has_cmd('systemctl'):
            # You already proved sshd.service exists
            if self._unit_exists('sshd.service'):
                self.use_journalctl = True
                self.journal_unit = 'sshd'
                print("✓ Using journalctl for sshd logs")
                return

        # fallback
        if os.path.exists(self.log_file):
            self.use_journalctl = False
            print(f"✓ Using traditional log file: {self.log_file}")
        else:
            # last resort: try journalctl without unit filtering
            self.use_journalctl = True
            self.journal_unit = 'sshd'
            print("⚠️  auth.log not found; defaulting to journalctl (sshd)")

    def _has_cmd(self, cmd):
        try:
            subprocess.run([cmd, '--version'], capture_output=True, text=True, timeout=2)
            return True
        except Exception:
            return False

    def _unit_exists(self, unit_name):
        try:
            r = subprocess.run(
                ['systemctl', 'list-unit-files', unit_name],
                capture_output=True,
                text=True,
                timeout=3
            )
            return (r.returncode == 0) and (unit_name in r.stdout)
        except Exception:
            return False

    # -------------------------
    # Reading
    # -------------------------
    def _read_from_journalctl(self):
        """
        Incremental read using journal cursor.
        - First run: --since 'N minutes ago'
        - Next runs: --after-cursor <cursor>
        """
        base_cmd = ['journalctl', '--no-pager', '--show-cursor', '-u', self.journal_unit]

        if self.journal_cursor:
            cmd = base_cmd + ['--after-cursor', self.journal_cursor]
        else:
            # First run: look back a bit
            since = f"{self.lookback_minutes} min ago"
            cmd = base_cmd + ['--since', since]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)

            # If journalctl output is empty, surface stderr if any
            if result.returncode != 0:
                if result.stderr.strip():
                    print(f"⚠️  journalctl error: {result.stderr.strip()}")
                return []

            lines = result.stdout.splitlines()

            # Extract last cursor from output
            # journalctl prints cursor lines like: "-- cursor: s=...."
            last_cursor = None
            for line in reversed(lines):
                if line.startswith('-- cursor: '):
                    last_cursor = line.replace('-- cursor: ', '').strip()
                    break

            if last_cursor:
                self.journal_cursor = last_cursor

            # Remove cursor marker lines from parsing input
            cleaned = [ln for ln in lines if not ln.startswith('-- cursor: ')]
            return cleaned

        except subprocess.TimeoutExpired:
            print("⚠️  journalctl timeout")
            return []
        except Exception as e:
            print(f"⚠️  journalctl exception: {e}")
            return []

    def _read_from_file(self):
        try:
            with open(self.log_file, 'r') as f:
                return f.readlines()[-200:]
        except Exception:
            return []

    def read_new_entries(self):
        return self._read_from_journalctl() if self.use_journalctl else self._read_from_file()

    # -------------------------
    # Parsing
    # -------------------------
    def parse_lines(self, lines):
        new_attempts = defaultdict(int)

        for line in lines:
            for pattern_name, pattern in self.PATTERNS.items():
                match = pattern.search(line)
                if not match:
                    continue

                if pattern_name in ('failed_password', 'invalid_user'):
                    ip = match.group(2)
                else:
                    ip = match.group(1)

                new_attempts[ip] += 1
                self.failed_attempts[ip] += 1
                break

        return dict(new_attempts)

    def scan_once(self):
        return self.parse_lines(self.read_new_entries())

    def get_all_attempts(self):
        return dict(self.failed_attempts)

    def reset(self):
        self.failed_attempts.clear()


if __name__ == "__main__":
    parser = LogParser()

    print("\nTesting SSH Log Parser...")
    print(f"Log source: {'journalctl -u ' + parser.journal_unit if parser.use_journalctl else parser.log_file}")

    print("\nScan 1 (baseline)...")
    a1 = parser.scan_once()
    print("New attempts:", a1 if a1 else "None")

    print("\nNow generate failures (wrong password) and run again:")
    print("  ssh <user>@127.0.0.1  (enter wrong password a few times)\n")


