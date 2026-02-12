import sys
import time
import signal
from log_parser import LogParser
from detector import Detector
from database import Database
from file_logger import FileLogger
from blocker import Blocker

class IDS:
    """Real-world IDS - Reads actual system logs"""
    
    def __init__(self, threshold=5, scan_interval=30):
        print("=" * 70)
        print("  PRODUCTION INTRUSION DETECTION SYSTEM")
        print("  Real SSH Brute Force Detection")
        print("=" * 70)
        
        # Initialize components
        self.parser = LogParser()
        self.detector = Detector(threshold=threshold)
        self.db = Database()
        self.logger = FileLogger()
        self.blocker = Blocker()
        
        self.threshold = threshold
        self.scan_interval = scan_interval
        self.running = False
        
        # Log startup
        self.logger.log_system(f"IDS started (threshold: {threshold})")
        
        # Show what we're monitoring
        log_source = 'journalctl' if self.parser.use_journalctl else self.parser.log_file
        print(f"\n✓ Monitoring: {log_source}")
        print(f"✓ Threshold: {threshold} failed attempts")
        print(f"✓ Scan interval: {scan_interval} seconds\n")
    
    def start(self):
        """Start monitoring"""
        self.running = True
        print("🛡️  IDS is monitoring... (Press Ctrl+C to stop)\n")
        
        try:
            while self.running:
                self._scan_cycle()
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            self.stop()
    
    def _scan_cycle(self):
        """Single scan cycle"""
        timestamp = time.strftime('%H:%M:%S')
        
        # Read NEW log entries
        new_attempts = self.parser.scan_once()
        
        if not new_attempts:
            print(f"[{timestamp}] No new failed attempts")
            return
        
        print(f"[{timestamp}] ⚠️  Found failed attempts from {len(new_attempts)} IP(s)")
        for ip, count in new_attempts.items():
            print(f"           {ip}: {count} new attempts")
        
        # Get cumulative attempts for detection
        all_attempts = self.parser.get_all_attempts()
        
        # Detect threats
        threats = self.detector.detect_threats(all_attempts)
        
        if threats:
            self._handle_threats(threats)
    
    def _handle_threats(self, threats):
        """Handle detected threats"""
        print(f"\n{'='*70}")
        print(f"  🚨 THREAT ALERT: {len(threats)} MALICIOUS IP(S) DETECTED!")
        print(f"{'='*70}\n")
        
        for threat in threats:
            ip = threat['ip']
            attempts = threat['attempts']
            level = threat['threat_level']
            
            print(f"IP Address: {ip}")
            print(f"  ├─ Total Attempts: {attempts}")
            print(f"  ├─ Threat Level: {level}")
            
            # Save to database
            self.db.save_threat(ip, attempts, level)
            self.logger.log_threat(ip, attempts, level)
            
            # Block if HIGH or CRITICAL
            if level in ['HIGH', 'CRITICAL']:
                print(f"  └─ 🔒 ACTION: BLOCKING IP...")
                if self.blocker.block_ip(ip):
                    self.db.mark_as_blocked(ip)
                    self.db.save_blocked_ip(ip, f"{level} threat")
                    print(f"     ✓ Successfully blocked {ip}")
                else:
                    print(f"     ✗ Block failed (run with sudo for blocking)")
            else:
                print(f"  └─ ⚠️  Below blocking threshold")
            
            print()
    
    def stop(self):
        """Stop IDS"""
        print("\n\n🛑 Stopping IDS...")
        self.running = False
        
        summary = self.detector.get_threat_summary()
        stats = self.db.get_statistics()
        
        print("\n" + "=" * 70)
        print("  SESSION SUMMARY")
        print("=" * 70)
        print(f"  Threats Detected: {summary['total']}")
        print(f"  IPs Blocked: {stats['total_blocked']}")
        print(f"  By Level: {dict(summary['by_level'])}")
        print("=" * 70 + "\n")

def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print("""
Real-World Intrusion Detection System

Usage:
    sudo python3 main.py              # Run with blocking (recommended)
    python3 main.py                   # Run without blocking (monitor only)
    python3 main.py --gui             # GUI mode
    python3 main.py --threshold 10    # Custom threshold
    python3 main.py --interval 15     # Custom scan interval

Options:
    --threshold N    Set detection threshold (default: 5)
    --interval N     Set scan interval in seconds (default: 30)
    --gui            Launch GUI mode

Examples:
    sudo python3 main.py --threshold 3 --interval 10
    python3 main.py --gui
        """)
        return
    
    # Parse arguments
    threshold = 5
    interval = 30
    
    for i, arg in enumerate(sys.argv):
        if arg == '--threshold' and i + 1 < len(sys.argv):
            threshold = int(sys.argv[i + 1])
        elif arg == '--interval' and i + 1 < len(sys.argv):
            interval = int(sys.argv[i + 1])
        elif arg == '--gui':
            from gui import run_gui
            run_gui()
            return
    
    # Start IDS
    ids = IDS(threshold=threshold, scan_interval=interval)
    
    def signal_handler(sig, frame):
        ids.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    ids.start()

if __name__ == "__main__":
    main()
