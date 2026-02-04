#!/usr/bin/env python3
"""
Python Intrusion Detection System (IDS)
Main entry point for the application.

Author: Anmol Chhetri
Course: ST5062CEM - Programming and Algorithm 2
"""

import sys
import time
import signal
from log_parser import LogParser
from detector import Detector
from database import Database
from file_logger import FileLogger
from blocker import Blocker

class IDS:
    """
    Main IDS controller class.
    Coordinates all components for threat detection and response.
    """
    
    def __init__(self, threshold=5, interval=10):
        """
        Initialize IDS with all components.
        
        Args:
            threshold (int): Failed login threshold for detection
            interval (int): Log monitoring interval in seconds
        """
        print("=" * 60)
        print("  PYTHON INTRUSION DETECTION SYSTEM")
        print("  Initializing components...")
        print("=" * 60)
        
        # Initialize components
        self.parser = LogParser(interval=interval)
        self.detector = Detector(threshold=threshold)
        self.db = Database()
        self.logger = FileLogger()
        self.blocker = Blocker()
        
        # Configuration
        self.threshold = threshold
        self.interval = interval
        self.running = False
        
        # Log system start
        self.logger.log_system("IDS initialized")
        self.logger.log_system(f"Threshold: {threshold} failed attempts")
        self.logger.log_system(f"Monitoring interval: {interval} seconds")
        
        print("\n✓ All components initialized successfully!")
    
    def start(self):
        """Start the IDS monitoring process."""
        self.running = True
        self.logger.log_system("IDS monitoring started")
        
        print("\n🛡️  IDS is now monitoring for threats...")
        print(f"   Checking logs every {self.interval} seconds")
        print("   Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                self.scan_and_respond()
                time.sleep(self.interval)
        
        except KeyboardInterrupt:
            self.stop()
    
    def scan_and_respond(self):
        """Perform one scan cycle: parse logs, detect threats, respond."""
        
        # Get failed login attempts from log parser
        failed_attempts = self.parser.attempts.copy()
        
        if not failed_attempts:
            print(f"[{time.strftime('%H:%M:%S')}] No suspicious activity detected")
            return
        
        # Detect threats
        threats = self.detector.detect_threats(failed_attempts)
        
        if threats:
            print(f"\n⚠️  ALERT: {len(threats)} threat(s) detected!")
            
            for threat in threats:
                ip = threat['ip']
                attempts = threat['attempts']
                level = threat['threat_level']
                
                print(f"\n   🚨 Threat Details:")
                print(f"      IP Address: {ip}")
                print(f"      Failed Attempts: {attempts}")
                print(f"      Threat Level: {level}")
                
                # Log threat
                self.logger.log_threat(ip, attempts, level)
                
                # Save to database
                threat_id = self.db.save_threat(ip, attempts, level)
                print(f"      Database ID: {threat_id}")
                
                # Block if HIGH or CRITICAL
                if level in ['HIGH', 'CRITICAL']:
                    print(f"      🔒 Blocking IP {ip}...")
                    
                    if self.blocker.block_ip(ip):
                        self.db.mark_as_blocked(ip)
                        self.db.save_blocked_ip(ip, f"{level} threat - {attempts} attempts")
                        self.logger.log_block(ip, f"{level} threat level")
                        print(f"      ✓ IP {ip} has been blocked")
                    else:
                        print(f"      ✗ Failed to block IP {ip}")
                        self.logger.log_error(f"Failed to block IP {ip}")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Activity detected but below threshold")
    
    def stop(self):
        """Stop the IDS."""
        print("\n\n🛑 Stopping IDS...")
        self.running = False
        self.logger.log_system("IDS stopped by user")
        
        # Show summary
        summary = self.detector.get_threat_summary()
        stats = self.db.get_statistics()
        
        print("\n" + "=" * 60)
        print("  SESSION SUMMARY")
        print("=" * 60)
        print(f"  Total Threats Detected: {summary['total']}")
        print(f"  Total IPs Blocked: {stats['total_blocked']}")
        print(f"  Threats by Level: {dict(summary['by_level'])}")
        print("=" * 60)
        print("\n✓ IDS stopped successfully. Goodbye!\n")

def main():
    """Main entry point."""
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--gui':
            # Launch GUI mode
            print("Launching GUI mode...")
            from gui import run_gui
            run_gui()
            return
        
        elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("""
Python Intrusion Detection System (IDS)

Usage:
    python3 main.py              # Run in CLI mode
    python3 main.py --gui        # Run in GUI mode
    python3 main.py --help       # Show this help

Options:
    --gui       Launch graphical user interface
    --help      Display this help message

Examples:
    python3 main.py
    python3 main.py --gui
            """)
            return
    
    # CLI mode (default)
    try:
        # Create IDS instance
        ids = IDS(threshold=5, interval=10)
        
        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            ids.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start monitoring
        ids.start()
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
