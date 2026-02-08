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
import random
from log_parser import LogParser
from detector import Detector
from http_detector import HTTPDetector
from database import Database
from file_logger import FileLogger
from blocker import Blocker

class IDS:
    """
    Main IDS controller class.
    Coordinates all components for threat detection and response.
    Supports both SSH and HTTP attack detection.
    """
    
    def __init__(self, threshold=5, interval=10, enable_http=True, demo_mode=True):
        """
        Initialize IDS with all components.
        
        Args:
            threshold (int): Failed login threshold for detection
            interval (int): Log monitoring interval in seconds
            enable_http (bool): Enable HTTP attack detection
            demo_mode (bool): Use demo data for demonstration
        """
        print("=" * 60)
        print("  PYTHON INTRUSION DETECTION SYSTEM")
        print("  Multi-Attack Detection Engine")
        print("=" * 60)
        print("\n  Initializing components...")
        
        # Initialize components
        self.parser = LogParser(interval=interval)
        self.detector = Detector(threshold=threshold)
        self.http_detector = HTTPDetector() if enable_http else None
        self.db = Database()
        self.logger = FileLogger()
        self.blocker = Blocker()
        
        # Configuration
        self.threshold = threshold
        self.interval = interval
        self.enable_http = enable_http
        self.demo_mode = demo_mode
        self.running = False
        self.scan_count = 0
        
        # Log system start
        self.logger.log_system("IDS initialized")
        self.logger.log_system(f"SSH Detection: Enabled (threshold: {threshold})")
        if enable_http:
            self.logger.log_system("HTTP Attack Detection: Enabled")
        if demo_mode:
            self.logger.log_system("Demo Mode: Enabled (using simulated attacks)")
        self.logger.log_system(f"Monitoring interval: {interval} seconds")
        
        print("\n✓ All components initialized successfully!")
        print(f"✓ SSH Brute Force Detection: Active")
        if enable_http:
            print(f"✓ HTTP Attack Detection: Active")
        if demo_mode:
            print(f"✓ Demo Mode: Active (simulated attacks)")
    
    def start(self):
        """Start the IDS monitoring process."""
        self.running = True
        self.logger.log_system("IDS monitoring started")
        
        print("\n🛡️  IDS is now monitoring for threats...")
        print(f"   Attack Types: SSH Brute Force" + (" + HTTP Attacks" if self.enable_http else ""))
        print(f"   Checking logs every {self.interval} seconds")
        print("   Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                self.scan_and_respond()
                self.scan_count += 1
                time.sleep(self.interval)
        
        except KeyboardInterrupt:
            self.stop()
    
    def scan_and_respond(self):
        """Perform one scan cycle: parse logs, detect threats, respond."""
        
        # SSH Attack Detection
        self._scan_ssh_attacks()
        
        # HTTP Attack Detection (if enabled)
        if self.enable_http:
            self._scan_http_attacks()
    
    def _scan_ssh_attacks(self):
        """Scan for SSH brute force attacks."""
        
        if self.demo_mode:
            # Demo mode: Simulate SSH attacks periodically
            # Show attack every 2-3 scans
            if self.scan_count % 3 == 0:
                # Generate demo SSH attack
                demo_ips = [
                    ('203.0.113.50', random.randint(6, 12)),
                    ('45.76.123.45', random.randint(8, 15)),
                    ('198.51.100.100', random.randint(3, 7)),
                ]
                
                failed_attempts = dict(demo_ips)
                print(f"[{time.strftime('%H:%M:%S')}] SSH: Detected brute force from {len(failed_attempts)} IP(s)")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] SSH: No suspicious activity")
                return
        else:
            # Real mode: Try to read actual logs
            self.parser.scan_once()
            failed_attempts = self.parser.attempts.copy()
            
            if not failed_attempts:
                print(f"[{time.strftime('%H:%M:%S')}] SSH: No suspicious activity")
                return
            
            print(f"[{time.strftime('%H:%M:%S')}] SSH: Found activity from {len(failed_attempts)} IP(s)")
        
        # Detect threats
        threats = self.detector.detect_threats(failed_attempts)
        
        if threats:
            print(f"\n⚠️  SSH ATTACK DETECTED: {len(threats)} threat(s)!")
            
            for threat in threats:
                ip = threat['ip']
                attempts = threat['attempts']
                level = threat['threat_level']
                
                print(f"\n   🚨 SSH Brute Force Attack:")
                print(f"      IP Address: {ip}")
                print(f"      Failed Attempts: {attempts}")
                print(f"      Threat Level: {level}")
                
                self.logger.log_threat(ip, attempts, level)
                threat_id = self.db.save_threat(ip, attempts, level, notes="SSH brute force")
                print(f"      Database ID: {threat_id}")
                
                if level in ['HIGH', 'CRITICAL']:
                    self._block_ip(ip, f"SSH {level} threat - {attempts} attempts")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] SSH: Activity below threshold")
    
    def _scan_http_attacks(self):
        """Scan for HTTP-based attacks."""
        # Simulate HTTP request monitoring
        sample_requests = [
            ("192.168.1.200", "GET /index.php?id=1' OR '1'='1"),
            ("192.168.1.201", "GET /search?q=<script>alert('XSS')</script>"),
        ]
        
        for ip, request in sample_requests:
            attack = self.http_detector.analyze_request(ip, request)
            
            if attack:
                print(f"\n⚠️  HTTP ATTACK DETECTED!")
                print(f"      IP Address: {attack['ip']}")
                print(f"      Attack Types: {', '.join(attack['attack_types'])}")
                print(f"      Threat Level: {attack['threat_level']}")
                print(f"      Request: {attack['request'][:60]}...")
                
                self.logger.log_event('HTTP_ATTACK', 
                    f"HTTP attack from {ip}: {', '.join(attack['attack_types'])}")
                
                threat_id = self.db.save_threat(
                    ip, 
                    len(attack['attack_types']), 
                    attack['threat_level'],
                    notes=f"HTTP: {', '.join(attack['attack_types'])}"
                )
                
                if attack['threat_level'] in ['HIGH', 'CRITICAL']:
                    self._block_ip(ip, f"HTTP attack - {', '.join(attack['attack_types'])}")
    
    def _block_ip(self, ip, reason):
        """Block an IP address."""
        print(f"      🔒 Blocking IP {ip}...")
        
        if self.blocker.block_ip(ip):
            self.db.mark_as_blocked(ip)
            self.db.save_blocked_ip(ip, reason)
            self.logger.log_block(ip, reason)
            print(f"      ✓ IP {ip} has been blocked")
        else:
            print(f"      ✗ Failed to block IP {ip}")
            self.logger.log_error(f"Failed to block IP {ip}")
    
    def stop(self):
        """Stop the IDS."""
        print("\n\n🛑 Stopping IDS...")
        self.running = False
        self.logger.log_system("IDS stopped by user")
        
        # Show summary
        ssh_summary = self.detector.get_threat_summary()
        http_summary = self.http_detector.get_attack_summary() if self.enable_http else None
        stats = self.db.get_statistics()
        
        print("\n" + "=" * 60)
        print("  SESSION SUMMARY")
        print("=" * 60)
        print(f"  SSH Threats Detected: {ssh_summary['total']}")
        if http_summary:
            print(f"  HTTP Attacks Detected: {http_summary['total_attacks']}")
        print(f"  Total IPs Blocked: {stats['total_blocked']}")
        print(f"  Threats by Level: {dict(ssh_summary['by_level'])}")
        print("=" * 60)
        print("\n✓ IDS stopped successfully. Goodbye!\n")

def main():
    """Main entry point."""
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--gui':
            print("Launching GUI mode...")
            from gui import run_gui
            run_gui()
            return
        
        elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("""
Python Intrusion Detection System (IDS)

Detects and blocks:
  • SSH Brute Force Attacks
  • HTTP Injection Attacks (SQL, XSS, Command Injection, Path Traversal)

Usage:
    python3 main.py              # Run in CLI mode (demo mode)
    python3 main.py --gui        # Run in GUI mode
    python3 main.py --real       # Real mode (read actual logs)
    python3 main.py --ssh-only   # SSH detection only
    python3 main.py --help       # Show this help

Examples:
    python3 main.py
    python3 main.py --gui
    python3 main.py --real
            """)
            return
        
        elif sys.argv[1] == '--ssh-only':
            ids = IDS(threshold=5, interval=10, enable_http=False, demo_mode=True)
            
            def signal_handler(sig, frame):
                ids.stop()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            ids.start()
            return
        
        elif sys.argv[1] == '--real':
            # Real mode - attempt to read actual logs
            ids = IDS(threshold=5, interval=10, enable_http=True, demo_mode=False)
            
            def signal_handler(sig, frame):
                ids.stop()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            ids.start()
            return
    
    # Default: CLI mode with demo data
    try:
        ids = IDS(threshold=5, interval=10, enable_http=True, demo_mode=True)
        
        def signal_handler(sig, frame):
            ids.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        ids.start()
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
