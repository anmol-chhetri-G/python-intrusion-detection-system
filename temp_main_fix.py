def _scan_ssh_attacks(self):
    """Scan for SSH brute force attacks."""
    # Actually scan the logs (was missing this!)
    self.parser.scan_once()
    failed_attempts = self.parser.attempts.copy()
    
    if not failed_attempts:
        print(f"[{time.strftime('%H:%M:%S')}] SSH: No suspicious activity")
        return
    
    # Clear old attempts to avoid duplicates
    if failed_attempts:
        print(f"[{time.strftime('%H:%M:%S')}] SSH: Found activity from {len(failed_attempts)} IPs")
    
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
