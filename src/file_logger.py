from datetime import datetime
import os

class FileLogger:
    """
    Handles file-based logging for IDS events and activities.
    """
    
    def __init__(self, log_file='logs/ids_activity.log'):
        """
        Initialize file logger.
        
        Args:
            log_file (str): Path to log file
        """
        self.log_file = log_file
        
        # Ensure logs directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Create log file if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write(f"=== IDS Log Started at {datetime.now()} ===\n")
    
    def _write_log(self, log_entry):
        """
        Write log entry to file.
        
        Args:
            log_entry (str): Formatted log entry
        """
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def log_event(self, event_type, message):
        """
        Log a general event.
        
        Args:
            event_type (str): Type of event (SYSTEM, THREAT, BLOCK, ERROR)
            message (str): Event description
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{event_type:10}] {message}"
        self._write_log(log_entry)
        print(log_entry)  # Also print to console
    
    def log_threat(self, ip, attempts, threat_level):
        """
        Log detected threat.
        
        Args:
            ip (str): IP address
            attempts (int): Number of failed attempts
            threat_level (str): Threat severity
        """
        message = f"Malicious IP detected: {ip} ({attempts} attempts, {threat_level} threat level)"
        self.log_event('THREAT', message)
    
    def log_block(self, ip, reason="Exceeded threshold"):
        """
        Log IP block action.
        
        Args:
            ip (str): IP address
            reason (str): Reason for blocking
        """
        message = f"IP blocked: {ip} - Reason: {reason}"
        self.log_event('BLOCK', message)
    
    def log_system(self, message):
        """
        Log system event.
        
        Args:
            message (str): System message
        """
        self.log_event('SYSTEM', message)
    
    def log_error(self, message):
        """
        Log error event.
        
        Args:
            message (str): Error message
        """
        self.log_event('ERROR', message)
    
    def get_recent_logs(self, lines=50):
        """
        Get recent log entries.
        
        Args:
            lines (int): Number of recent lines to retrieve
        
        Returns:
            list: List of log lines
        """
        try:
            with open(self.log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except FileNotFoundError:
            return []

# Test the logger
if __name__ == "__main__":
    logger = FileLogger()
    
    print("Testing FileLogger...")
    
    logger.log_system("IDS started")
    logger.log_threat('192.168.1.100', 7, 'MEDIUM')
    logger.log_block('192.168.1.100', 'Brute force attempt')
    logger.log_error('Test error message')
    
    print("\nRecent logs:")
    recent = logger.get_recent_logs(5)
    for line in recent:
        print(line.strip())
