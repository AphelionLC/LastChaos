import os
import time
from config import (
    SECURITY_DIR,
    BLOCKED_IP_LOG,
    ATTEMPTED_CONNECTIONS_LOG,
    DDOS_MONITOR_LOG,
    ERROR_LOG,
    LEVEL_CHANGE_LOG,
    Colors
)

def ensure_log_directory():
    """Ensure the log directory exists."""
    if not os.path.exists(SECURITY_DIR):
        os.makedirs(SECURITY_DIR)

def ensure_log_files():
    """Ensure all log files exist."""
    log_files = [BLOCKED_IP_LOG, ATTEMPTED_CONNECTIONS_LOG, DDOS_MONITOR_LOG, ERROR_LOG, LEVEL_CHANGE_LOG]
    for log_file in log_files:
        if not os.path.exists(log_file):
            open(log_file, 'a').close()

def log_error(error_message):
    """Log an error message."""
    try:
        with open(ERROR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {error_message}\n")
    except Exception as e:
        print(f"{Colors.RED}Error logging to error log: {str(e)}{Colors.RESET}")

def log_blocked_ip(ip, reason):
    """Log a blocked IP."""
    try:
        with open(BLOCKED_IP_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip} - Reason: {reason}\n")
    except Exception as e:
        log_error(f"Error logging blocked IP: {str(e)}")

def log_connection_attempt(log_line):
    """Log a connection attempt."""
    try:
        with open(ATTEMPTED_CONNECTIONS_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {log_line}\n")
    except Exception as e:
        log_error(f"Error logging connection attempt: {str(e)}")

def log_ddos_monitor(activity):
    """Log DDoS monitoring activity."""
    try:
        with open(DDOS_MONITOR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {activity}\n")
    except Exception as e:
        log_error(f"Error logging DDoS monitoring activity: {str(e)}")

def log_level_change(old_level, new_level, reason):
    """Log a protection level change."""
    try:
        with open(LEVEL_CHANGE_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Protection level changed from {old_level} to {new_level}. Reason: {reason}\n")
    except Exception as e:
        log_error(f"Error logging level change: {str(e)}")

def rotate_logs():
    """Rotate logs when they exceed 100MB."""
    log_files = [BLOCKED_IP_LOG, ATTEMPTED_CONNECTIONS_LOG, DDOS_MONITOR_LOG]
    MAX_LOG_SIZE = 100 * 1024 * 1024  # 100 MB in bytes

    for log_file in log_files:
        if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
            try:
                print(f"{Colors.YELLOW}Rotating log: {log_file} (exceeds 100MB)...{Colors.RESET}")
                os.remove(log_file)
                open(log_file, 'a').close()
                print(f"{Colors.GREEN}Log rotated successfully: {log_file}{Colors.RESET}")
            except Exception as e:
                log_error(f"Error rotating log {log_file}: {str(e)}")

def extract_ip_from_log(log_line):
    """Extract an IP address from a log entry."""
    import re
    try:
        ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        return ip_match[0] if ip_match else None
    except Exception as e:
        log_error(f"Error extracting IP from log: {str(e)}")
        return None

# Initialize logging
def init_logging():
    """Initialize logging by ensuring directory and files exist."""
    ensure_log_directory()
    ensure_log_files()
    print(f"{Colors.GREEN}Logging initialized successfully.{Colors.RESET}")
