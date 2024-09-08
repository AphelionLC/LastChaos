import os
import subprocess
import time
import threading
from collections import defaultdict
import psutil
import re
import math

# ============================ CONFIGURATION ============================ #
# Protection Level Configuration (1 = lenient, 6 = maximum security)
PROTECTION_LEVELS = {
    1: {
        "description": "Lenient: Higher connection limits, fewer login attempt restrictions",  # General description
        "SYNFLOOD_RATE": "1000/s",    # Rate limit for SYN flood protection (1000 packets per second)
        "SYNFLOOD_BURST": "500",      # Burst limit for SYN flood protection (allows up to 500 packets in a short burst)
        "CT_LIMIT": 5000,             # Maximum concurrent connections allowed (connection tracking limit)
        "CT_BLOCK_TIME": "3600",      # Time (in seconds) to block an IP if it exceeds the connection limit (1 hour)
        "LF_TRIGGER": 10,             # Number of failed login attempts before triggering an IP block
        "LOG_MONITOR_INTERVAL": 60,   # Interval (in seconds) to monitor log files (check for failed login attempts)
        "LF_DOS_LIMIT": 2000,         # Port flood protection limit: maximum allowed connections per second
        "LF_DOS_INTERVAL": 200,       # Port flood protection burst: burst allowed for port flooding (up to 200 packets)
        "DDOS_MONITOR_INTERVAL": 180, # Interval (in seconds) to check for potential DDoS attacks (every 3 minutes)
        "CONNLIMIT": 500,             # Maximum allowed connections per source IP before it is limited
        "PORTFLOOD_BURST": 100,       # Maximum burst for incoming connections per port (prevents connection flooding)
        "PORTFLOOD_INTERVAL": 60,     # Time interval for port flood monitoring (in seconds)
        "ICMP_RATE": "1/s",           # Rate limit for ICMP (ping) packets (1 packet per second)
        "UDP_LIMIT": "500/s",         # Rate limit for UDP packets to prevent UDP floods (500 packets per second)
        "BLOCK_INVALID": True,        # Block invalid packets (packets with incorrect state or malformed)
        "BLOCK_DNS": True,            # Block DNS traffic (prevents abuse of DNS services, blocks UDP port 53)
        "RST_RATE": "5/s",            # Rate limit for RST (Reset) packets (5 RST packets per second)
        "RST_BURST": "10"             # Burst limit for RST flood protection (allows up to 10 RST packets)
    },
    2: {
        "description": "Moderate: Balanced protection between performance and security",
        "SYNFLOOD_RATE": "500/s",
        "SYNFLOOD_BURST": "300",
        "CT_LIMIT": 3000,
        "CT_BLOCK_TIME": "1800",
        "LF_TRIGGER": 7,
        "LOG_MONITOR_INTERVAL": 50,
        "LF_DOS_LIMIT": 1500,
        "LF_DOS_INTERVAL": 150,
        "DDOS_MONITOR_INTERVAL": 120,
        "CONNLIMIT": 300,
        "PORTFLOOD_BURST": 80,
        "PORTFLOOD_INTERVAL": 60,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "400/s",
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "4/s",
        "RST_BURST": "8"
    },
    3: {
        "description": "Medium: Moderate connection limits and failed login restrictions",
        "SYNFLOOD_RATE": "300/s",
        "SYNFLOOD_BURST": "200",
        "CT_LIMIT": 2000,
        "CT_BLOCK_TIME": "1800",
        "LF_TRIGGER": 5,
        "LOG_MONITOR_INTERVAL": 40,
        "LF_DOS_LIMIT": 1000,
        "LF_DOS_INTERVAL": 100,
        "DDOS_MONITOR_INTERVAL": 100,
        "CONNLIMIT": 200,
        "PORTFLOOD_BURST": 60,
        "PORTFLOOD_INTERVAL": 90,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "300/s",
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "3/s",
        "RST_BURST": "6"
    },
    4: {
        "description": "Strict: Lower connection limits, more frequent log monitoring",
        "SYNFLOOD_RATE": "150/s",
        "SYNFLOOD_BURST": "100",
        "CT_LIMIT": 1000,
        "CT_BLOCK_TIME": "3600",
        "LF_TRIGGER": 3,
        "LOG_MONITOR_INTERVAL": 30,
        "LF_DOS_LIMIT": 500,
        "LF_DOS_INTERVAL": 50,
        "DDOS_MONITOR_INTERVAL": 60,
        "CONNLIMIT": 100,
        "PORTFLOOD_BURST": 40,
        "PORTFLOOD_INTERVAL": 120,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "200/s",
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "2/s",
        "RST_BURST": "5"
    },
    5: {
        "description": "Very Strict: Very tight limits, minimal connection bursts allowed",
        "SYNFLOOD_RATE": "100/s",
        "SYNFLOOD_BURST": "50",
        "CT_LIMIT": 500,
        "CT_BLOCK_TIME": "7200",
        "LF_TRIGGER": 2,
        "LOG_MONITOR_INTERVAL": 20,
        "LF_DOS_LIMIT": 300,
        "LF_DOS_INTERVAL": 30,
        "DDOS_MONITOR_INTERVAL": 60,
        "CONNLIMIT": 50,
        "PORTFLOOD_BURST": 30,
        "PORTFLOOD_INTERVAL": 90,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "100/s",
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "1/s",
        "RST_BURST": "3"
    },
    6: {
        "description": "Maximum: Maximum security with ultra-tight restrictions",
        "SYNFLOOD_RATE": "50/s",
        "SYNFLOOD_BURST": "25",
        "CT_LIMIT": 250,
        "CT_BLOCK_TIME": "14400",
        "LF_TRIGGER": 1,
        "LOG_MONITOR_INTERVAL": 10,
        "LF_DOS_LIMIT": 200,
        "LF_DOS_INTERVAL": 20,
        "DDOS_MONITOR_INTERVAL": 60,
        "CONNLIMIT": 25,
        "PORTFLOOD_BURST": 20,
        "PORTFLOOD_INTERVAL": 60,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "50/s",
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "1/s",
        "RST_BURST": "2"
    }
}

# Define DDoS thresholds for each protection level
DDOS_THRESHOLDS = {
    1: 400,  # For Lenient level
    2: 350,
    3: 300,
    4: 250,
    5: 200,
    6: 100   # For Maximum security level
}

# Set DDOS_THRESHOLD initially to None
DDOS_THRESHOLD = None

# Empty allowed IPs and ports (will be populated by user input)
ALLOWED_MARIADB_IPS = []
DEFAULT_MARIADB_IPS = ["127.0.0.1"]  # Always included
CT_PORTS = []

# These port are always allowed by default
DEFAULT_PORTS = ["20", "22", "25", "53", "80", "110", "143", "443"]  # Always included ports

# Logging settings
SCRIPT_DIR = os.getcwd()  # Get the current directory where the script is run
SECURITY_DIR = os.path.join(SCRIPT_DIR, "1-Security-Bot")  # Directory for logs
BLOCKED_IP_LOG = os.path.join(SECURITY_DIR, "blocked_ips.log")  # Blocked IP log
ATTEMPTED_CONNECTIONS_LOG = os.path.join(SECURITY_DIR, "connection_attempts.log")  # SSH/FTP connection attempts
DDOS_MONITOR_LOG = os.path.join(SECURITY_DIR, "DDoS-Monitor.log")  # Log for DDoS monitoring checks
ERROR_LOG = os.path.join(SECURITY_DIR, "error.log")

# Ensure the directory for logs exists
if not os.path.exists(SECURITY_DIR):
    os.makedirs(SECURITY_DIR)

# Ensure the log files are created if they don't exist
open(BLOCKED_IP_LOG, 'a').close()
open(ATTEMPTED_CONNECTIONS_LOG, 'a').close()
open(DDOS_MONITOR_LOG, 'a').close()
open(ERROR_LOG, 'a').close()

# Track blocked IPs and failed attempts
blocked_ips = defaultdict(int)
failed_attempts = defaultdict(int)  # Track failed connection attempts for each IP

# ============================ COLOR CODES ============================ #
class Colors:
    RESET = "\033[0m"         # Reset color
    RED = "\033[31m"          # Red
    GREEN = "\033[32m"        # Green
    YELLOW = "\033[33m"       # Yellow
    BLUE = "\033[34m"         # Blue
    CYAN = "\033[36m"         # Cyan
    LIGHT_GREEN = "\033[92m"  # Light Green
    LIGHT_RED = "\033[91m"    # Light Red
    ORANGE = "\033[38;5;214m" # Orange color for specific messages
    BOLD_WHITE = "\033[1;37m" # Bold White for making numbers more visible

# ============================ LOGGING FUNCTIONS ============================ #
def log_error(error_message):
    """Log errors to the error.log file."""
    try:
        with open(ERROR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {error_message}\n")
    except Exception as log_error:
        print(f"Error logging the error: {str(log_error)}")

def log_blocked_ip(ip, reason):
    """Log blocked IPs to the blocked_ips.log file with reasons."""
    try:
        with open(BLOCKED_IP_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip} - Reason: {reason}\n")
    except Exception as e:
        log_error(f"Error logging blocked IP: {str(e)}")

def log_ddos_monitor(activity):
    """Log DDoS monitoring activity."""
    try:
        with open(DDOS_MONITOR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {activity}\n")
    except Exception as e:
        log_error(f"Error logging DDoS monitoring activity: {str(e)}")

# ============================ ERROR HANDLING IN FUNCTIONS ============================ #
def display_welcome_message():
    """Display a welcome message with script details."""
    try:
        print(f"""\n{Colors.GREEN}
        =============================================================
                     WELCOME TO THE DDoS PROTECTION SCRIPT  
        =============================================================
        {Colors.RESET}
        This script will help you configure your server's security
        with multiple protection levels to guard against DDoS attacks.
        Let's get started!\n
        """)
    except Exception as e:
        log_error(f"Error displaying welcome message: {str(e)}")

def show_menu():
    """Display the protection level menu with color-coded levels and validate user input."""
    try:
        print(f"\n{Colors.CYAN}Choose a protection level:{Colors.RESET}")
        # Color gradient from light to strong
        level_colors = [
            Colors.CYAN,    # Level 1: Cyan (Aqua)
            Colors.GREEN,   # Level 2: Green
            Colors.YELLOW,  # Level 3: Yellow
            Colors.BLUE,    # Level 4: Blue
            Colors.LIGHT_RED,  # Level 5: Light Red
            Colors.RED      # Level 6: Strong Red
        ]
        # Display the levels with appropriate colors
        for level, config in PROTECTION_LEVELS.items():
            color = level_colors[level - 1]
            print(f"  {color}{level}. {config['description']}{Colors.RESET}")

        # Input validation loop
        while True:
            try:
                choice = int(input("\nEnter the desired protection level (1-6): "))
                if 1 <= choice <= 6:
                    return choice
                else:
                    print(f"{Colors.RED}Invalid input. Please enter a number between 1 and 6.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}Invalid input. Please enter a number between 1 and 6.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error displaying or selecting menu: {str(e)}")

def get_allowed_mariadb_ips():
    """Prompt the user to input allowed MariaDB IPs separated by commas."""
    try:
        ip_input = input(f"{Colors.CYAN}Enter the IP addresses allowed to connect to MariaDB (separated by commas): {Colors.RESET}")
        if ip_input:
            user_ips = [ip.strip() for ip in ip_input.split(',')]  # Split and remove spaces
            allowed_ips = list(set(DEFAULT_MARIADB_IPS + user_ips))  # Combine default and user-defined IPs, remove duplicates
            return allowed_ips
        return DEFAULT_MARIADB_IPS  # If no user input, return only default IPs
    except Exception as e:
        log_error(f"Error getting allowed MariaDB IPs: {str(e)}")
        return DEFAULT_MARIADB_IPS

def get_allowed_ports():
    """Prompt the user to input the allowed ports separated by commas, and merge with default ports."""
    try:
        port_input = input(f"{Colors.CYAN}Enter additional ports to protect (separated by commas): {Colors.RESET}")
        if port_input:
            user_ports = [port.strip() for port in port_input.split(',')]  # Split and remove spaces
            allowed_ports = list(set(DEFAULT_PORTS + user_ports))  # Combine default and user-defined ports, remove duplicates
            return allowed_ports
        return DEFAULT_PORTS  # If no user input, return only default ports
    except Exception as e:
        log_error(f"Error getting allowed ports: {str(e)}")
        return DEFAULT_PORTS

def apply_protection_level(level, allowed_ports):
    """Apply settings based on the user's chosen protection level and allowed ports."""
    try:
        global SYNFLOOD_RATE, SYNFLOOD_BURST, CT_LIMIT, CT_BLOCK_TIME, LF_TRIGGER, LOG_MONITOR_INTERVAL, LF_DOS_LIMIT, LF_DOS_INTERVAL, DDOS_MONITOR_INTERVAL, CONNLIMIT, PORTFLOOD, ICMP_RATE, UDP_LIMIT, BLOCK_INVALID, BLOCK_DNS, RST_RATE, RST_BURST

        config = PROTECTION_LEVELS.get(level)
        if config:
            SYNFLOOD_RATE = config['SYNFLOOD_RATE']
            SYNFLOOD_BURST = config['SYNFLOOD_BURST']
            CT_LIMIT = config['CT_LIMIT']
            CT_BLOCK_TIME = config['CT_BLOCK_TIME']
            LF_TRIGGER = config['LF_TRIGGER']
            LOG_MONITOR_INTERVAL = config['LOG_MONITOR_INTERVAL']
            LF_DOS_LIMIT = config['LF_DOS_LIMIT']
            LF_DOS_INTERVAL = config['LF_DOS_INTERVAL']
            DDOS_MONITOR_INTERVAL = config['DDOS_MONITOR_INTERVAL']
            ICMP_RATE = config['ICMP_RATE']
            UDP_LIMIT = config['UDP_LIMIT']
            BLOCK_INVALID = config['BLOCK_INVALID']
            BLOCK_DNS = config.get('BLOCK_DNS', False)
            RST_RATE = config['RST_RATE']  # Add RST rate
            RST_BURST = config['RST_BURST']  # Add RST burst

            # Use user-defined ports (combined with default ports) and apply connection limits and port flooding dynamically
            if allowed_ports:
                CONNLIMIT = f"{','.join(allowed_ports)};{config['CONNLIMIT']}"  # Dynamic port + level-based limit
                PORTFLOOD = f"{','.join(allowed_ports)};tcp;{config['PORTFLOOD_BURST']};{config['PORTFLOOD_INTERVAL']}"
            else:
                CONNLIMIT = ""
                PORTFLOOD = ""

            # If DNS blocking is enabled, block UDP traffic on port 53 (DNS)
            if BLOCK_DNS:
                subprocess.run("iptables -A INPUT -p udp --dport 53 -j DROP", shell=True, check=True)
                subprocess.run("iptables -A OUTPUT -p udp --dport 53 -j DROP", shell=True, check=True)
        else:
            log_error("Invalid protection level selected. Defaulting to Level 1.")
            apply_protection_level(1, allowed_ports)
    except Exception as e:
        log_error(f"Error applying protection level: {str(e)}")

def rule_exists(rule):
    """Check if a given iptables rule already exists."""
    try:
        result = subprocess.run(f"iptables-save | grep -- '{rule}'", shell=True, stdout=subprocess.PIPE)
        return result.returncode == 0
    except Exception as e:
        log_error(f"Error checking if iptables rule exists: {str(e)}")
        return False

def chunk_ports(port_list, chunk_size=15):
    """Utility function to split ports into chunks of chunk_size to avoid iptables limit."""
    for i in range(0, len(port_list), chunk_size):
        yield port_list[i:i + chunk_size]

def setup_iptables():
    """Set up IPTables rules to mitigate various attacks while allowing game traffic."""
    try:
        # Flush existing IPTables rules and set default policies to DROP
        subprocess.run("iptables -F", shell=True, check=True)
        subprocess.run("iptables -X", shell=True, check=True)

        # Set default policies to DROP
        subprocess.run("iptables -P INPUT DROP", shell=True, check=True)
        subprocess.run("iptables -P FORWARD DROP", shell=True, check=True)
        subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=True)

        # Accept loopback traffic (for local processes)
        subprocess.run("iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A OUTPUT -o lo -j ACCEPT", shell=True, check=True)

        # Allow MariaDB access from allowed IPs
        if ALLOWED_MARIADB_IPS:
            for ip in ALLOWED_MARIADB_IPS:
                subprocess.run(f"iptables -A INPUT -p tcp --dport 3306 -s {ip} -j ACCEPT", shell=True, check=True)

        # Block all other IPs from accessing MariaDB
        subprocess.run(f"iptables -A INPUT -p tcp --dport 3306 -j DROP", shell=True, check=True)

        # SYN flood protection
        subprocess.run(f"iptables -A INPUT -p tcp --syn -m limit --limit {SYNFLOOD_RATE} --limit-burst {SYNFLOOD_BURST} -j ACCEPT", shell=True, check=True)

        # RST Flood protection
        subprocess.run(f"iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit {RST_RATE} --limit-burst {RST_BURST} -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP", shell=True, check=True)

        # Allow inbound traffic on user-specified and default ports
        if CT_PORTS:
            subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {','.join(CT_PORTS)} -j ACCEPT", shell=True, check=True)

        # Allow outbound traffic on the specified ports
        if CT_PORTS:
            subprocess.run(f"iptables -A OUTPUT -p tcp -m multiport --sports {','.join(CT_PORTS)} -j ACCEPT", shell=True, check=True)

        # Apply connection limits
        subprocess.run(f"iptables -A INPUT -p tcp -m connlimit --connlimit-above {CT_LIMIT} --connlimit-mask 32 -j REJECT", shell=True, check=True)

        # Apply ICMP rate limiting
        subprocess.run(f"iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {ICMP_RATE} -j ACCEPT", shell=True, check=True)
        subprocess.run(f"iptables -A INPUT -p icmp --icmp-type echo-request -j DROP", shell=True, check=True)

        # Apply UDP flood protection
        subprocess.run(f"iptables -A INPUT -p udp -m limit --limit {UDP_LIMIT} -j ACCEPT", shell=True, check=True)
        subprocess.run(f"iptables -A INPUT -p udp -j DROP", shell=True, check=True)

        # Block invalid packets
        if BLOCK_INVALID:
            subprocess.run(f"iptables -A INPUT -m state --state INVALID -j DROP", shell=True, check=True)

        # Block DNS traffic (UDP port 53)
        if PROTECTION_LEVELS[PROTECTION_LEVEL]['BLOCK_DNS']:
            subprocess.run("iptables -A INPUT -p udp --dport 53 -j DROP", shell=True, check=True)

        # Block all other unspecified ports explicitly
        subprocess.run("iptables -A INPUT -p tcp --syn -j REJECT", shell=True, check=True)

    except Exception as e:
        log_error(f"Error setting up iptables: {str(e)}")

def block_ip(ip, reason):
    """Block an IP using IPTables and log the blocked IP, excluding 127.0.0.1."""
    try:
        if ip != "127.0.0.1" and ip not in blocked_ips:
            subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            log_blocked_ip(ip, reason)
            blocked_ips[ip] += 1
    except Exception as e:
        log_error(f"Error blocking IP {ip}: {str(e)}")

def monitor_logs():
    """Monitor /var/log/secure and log SSH attempts (Accepted/Failed passwords) to connection_attempts.log."""
    secure_log = "/var/log/secure"
    secure_position = 0
    try:
        # Open the secure log file and start reading from the end
        if os.path.exists(secure_log):
            with open(secure_log, 'r') as f:
                f.seek(0, os.SEEK_END)
                secure_position = f.tell()

        while True:
            with open(secure_log, 'r') as f:
                f.seek(secure_position)  # Start reading from the last position
                lines = f.readlines()  # Read all new lines
                secure_position = f.tell()

                if lines:
                    for line in lines:
                        if "sshd" in line and ("Failed password" in line or "Accepted password" in line):
                            with open(ATTEMPTED_CONNECTIONS_LOG, 'a') as log_file:
                                log_file.write(line)  # Log the full line

                            # Extract IP and decide whether to block
                            ip = extract_ip_from_log(line)
                            if ip and "Failed password" in line:
                                failed_attempts[ip] += 1
                                if failed_attempts[ip] >= LF_TRIGGER:
                                    block_ip(ip, "Failed SSH attempts")
            time.sleep(LOG_MONITOR_INTERVAL)
    except Exception as e:
        log_error(f"Error monitoring logs: {str(e)}")

def monitor_ddos():
    """Monitor for potential DDoS attacks by analyzing connections using netstat."""
    try:
        while True:
            # Log DDoS monitoring activity
            log_ddos_monitor("Checking for DDoS activity...")

            # Get TCP connections
            result = subprocess.run(["netstat", "-ant"], stdout=subprocess.PIPE, universal_newlines=True)
            connections = result.stdout.splitlines()

            # Count established connections per IP
            connection_count = defaultdict(int)
            for line in connections:
                if "ESTABLISHED" in line:
                    ip = line.split()[4].split(':')[0]
                    connection_count[ip] += 1

            # Use the dynamic DDOS_THRESHOLD set earlier
            for ip, count in connection_count.items():
                if ip != "127.0.0.1" and count > DDOS_THRESHOLD:
                    block_ip(ip, "Potential DDoS attack")
                    log_ddos_monitor(f"Blocked IP {ip} for potential DDoS attack")

            # Sleep for the configured DDoS monitor interval before checking again
            time.sleep(DDOS_MONITOR_INTERVAL)
    except Exception as e:
        log_error(f"Error monitoring DDoS: {str(e)}")

def kill_existing_script():
    """Check if the script is already running and kill it if found."""
    try:
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if proc.info['name'] in ['python', 'python3'] and 'Block-DDoS.py' in proc.info['cmdline'][1]:
                if proc.info['pid'] != current_pid:
                    proc.terminate()
                    proc.wait()
    except Exception as e:
        log_error(f"Error killing existing script instance: {str(e)}")

# ============================ INSTALL DEPENDENCIES ============================ #
def install_dependencies():
    """Check and install necessary dependencies for AlmaLinux with error handling."""
    try:
        # Check if psutil is installed
        try:
            import psutil
            print(f"{Colors.GREEN}psutil is already installed.{Colors.RESET}")
        except ImportError:
            print(f"{Colors.RED}psutil is not installed. Installing...{Colors.RESET}")
            subprocess.run("pip install psutil", shell=True, check=True)
            print(f"{Colors.GREEN}psutil installed successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error installing psutil: {str(e)}")

    try:
        # Check if netstat is installed
        netstat_installed = subprocess.run("command -v netstat", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if netstat_installed.returncode == 0:
            print(f"{Colors.GREEN}netstat is already installed.{Colors.RESET}")
        else:
            print(f"{Colors.RED}netstat is not installed. Installing net-tools...{Colors.RESET}")
            subprocess.run("yum install -y net-tools", shell=True, check=True)
            print(f"{Colors.GREEN}net-tools (which includes netstat) installed successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error installing net-tools: {str(e)}")

    try:
        # Check if iptables is installed
        iptables_installed = subprocess.run("command -v iptables", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if iptables_installed.returncode == 0:
            print(f"{Colors.GREEN}iptables is already installed.{Colors.RESET}")
        else:
            print(f"{Colors.RED}iptables is not installed. Installing iptables...{Colors.RESET}")
            subprocess.run("yum install -y iptables", shell=True, check=True)
            print(f"{Colors.GREEN}iptables installed successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error installing iptables: {str(e)}")

def run_in_background():
    """Run the script in the background by forking a new process."""
    try:
        pid = os.fork()  # Fork the current process
        if pid > 0:
            print(f"Script is running in the background with PID {pid}. Exiting terminal.")
            os._exit(0)  # Exit the parent process to allow the child process to continue running
    except AttributeError:
        # If os.fork() is not available (on Windows for example), handle the error.
        log_error("Forking not supported on this platform. Running in the foreground.")

def extract_ip_from_log(log_line):
    """Extract an IP address from a log entry using a regular expression."""
    try:
        # Regular expression to match an IPv4 address
        ip_match = re.findall(r'[0-9]+(?:\.[0-9]+){3}', log_line)
        return ip_match[0] if ip_match else None  # Return the first match or None if no match
    except Exception as e:
        log_error(f"Error extracting IP from log: {str(e)}")
        return None

def rotate_logs():
    """Rotate logs when they exceed 100MB, delete and recreate them."""
    log_files = [BLOCKED_IP_LOG, ATTEMPTED_CONNECTIONS_LOG, DDOS_MONITOR_LOG]

    # 100 MB threshold for logs
    MAX_LOG_SIZE = 100 * 1024 * 1024  # 100 MB in bytes

    for log_file in log_files:
        if os.path.exists(log_file):
            if os.path.getsize(log_file) > MAX_LOG_SIZE:
                try:
                    print(f"{Colors.YELLOW}Rotating log: {log_file} (exceeds 100MB)...{Colors.RESET}")
                    os.remove(log_file)  # Delete the log file
                    open(log_file, 'a').close()  # Recreate an empty log file
                    print(f"{Colors.GREEN}Log rotated successfully: {log_file}{Colors.RESET}")
                except Exception as e:
                    log_error(f"Error rotating log {log_file}: {str(e)}")

# ============================ MAIN FUNCTION ============================ #
def main():
    """Main function to start the script and handle errors during startup and runtime."""
    try:
        display_welcome_message()

        # First, kill existing scripts and install dependencies without showing progress
        kill_existing_script()
        install_dependencies()

        global PROTECTION_LEVEL, ALLOWED_MARIADB_IPS, CT_PORTS, DDOS_THRESHOLD
        
        # Collect inputs from the user without echoing yet
        PROTECTION_LEVEL = show_menu()

        # Set the DDoS threshold based on the selected protection level
        DDOS_THRESHOLD = DDOS_THRESHOLDS[PROTECTION_LEVEL]

        # Collect allowed MariaDB IPs and ports
        ALLOWED_MARIADB_IPS = get_allowed_mariadb_ips()
        CT_PORTS = get_allowed_ports()

        # After collecting all inputs, echo the steps in light green and numbers in bold white
        print(f"\n{Colors.LIGHT_GREEN}Setting DDoS threshold to {Colors.BOLD_WHITE}{DDOS_THRESHOLD}{Colors.LIGHT_GREEN} connections for protection level {Colors.BOLD_WHITE}{PROTECTION_LEVEL}.{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowed MariaDB IP addresses: {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowed ports: {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")
        
        # Now proceed with the rest of the steps
        print(f"{Colors.LIGHT_GREEN}Applying protection level {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN} settings...{Colors.RESET}")
        apply_protection_level(PROTECTION_LEVEL, CT_PORTS)

        # Run IPTables setup only once here, right after all inputs are collected
        print(f"{Colors.LIGHT_GREEN}Flushing existing IPTables rules...{Colors.RESET}")
        setup_iptables()

        # IPTables setup details in light green with numbers in bold white
        print(f"{Colors.LIGHT_GREEN}Applying Protection Level: {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Flushing existing IPTables rules and setting default policies to DROP...{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowing loopback traffic...{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowing MariaDB access from IP: {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Blocking all other IPs from accessing MariaDB on port 3306...{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying SYN flood protection: {Colors.BOLD_WHITE}{SYNFLOOD_RATE}{Colors.LIGHT_GREEN}, burst {Colors.BOLD_WHITE}{SYNFLOOD_BURST}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying ICMP rate limit: {Colors.BOLD_WHITE}{ICMP_RATE}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying UDP flood protection limit: {Colors.BOLD_WHITE}{UDP_LIMIT}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Blocking invalid packets...{Colors.RESET}")
        
        # Add DNS blocking step if it's part of the protection level
        if PROTECTION_LEVELS[PROTECTION_LEVEL]['BLOCK_DNS']:
            print(f"{Colors.LIGHT_GREEN}Blocking DNS traffic on UDP port 53...{Colors.RESET}")
        
        print(f"{Colors.LIGHT_GREEN}Applying RST flood protection: rate {Colors.BOLD_WHITE}{PROTECTION_LEVELS[PROTECTION_LEVEL]['RST_RATE']}{Colors.LIGHT_GREEN}, burst {Colors.BOLD_WHITE}{PROTECTION_LEVELS[PROTECTION_LEVEL]['RST_BURST']}{Colors.RESET}")
        
        # Allowing and blocking ports
        print(f"{Colors.LIGHT_GREEN}Allowing inbound traffic on default and user-specified ports: {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowing outbound traffic on specified ports: {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying connection limits: {Colors.BOLD_WHITE}{CT_LIMIT}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying port flood protection with burst {Colors.BOLD_WHITE}{LF_DOS_LIMIT}{Colors.LIGHT_GREEN}, interval {Colors.BOLD_WHITE}{LF_DOS_INTERVAL}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Blocking all other unspecified ports...{Colors.RESET}")
        
        # Print IPTables rules applied message in orange
        print(f"{Colors.ORANGE}IPTables rules applied successfully.{Colors.RESET}")
        
        # Print running in the background message in orange
        print(f"{Colors.ORANGE}Running the script in the background...{Colors.RESET}")
        
        run_in_background()

        # Display the final success message before starting threads
        print(f"{Colors.YELLOW}=================================================================================================")
        print(f" Security Setup finished! Your server is now protected from DDoS attacks and unauthorized access.")
        print(f"================================================================================================={Colors.RESET}")

        # Start the monitoring threads after the final message
        print(f"{Colors.LIGHT_GREEN}Starting log monitoring thread...{Colors.RESET}")
        log_monitor_thread = threading.Thread(target=monitor_logs)

        print(f"{Colors.LIGHT_GREEN}Starting DDoS monitoring thread...{Colors.RESET}")
        ddos_monitor_thread = threading.Thread(target=monitor_ddos)

        print(f"{Colors.LIGHT_GREEN}Starting both monitoring threads...{Colors.RESET}")
        log_monitor_thread.start()
        ddos_monitor_thread.start()

        log_monitor_thread.join()
        ddos_monitor_thread.join()

        # **Rotate logs periodically during runtime**
        while True:
            rotate_logs()
            time.sleep(3600)  # Check log size every hour
    
    except Exception as e:
        print("An error occurred in the main function.")
        log_error(f"Error in main: {str(e)}")

if __name__ == "__main__":
    main()
