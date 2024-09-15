import os
import subprocess
import time
import threading
from collections import defaultdict
import psutil
import re
import math
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
        "DDOS_MONITOR_INTERVAL": 10,  # Interval (in seconds) to check for potential DDoS attacks (every 3 minutes)
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
        "DDOS_MONITOR_INTERVAL": 10,
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
        "DDOS_MONITOR_INTERVAL": 10,
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
        "DDOS_MONITOR_INTERVAL": 10,
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
        "DDOS_MONITOR_INTERVAL": 10,
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
        "DDOS_MONITOR_INTERVAL": 10,
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
    1: 15,  # Lenient threshold for lower protection levels
    2: 12,
    3: 10,
    4: 8,
    5: 7,
    6: 5   # Maximum security: block after 70 connections
}

# Define DDoS thresholds for each protection level
#DDOS_THRESHOLDS = {
#    1: 100,  # Lenient threshold for lower protection levels
#    2: 90,
#    3: 85,
#    4: 80,
#    5: 75,
#    6: 70   # Maximum security: block after 70 connections
#}

# Initial variables
INITIAL_PROTECTION_LEVEL = None  # Store initial protection level set by the user
CURRENT_PROTECTION_LEVEL = None  # Track current active protection level
DDOS_THRESHOLD = None            # Dynamic DDoS threshold, will change based on protection level
SUSPICIOUS_ACTIVITY_THRESHOLD = 3  # Number of DDoS triggers before upgrading level

# Empty allowed IPs and ports (will be populated by user input)
ALLOWED_MARIADB_IPS = []
DEFAULT_MARIADB_IPS = ["127.0.0.1", "79.116.74.78", "80.194.10.67", "185.62.188.4"]  # Always included
CT_PORTS = []

# Add your server's IP here
WHITELISTED_IPS = ["127.0.0.1"]

# These port are always allowed by default
DEFAULT_PORTS = ["20", "22", "25", "53", "80", "110", "143", "443"]  # Always included ports

# Log files
SCRIPT_DIR = os.getcwd()
SECURITY_DIR = os.path.join(SCRIPT_DIR, "Security Logs")
BLOCKED_IP_LOG = os.path.join(SECURITY_DIR, "blocked_ips.log")
ATTEMPTED_CONNECTIONS_LOG = os.path.join(SECURITY_DIR, "connection_attempts.log")
DDOS_MONITOR_LOG = os.path.join(SECURITY_DIR, "DDoS-Monitor.log")
ERROR_LOG = os.path.join(SECURITY_DIR, "error.log")
LEVEL_CHANGE_LOG = os.path.join(SECURITY_DIR, "level_change.log")
CONNECTION_LOG = os.path.join(SECURITY_DIR, "connections_per_ip.log")

# Ensure log directory exists
if not os.path.exists(SECURITY_DIR):
    os.makedirs(SECURITY_DIR)

# Ensure log files exist
for log_file in [BLOCKED_IP_LOG, ATTEMPTED_CONNECTIONS_LOG, DDOS_MONITOR_LOG, ERROR_LOG, LEVEL_CHANGE_LOG, CONNECTION_LOG]:
    open(log_file, 'a').close()

blocked_ips = defaultdict(int)
failed_attempts = defaultdict(int)

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "aphelionlc.status@gmail.com"
SENDER_PASSWORD = "rucrdxslwkkzmkcn"
RECIPIENT_EMAILS = ["williamperez1988@hotmail.com"] #, "lewisallum11@gmail.com"]

# ============================ EMAIL FUNCTION ============================ #
def send_email(subject, message):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECIPIENT_EMAILS)
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'html'))

        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print("Error sending email:", str(e))

# ============================ MONITOR LOGS FOR EMAIL ============================ #
def monitor_ddos_log():
    """Check DDoS-Monitor.log for new DDoS activity and send email if detected."""
    ddos_log_path = os.path.join(SECURITY_DIR, "DDoS-Monitor.log")
    last_position = 0
    if os.path.exists(ddos_log_path):
        last_position = os.path.getsize(ddos_log_path)
        
    while True:
        time.sleep(120)  # Check every 2 minutes
        with open(ddos_log_path, 'r') as ddos_log:
            ddos_log.seek(last_position)
            new_lines = ddos_log.readlines()
            last_position = ddos_log.tell()
            
            for line in new_lines:
                if "Potential DDoS attack" in line:
                    email_subject = "DDoS Activity Detected on Your Server"
                    email_message = f"""
                    <html>
                    <body>
                    <h2>Dear Admins,</h2>
                    <p>We detected a potential DDoS attack on Phoenix LC server:</p>
                    <p><strong>{line}</strong></p>
                    <p>Best regards,<br>Block DDoS Automated System</p>
                    </body>
                    </html>
                    """
                    send_email(email_subject, email_message)

def monitor_level_change_log():
    """Check level_change.log for any protection level changes and send email if detected."""
    level_change_log_path = os.path.join(SECURITY_DIR, "level_change.log")
    last_position = 0
    if os.path.exists(level_change_log_path):
        last_position = os.path.getsize(level_change_log_path)
        
    while True:
        time.sleep(120)  # Check every 2 minutes
        with open(level_change_log_path, 'r') as level_log:
            level_log.seek(last_position)
            new_lines = level_log.readlines()
            last_position = level_log.tell()
            
            for line in new_lines:
                email_subject = "Protection Level Changed on Your Server"
                email_message = f"""
                <html>
                <body>
                <h2>Dear Admins,</h2>
                <p>The protection level on Phoenix LC server has changed:</p>
                <p><strong>{line}</strong></p>
                <p>Best regards,<br>Block DDoS Automated System</p>
                </body>
                </html>
                """
                send_email(email_subject, email_message)

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
    try:
        with open(ERROR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {error_message}\n")
    except Exception as log_error:
        print(f"Error logging the error: {str(log_error)}")

def log_blocked_ip(ip, reason):
    try:
        with open(BLOCKED_IP_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip} - Reason: {reason}\n")
    except Exception as e:
        log_error(f"Error logging blocked IP: {str(e)}")

def log_ddos_monitor(activity):
    try:
        with open(DDOS_MONITOR_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {activity}\n")
    except Exception as e:
        log_error(f"Error logging DDoS monitoring activity: {str(e)}")

def log_level_change(old_level, new_level, reason):
    try:
        with open(LEVEL_CHANGE_LOG, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Protection level changed from {old_level} to {new_level}. Reason: {reason}\n")
    except Exception as e:
        log_error(f"Error logging level change: {str(e)}")

# ============================ AUTO PROTECTION LEVEL ADJUSTMENTS ============================ #
def adjust_protection_level(activity):
    """Automatically upgrade or downgrade protection level based on activity."""
    global CURRENT_PROTECTION_LEVEL, INITIAL_PROTECTION_LEVEL

    if activity == "upgrade" and CURRENT_PROTECTION_LEVEL < 6:
        old_level = CURRENT_PROTECTION_LEVEL
        CURRENT_PROTECTION_LEVEL += 1
        print(f"{Colors.LIGHT_GREEN}Upgrading protection level to {Colors.BOLD_WHITE}{CURRENT_PROTECTION_LEVEL}{Colors.RESET} due to suspicious activity.")
        
        # Flush and reapply rules for the new level
        apply_protection_level(CURRENT_PROTECTION_LEVEL, CT_PORTS)
        log_level_change(old_level, CURRENT_PROTECTION_LEVEL, "Suspicious activity detected")

    elif activity == "downgrade" and CURRENT_PROTECTION_LEVEL > INITIAL_PROTECTION_LEVEL:
        old_level = CURRENT_PROTECTION_LEVEL
        CURRENT_PROTECTION_LEVEL = INITIAL_PROTECTION_LEVEL
        print(f"{Colors.LIGHT_GREEN}Downgrading protection level to {Colors.BOLD_WHITE}{CURRENT_PROTECTION_LEVEL}{Colors.RESET} due to lower activity.")
        
        # Flush and reapply rules for the downgraded level
        apply_protection_level(CURRENT_PROTECTION_LEVEL, CT_PORTS)
        log_level_change(old_level, CURRENT_PROTECTION_LEVEL, "Suspicious activity subsided")


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

# ============================ APPLY PROTECTION LEVEL ============================ #
def apply_protection_level(level, allowed_ports):
    """Apply protection settings based on the current level and allowed ports."""
    global SYNFLOOD_RATE, SYNFLOOD_BURST, CT_LIMIT, CT_BLOCK_TIME, LF_TRIGGER, LOG_MONITOR_INTERVAL, LF_DOS_LIMIT, LF_DOS_INTERVAL, DDOS_MONITOR_INTERVAL, CONNLIMIT, PORTFLOOD, ICMP_RATE, UDP_LIMIT, BLOCK_INVALID, BLOCK_DNS, RST_RATE, RST_BURST

    # Get the protection level configuration
    config = PROTECTION_LEVELS.get(level)

    if config:
        # Flush IPTables before applying the new rules
        flush_iptables_rules()

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
        RST_RATE = config['RST_RATE']
        RST_BURST = config['RST_BURST']

        # Apply user-defined ports
        if allowed_ports:
            CONNLIMIT = f"{','.join(allowed_ports)};{config['CONNLIMIT']}"
            PORTFLOOD = f"{','.join(allowed_ports)};tcp;{config['PORTFLOOD_BURST']};{config['PORTFLOOD_INTERVAL']}"
        else:
            CONNLIMIT = ""
            PORTFLOOD = ""

        # Reapply IPTables rules based on the new level
        setup_iptables()

        print(f"Applied protection level {level} with SYNFLOOD rate {SYNFLOOD_RATE}, burst {SYNFLOOD_BURST}")
    else:
        log_error("Invalid protection level selected. Defaulting to Level 1.")
        apply_protection_level(1, allowed_ports)

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

        # Allow inbound traffic on user-specified and default ports (chunked to avoid too many ports issue)
        if CT_PORTS:
            for port_chunk in chunk_ports(CT_PORTS, chunk_size=15):  # Adjust chunk size as needed
                ports_str = ','.join(port_chunk)
                subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {ports_str} -j ACCEPT", shell=True, check=True)

        # Allow outbound traffic on the specified ports (chunked to avoid too many ports issue)
        if CT_PORTS:
            for port_chunk in chunk_ports(CT_PORTS, chunk_size=15):  # Adjust chunk size as needed
                ports_str = ','.join(port_chunk)
                subprocess.run(f"iptables -A OUTPUT -p tcp -m multiport --sports {ports_str} -j ACCEPT", shell=True, check=True)

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

# ============================ MONITOR DDoS ATTACKS ============================ #
def monitor_ddos():
    """Monitor for potential DDoS attacks by analyzing connections using netstat and ss, and adjust protection level."""
    global suspicious_activity_count

    server_ip = "145.239.1.51"  # Server's own IP to exclude

    try:
        while True:
            log_ddos_monitor("Checking for DDoS activity...")

            # Define thresholds and ensure they are integers
            syn_threshold = int(PROTECTION_LEVELS[CURRENT_PROTECTION_LEVEL]['SYNFLOOD_RATE'].split('/')[0])
            udp_threshold = 500  # UDP flood threshold
            icmp_threshold = 100  # ICMP flood threshold
            tcp_time_wait_threshold = 200  # TCP connection flood threshold (TIME_WAIT/CLOSE_WAIT)
            threshold_display_percentage = 0.7  # Only show if threshold is reached at least 70%

            # Monitor TCP (ESTABLISHED) with netstat
            result = subprocess.run(["netstat", "-ant"], stdout=subprocess.PIPE, universal_newlines=True)
            tcp_connections = result.stdout.splitlines()

            tcp_established_count = defaultdict(int)
            syn_recv_count = defaultdict(int)

            for line in tcp_connections:
                try:
                    split_line = line.split()
                    if len(split_line) >= 5 and "ESTABLISHED" in split_line[-1]:
                        ip = split_line[4].split(':')[0]
                        if ip != "127.0.0.1" and ip != server_ip:  # Skip localhost and server's own IP
                            tcp_established_count[ip] += 1
                    elif len(split_line) >= 5 and "SYN_RECV" in split_line[-1]:
                        ip = split_line[4].split(':')[0]
                        if ip != "127.0.0.1" and ip != server_ip:  # Skip localhost and server's own IP
                            syn_recv_count[ip] += 1
                except IndexError as e:
                    log_error(f"Error processing TCP line: {line} - {str(e)}")
                    continue

            # Monitor UDP and ICMP connections with ss
            udp_result = subprocess.run(["ss", "-u", "-a"], stdout=subprocess.PIPE, universal_newlines=True)
            icmp_result = subprocess.run(["ss", "-i", "-a"], stdout=subprocess.PIPE, universal_newlines=True)

            udp_connections = udp_result.stdout.splitlines()
            icmp_connections = icmp_result.stdout.splitlines()

            udp_count = defaultdict(int)
            icmp_count = defaultdict(int)

            # Process UDP connections
            for line in udp_connections:
                try:
                    split_line = line.split()
                    if len(split_line) >= 6 and "UNCONN" in split_line:
                        ip = split_line[5].split(':')[0]
                        if ip != "127.0.0.1" and ip != server_ip:  # Skip localhost and server's own IP
                            udp_count[ip] += 1
                except IndexError as e:
                    log_error(f"Error processing UDP line: {line} - {str(e)}")
                    continue

            # Process ICMP connections
            for line in icmp_connections:
                try:
                    split_line = line.split()
                    if len(split_line) >= 6 and ("UNCONN" in split_line or "PING" in split_line):
                        ip = split_line[5].split(':')[0]
                        if ip != "127.0.0.1" and ip != server_ip:  # Skip localhost and server's own IP
                            icmp_count[ip] += 1
                except IndexError as e:
                    log_error(f"Error processing ICMP line: {line} - {str(e)}")
                    continue

            suspicious_activity_detected = False
            blocked_ips = []

            # Function to log how close an IP is to reaching the DDoS threshold
            def log_proximity(ip, count, threshold, attack_type):
                percentage = (count / threshold) * 100
                if percentage >= threshold_display_percentage * 100:
                    log_ddos_monitor(f"{ip} - {attack_type} count: {count}, {percentage:.2f}% of the threshold ({threshold}).")
                return percentage >= threshold_display_percentage * 100

            # Check for excessive TCP ESTABLISHED Connections
            for ip, count in tcp_established_count.items():
                if log_proximity(ip, count, DDOS_THRESHOLD, "TCP ESTABLISHED"):
                    if count > DDOS_THRESHOLD:
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential DDoS attack (TCP ESTABLISHED connections exceeded)")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive TCP ESTABLISHED connections")
                        blocked_ips.append(ip)

            # Check for excessive SYN_RECV connections
            for ip, count in syn_recv_count.items():
                if log_proximity(ip, count, syn_threshold, "SYN_RECV"):
                    if count > syn_threshold:
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential SYN flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive SYN_RECV connections")
                        blocked_ips.append(ip)

            # Check for excessive UDP connections
            for ip, count in udp_count.items():
                if log_proximity(ip, count, udp_threshold, "UDP"):
                    if count > udp_threshold:
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential UDP flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive UDP connections")
                        blocked_ips.append(ip)

            # Check for excessive ICMP connections
            for ip, count in icmp_count.items():
                if log_proximity(ip, count, icmp_threshold, "ICMP"):
                    if count > icmp_threshold:
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential ICMP flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive ICMP connections")
                        blocked_ips.append(ip)

            # Blocked IPs summary
            if blocked_ips:
                log_ddos_monitor(f"Blocked IPs: {', '.join(blocked_ips)}")

            # If suspicious activity is detected, take action
            if suspicious_activity_detected:
                suspicious_activity_count += 1
                print(f"Suspicious activity detected! Count: {suspicious_activity_count}")
                if suspicious_activity_count >= SUSPICIOUS_ACTIVITY_THRESHOLD:
                    adjust_protection_level("upgrade")
                    suspicious_activity_count = 0  # Reset count after upgrade
            else:
                if suspicious_activity_count > 0:
                    suspicious_activity_count -= 1  # Reset the count if no suspicious activity is detected
                adjust_protection_level("downgrade")

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
            print(f"{Colors.ORANGE}Script is running in the background with PID {pid}. Exiting terminal.{Colors.RESET}")
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
    log_files = [BLOCKED_IP_LOG, ATTEMPTED_CONNECTIONS_LOG, DDOS_MONITOR_LOG, CONNECTION_LOG]

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

def flush_iptables_rules():
    """Flush all existing IPTables rules and set default policies to DROP."""
    try:
        print(f"{Colors.YELLOW}Flushing all existing IPTables rules...{Colors.RESET}")
        subprocess.run("iptables -F", shell=True, check=True)  # Flush all rules
        subprocess.run("iptables -X", shell=True, check=True)  # Delete all user-defined chains
        subprocess.run("iptables -Z", shell=True, check=True)  # Zero all packet and byte counters
        subprocess.run("iptables -P INPUT DROP", shell=True, check=True)  # Set default policy to DROP
        subprocess.run("iptables -P FORWARD DROP", shell=True, check=True)  # Set default policy to DROP
        subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=True)  # Allow all outgoing traffic
        print(f"{Colors.GREEN}All IPTables rules flushed and default policies applied.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error flushing IPTables rules: {str(e)}")

def save_iptables_config():
    """Save the current IPTables configuration and ensure it overwrites the previous one."""
    try:
        subprocess.run("iptables-save > /etc/sysconfig/iptables", shell=True, check=True)
        print(f"{Colors.GREEN}IPTables configuration saved to /etc/sysconfig/iptables.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error saving IPTables configuration: {str(e)}")

def restore_iptables_config():
    """Restore the IPTables configuration from the saved file."""
    try:
        subprocess.run("iptables-restore < /etc/sysconfig/iptables", shell=True, check=True)
        print(f"{Colors.GREEN}IPTables configuration restored from /etc/sysconfig/iptables.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error restoring IPTables configuration: {str(e)}")

def setup_iptables_restore_service():
    """Create or update a systemd service to restore IPTables rules on system boot."""
    try:
        service_file = "/etc/systemd/system/iptables-restore.service"
        service_content = """
[Unit]
Description=Restore iptables rules
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/sbin/iptables-restore /etc/sysconfig/iptables
ExecStop=/usr/sbin/iptables-save > /etc/sysconfig/iptables
ExecReload=/usr/sbin/iptables-restore /etc/sysconfig/iptables
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
        with open(service_file, 'w') as f:
            f.write(service_content)

        # Reload systemd daemon and restart the iptables-restore service
        subprocess.run("systemctl daemon-reload", shell=True, check=True)
        subprocess.run("systemctl enable iptables-restore.service", shell=True, check=True)
        subprocess.run("systemctl restart iptables-restore.service", shell=True, check=True)
        print(f"{Colors.GREEN}IPTables restore service set up and restarted successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error setting up IPTables restore service: {str(e)}")

def monitor_connections_per_ip():
    """Monitor and log the foreign IPs connected to user-specified local ports, with channel labels and total connections."""
    try:
        while True:
            # Get the current connections using netstat
            result = subprocess.run(["netstat", "-ntu"], stdout=subprocess.PIPE, universal_newlines=True)
            connections = result.stdout.splitlines()

            connection_count = defaultdict(set)  # Use a set to ensure unique ports per IP
            channel_totals = { "CH-1": 0, "CH-2": 0, "CH-3": 0, "CH-4": 0 }  # To store total connections per channel
            overall_total_connections = 0  # To store the overall total connections

            # Process the output to capture connections on user-specified local ports
            for line in connections:
                if "ESTABLISHED" in line or "SYN_SENT" in line:
                    # Split the line by spaces to extract relevant info
                    parts = line.split()
                    local_address = parts[3]  # Local Address (example: 145.239.1.51:4585)
                    foreign_address = parts[4]  # Foreign Address (example: 79.117.116.141:23323)
                    
                    # Extract the local port
                    local_ip, local_port = local_address.rsplit(':', 1)

                    # Check if the local port is in the user-specified ports
                    if local_port in CT_PORTS:
                        ip = foreign_address.split(':')[0]  # Extract the IP part of the foreign address
                        if ip not in WHITELISTED_IPS:  # Exclude whitelisted IPs
                            connection_count[ip].add(local_port)  # Use set to avoid duplicate ports

                            # Map the ports to their respective channels and count totals
                            if local_port == '4101':
                                channel_totals["CH-1"] += 1
                            elif local_port == '4102':
                                channel_totals["CH-2"] += 1
                            elif local_port == '4103':
                                channel_totals["CH-3"] += 1
                            elif local_port == '4104':
                                channel_totals["CH-4"] += 1

            # Calculate the overall total connections
            overall_total_connections = sum(channel_totals.values())

            # Log the foreign IPs connected to user-specified local ports
            with open(CONNECTION_LOG, 'a') as f:
                if connection_count:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Foreign IPs connected to user-specified local ports:\n")
                    for ip, ports in connection_count.items():
                        port_labels = []
                        for port in sorted(ports):
                            # Add channel labels based on port
                            if port == '4101':
                                port_labels.append(f"[{port} CH-1]")
                            elif port == '4102':
                                port_labels.append(f"[{port} CH-2]")
                            elif port == '4103':
                                port_labels.append(f"[{port} CH-3]")
                            elif port == '4104':
                                port_labels.append(f"[{port} CH-4]")
                            else:
                                port_labels.append(f"[{port}]")  # For other ports, just show the port number

                        total_connections = len(ports)  # Calculate total unique connections (ports)
                        f.write(f"  {ip}: connected to local ports {', '.join(port_labels)} (Total connections: {total_connections})\n")
                    
                    # Log the total per channel
                    f.write(f"\nTotal connections per channel:\n")
                    f.write(f"  CH-1 (4101): {channel_totals['CH-1']} connections\n")
                    f.write(f"  CH-2 (4102): {channel_totals['CH-2']} connections\n")
                    f.write(f"  CH-3 (4103): {channel_totals['CH-3']} connections\n")
                    f.write(f"  CH-4 (4104): {channel_totals['CH-4']} connections\n")
                    f.write(f"\nOverall total connections: {overall_total_connections}\n\n")
                else:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - No foreign IPs connected to user-specified ports.\n")

            # Log rotation if needed
            rotate_logs()

            # Wait for the next check (e.g., every 3 minutes)
            time.sleep(180)
    except Exception as e:
        log_error(f"Error monitoring connections per IP: {str(e)}")

# ============================ MAIN FUNCTION ============================ #
def main():
    """Main function to start the script and handle errors during startup and runtime."""
    try:
        # Declare global variables at the beginning
        global PROTECTION_LEVEL, ALLOWED_MARIADB_IPS, CT_PORTS, DDOS_THRESHOLD, INITIAL_PROTECTION_LEVEL, CURRENT_PROTECTION_LEVEL, suspicious_activity_count

        display_welcome_message()

        # First, kill existing scripts and install dependencies
        print(f"{Colors.LIGHT_GREEN}Killing any existing script instances...{Colors.RESET}")
        kill_existing_script()
        
        print(f"{Colors.LIGHT_GREEN}Installing necessary dependencies...{Colors.RESET}")
        install_dependencies()

        # Collect inputs from the user
        PROTECTION_LEVEL = show_menu()
        INITIAL_PROTECTION_LEVEL = PROTECTION_LEVEL
        CURRENT_PROTECTION_LEVEL = PROTECTION_LEVEL
        suspicious_activity_count = 0  # Track suspicious activity events

        print(f"{Colors.LIGHT_GREEN}Setting protection level to {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN}.{Colors.RESET}")

        # Set the DDoS threshold based on the selected protection level
        DDOS_THRESHOLD = DDOS_THRESHOLDS[PROTECTION_LEVEL]
        print(f"{Colors.LIGHT_GREEN}DDoS connection threshold set to {Colors.BOLD_WHITE}{DDOS_THRESHOLD}{Colors.LIGHT_GREEN} connections.{Colors.RESET}")

        # Collect allowed MariaDB IPs and ports
        ALLOWED_MARIADB_IPS = get_allowed_mariadb_ips()
        print(f"{Colors.LIGHT_GREEN}Allowed MariaDB IP addresses (including defaults): {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")

        CT_PORTS = get_allowed_ports()
        print(f"{Colors.LIGHT_GREEN}Allowed ports for traffic (including defaults): {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")

        # Flush IPTables rules and apply new settings
        print(f"{Colors.LIGHT_GREEN}Flushing existing IPTables rules...{Colors.RESET}")
        flush_iptables_rules()

        # Apply protection level and setup IPTables
        print(f"{Colors.LIGHT_GREEN}Applying protection level {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN} settings...{Colors.RESET}")
        apply_protection_level(PROTECTION_LEVEL, CT_PORTS)

        print(f"{Colors.LIGHT_GREEN}Setting up IPTables rules...{Colors.RESET}")
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
        
        # Save the IPTables configuration after setting up the rules
        print(f"{Colors.LIGHT_GREEN}Saving IPTables configuration...{Colors.RESET}")
        save_iptables_config()

        # Set up the systemd service to restore IPTables rules on system boot
        print(f"{Colors.LIGHT_GREEN}Setting up IPTables restore service on reboot...{Colors.RESET}")
        setup_iptables_restore_service()

        # Start the background process
        run_in_background()

        # Send an email to notify that the script has started
        email_subject = "DDoS Protection Script Started"
        email_message = f"""
        <html>
        <body>
        <h2>Dear Admins,</h2>
        <p>Block DDoS Automated script has started successfully on Phoenix LC server:</p>
        <ul>
            <li><strong>Protection Level:</strong> {PROTECTION_LEVEL}</li>
            <li><strong>Allowed MariaDB IPs:</strong> {', '.join(ALLOWED_MARIADB_IPS)}</li>
            <li><strong>Allowed Ports:</strong> {', '.join(CT_PORTS)}</li>
        </ul>
        <p>Best regards,<br>Block DDoS Automated System</p>
        </body>
        </html>
        """
        send_email(email_subject, email_message)

        # Automated protection level adjustment based on activity  
        print(f"{Colors.ORANGE}Protection Upgrade Automation ... {Colors.RED}Active!{Colors.RESET}")

        # Start the monitoring threads
        print(f"{Colors.LIGHT_GREEN}Starting log monitoring thread...{Colors.RESET}")
        log_monitor_thread = threading.Thread(target=monitor_logs)

        print(f"{Colors.LIGHT_GREEN}Starting DDoS monitoring thread...{Colors.RESET}")
        ddos_monitor_thread = threading.Thread(target=monitor_ddos)

        # Start monitoring threads for DDoS and level change logs
        print(f"{Colors.LIGHT_GREEN}Starting DDoS log monitoring thread...{Colors.RESET}")
        ddos_log_thread = threading.Thread(target=monitor_ddos_log)

        print(f"{Colors.LIGHT_GREEN}Starting level change log monitoring thread...{Colors.RESET}")
        level_change_log_thread = threading.Thread(target=monitor_level_change_log)

        print(f"{Colors.LIGHT_GREEN}Starting connection monitoring thread...{Colors.RESET}")
        connection_monitor_thread = threading.Thread(target=monitor_connections_per_ip)

        print(f"{Colors.LIGHT_GREEN}Starting all monitoring threads...{Colors.RESET}")
        log_monitor_thread.start()
        ddos_monitor_thread.start()  # DDoS monitoring thread
        ddos_log_thread.start()
        level_change_log_thread.start()
        connection_monitor_thread.start()
        
        # Final message
        print(f"{Colors.ORANGE}Script is running in the background with PID {os.getpid()}. Exiting terminal.{Colors.RESET}")
        print(f"{Colors.YELLOW}=================================================================================================")
        print(f" Security Setup finished! Your server is now protected from DDoS attacks and unauthorized access.")
        print(f"================================================================================================={Colors.RESET}")
        
        while True:
            # Here, we handle only log rotation or other background tasks
            rotate_logs()
            time.sleep(DDOS_MONITOR_INTERVAL)  # Continue rotating logs and any other maintenance tasks
            

    except Exception as e:
        print(f"{Colors.RED}An error occurred in the main function.{Colors.RESET}")
        log_error(f"Error in main: {str(e)}")

if __name__ == "__main__":
    main()
