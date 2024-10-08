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
import traceback  # To log the detailed error traceback

# ============================ CONFIGURATION ============================ #
# Protection Level Configuration (1 = lenient, 6 = maximum security)
PROTECTION_LEVELS = {
    1: {
        "description": "Lenient: Higher connection limits, fewer login attempt restrictions",
        "SYNFLOOD_RATE": "700/s",  # Slightly increased SYN rate to allow more traffic
        "SYNFLOOD_BURST": "350",   # Increased burst size
        "CT_LIMIT": 35,            # Increased connection limit per IP
        "CT_BLOCK_TIME": "1800",    # Block time remains the same (30 mins)
        "LF_TRIGGER": 12,           # Increased failed login attempts allowed
        "LOG_MONITOR_INTERVAL": 60, # Same log interval
        "LF_DOS_LIMIT": 1300,       # Slightly higher DOS limit
        "LF_DOS_INTERVAL": 130,     # Increased burst allowance
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 35,            # Increased connection limit
        "PORTFLOOD_BURST": 70,      # Increased burst size for port flooding
        "PORTFLOOD_INTERVAL": 60,   # Same interval
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "320/s",       # Increased UDP packet limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "6/s",          # Increased RST rate limit
        "RST_BURST": "12"           # Increased RST burst size
    },
    2: {
        "description": "Moderate: Balanced protection between performance and security",
        "SYNFLOOD_RATE": "500/s",   # Slightly increased to allow more traffic
        "SYNFLOOD_BURST": "250",
        "CT_LIMIT": 28,             # Slightly increased
        "CT_BLOCK_TIME": "1500",
        "LF_TRIGGER": 8,            # More failed logins allowed
        "LOG_MONITOR_INTERVAL": 50,
        "LF_DOS_LIMIT": 1100,       # Increased DOS limit
        "LF_DOS_INTERVAL": 120,     # Increased burst
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 28,            # Increased connection limit
        "PORTFLOOD_BURST": 55,      # Increased burst size
        "PORTFLOOD_INTERVAL": 60,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "270/s",       # Increased UDP limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "5/s",          # Increased RST limit
        "RST_BURST": "10"
    },
    3: {
        "description": "Medium: Moderate connection limits and failed login restrictions",
        "SYNFLOOD_RATE": "280/s",
        "SYNFLOOD_BURST": "180",
        "CT_LIMIT": 22,             # Slightly more tolerant
        "CT_BLOCK_TIME": "1200",
        "LF_TRIGGER": 6,
        "LOG_MONITOR_INTERVAL": 40,
        "LF_DOS_LIMIT": 800,        # Increased DOS limit
        "LF_DOS_INTERVAL": 90,
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 22,            # Increased limit
        "PORTFLOOD_BURST": 45,      # Increased burst
        "PORTFLOOD_INTERVAL": 90,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "230/s",       # Increased UDP limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "4/s",          # Increased RST rate
        "RST_BURST": "7"
    },
    4: {
        "description": "Strict: Lower connection limits, more frequent log monitoring",
        "SYNFLOOD_RATE": "170/s",   # Increased SYN flood rate
        "SYNFLOOD_BURST": "120",    # Increased burst
        "CT_LIMIT": 17,             # Increased limit
        "CT_BLOCK_TIME": "900",
        "LF_TRIGGER": 4,            # More failed login attempts allowed
        "LOG_MONITOR_INTERVAL": 30,
        "LF_DOS_LIMIT": 650,        # Slightly higher DOS limit
        "LF_DOS_INTERVAL": 65,      # Increased burst
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 17,            # Increased connection limit
        "PORTFLOOD_BURST": 35,      # Increased burst size
        "PORTFLOOD_INTERVAL": 120,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "170/s",       # Increased UDP limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "3/s",
        "RST_BURST": "6"
    },
    5: {
        "description": "Very Strict: Very tight limits, minimal connection bursts allowed",
        "SYNFLOOD_RATE": "120/s",
        "SYNFLOOD_BURST": "60",     # Slightly increased burst
        "CT_LIMIT": 12,             # Increased connection limit
        "CT_BLOCK_TIME": "3600",
        "LF_TRIGGER": 3,            # More failed login attempts allowed
        "LOG_MONITOR_INTERVAL": 20,
        "LF_DOS_LIMIT": 450,        # Increased DOS limit
        "LF_DOS_INTERVAL": 45,      # Increased burst
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 12,            # Slightly increased connection limit
        "PORTFLOOD_BURST": 25,      # Increased burst size
        "PORTFLOOD_INTERVAL": 90,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "120/s",       # Increased UDP limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "2/s",          # Slightly increased RST rate
        "RST_BURST": "4"
    },
    6: {
        "description": "Maximum: Maximum security with ultra-tight restrictions",
        "SYNFLOOD_RATE": "80/s",    # Increased SYN flood rate
        "SYNFLOOD_BURST": "45",     # Increased burst size
        "CT_LIMIT": 9,              # Increased connection limit slightly
        "CT_BLOCK_TIME": "14400",
        "LF_TRIGGER": 2,            # More failed login attempts allowed
        "LOG_MONITOR_INTERVAL": 20,
        "LF_DOS_LIMIT": 350,        # Increased DOS limit
        "LF_DOS_INTERVAL": 35,      # Increased burst size
        "DDOS_MONITOR_INTERVAL": 15,
        "CONNLIMIT": 9,             # Slightly more tolerant connection limit
        "PORTFLOOD_BURST": 18,      # Increased burst size
        "PORTFLOOD_INTERVAL": 60,
        "ICMP_RATE": "1/s",
        "UDP_LIMIT": "80/s",        # Slightly increased UDP limit
        "BLOCK_INVALID": True,
        "BLOCK_DNS": True,
        "RST_RATE": "1/s",          
        "RST_BURST": "3"
    }
}

#==============================================================================================================================

# DDoS Threshold Configuration
DDOS_THRESHOLDS = {
    1: 90,  # Lenient
    2: 80,
    3: 70,
    4: 66,
    5: 62,
    6: 50   # Maximum security
}

# This configuration defines the allowed number of simultaneous connections per IP address
# for each DDoS protection level. The system monitors incoming connections from each IP,
# and if an IP exceeds the threshold defined for the current protection level, it is flagged 
# as suspicious, and appropriate actions (like blocking) are taken.

#How It Works:

# 1. The system monitors the number of connections each IP has to the server using tools 
#    like netstat or ss.
# 2. For each IP, the system checks if the number of connections exceeds the specified threshold 
#    for the active protection level (from 1 to 6).
# 3. If an IP exceeds the threshold for the active level, it is considered a potential DDoS threat, 
#    and further actions such as blocking or upgrading the security level are performed.
# 4. The lower the level, the more connections are allowed per IP; higher levels offer tighter 
#    security with lower connection limits to mitigate potential DDoS attacks.

#===============================================================================================================================

# Initial variables
INITIAL_PROTECTION_LEVEL = None  # Store initial protection level set by the user
CURRENT_PROTECTION_LEVEL = None  # Track current active protection level
DDOS_THRESHOLD = None            # Dynamic DDoS threshold, will change based on protection level
SUSPICIOUS_ACTIVITY_THRESHOLD = 1  # Number of DDoS triggers before upgrading level

# Empty allowed IPs and ports (will be populated by user input)
ALLOWED_MARIADB_IPS = []
DEFAULT_MARIADB_IPS = ["127.0.0.1", "79.116.153.247", "80.194.10.67"]  # Always included
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

RECIPIENTS = {
    "Aphelion LC": ["williamperez1988@hotmail.com", "lewisallum11@gmail.com"],  
    "Phoenix LC": ["williamperez1988@hotmail.com", "lewisallum11@gmail.com"],    
    "Manual Input": ["williamperez1988@hotmail.com", "lewisallum11@gmail.com"] 
}

# ============================ SERVER SELECTION FUNCTION ============================ #
def select_server():
    """Prompt the user to select which server the script is meant to work with."""
    try:
        print(f"\n{Colors.CYAN}==============================================================")
        print(f"             Please select which server to configure")
        print(f"=============================================================={Colors.RESET}")
        print(f"\n  1. {Colors.LIGHT_GREEN}Aphelion Last Chaos{Colors.RESET}")
        print(f"\n  2. {Colors.LIGHT_GREEN}Phoenix Last Chaos{Colors.RESET}")
        print(f"\n  3. {Colors.LIGHT_GREEN}Manual Input (Enter MariaDB IPs and Ports Manually){Colors.RESET}")

        while True:
            try:
                choice = int(input(f"\nEnter the desired server (1, 2, or 3): "))
                if choice == 1:
                    return "Aphelion LC"
                elif choice == 2:
                    return "Phoenix LC"
                elif choice == 3:
                    return "Manual Input"
                else:
                    print(f"{Colors.RED}Invalid input. Please enter 1, 2, or 3.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}Invalid input. Please enter 1, 2, or 3.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error selecting server: {str(e)}")
        return None

# ============================ APPLY SERVER SETTINGS ============================ #
def apply_server_settings(server_name):
    """Apply the MariaDB IPs and ports based on the selected server or user input."""
    global ALLOWED_MARIADB_IPS, CT_PORTS

    if server_name == "Aphelion LC":
        ALLOWED_MARIADB_IPS = ["127.0.0.1", "79.116.153.247", "80.194.10.67", "217.235.140.45", "201.26.55.190", "185.61.137.171"]  # Example IPs for Aphelion LC
        CT_PORTS = ["7843", "10004", "10561", "4585", "5212", "4968", "10005", "10011"] + DEFAULT_PORTS  # Example ports for Aphelion LC plus default ports
        
    elif server_name == "Phoenix LC":
        ALLOWED_MARIADB_IPS = ["127.0.0.1", "79.116.153.247", "80.194.10.67", "185.62.188.4"]  # Example IPs for Phoenix LC
        CT_PORTS = ["7777", "4101", "4102", "4103", "4104"] + DEFAULT_PORTS  # Example ports for Phoenix LC plus default ports
        
    elif server_name == "Manual Input":
        # Only for Manual Input, prompt the user for MariaDB IPs and ports
        ip_input = input("Enter the IP addresses allowed to connect to MariaDB (separated by commas): ")
        if ip_input:
            ALLOWED_MARIADB_IPS = [ip.strip() for ip in ip_input.split(',')]  # Split and remove spaces
        else:
            ALLOWED_MARIADB_IPS = DEFAULT_MARIADB_IPS  # Use default if no input
        
        port_input = input("Enter the ports to protect (separated by commas): ")
        if port_input:
            CT_PORTS = [port.strip() for port in port_input.split(',')] + DEFAULT_PORTS  # User input ports plus default ports
        else:
            CT_PORTS = DEFAULT_PORTS  # Use default if no input
    else:
        log_error("Invalid server name selected.")
        return

    print(f"{Colors.LIGHT_GREEN}Server {server_name} selected.{Colors.RESET}")
    print(f"{Colors.LIGHT_GREEN}Allowed MariaDB IPs: {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")
    print(f"{Colors.LIGHT_GREEN}Allowed ports: {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")



# ============================ EMAIL FUNCTION ============================ #
def send_email(server_name, subject, message):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ', '.join(RECIPIENTS[server_name])  # Send email based on the selected server
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'html'))

        server.sendmail(SENDER_EMAIL, RECIPIENTS[server_name], msg.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print("Error sending email:", str(e))

# ============================ MONITOR LOGS FOR EMAIL ============================ #
def monitor_ddos_log(server_name):
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
                    email_subject = f"DDoS Activity Detected on {server_name} Server"
                    email_message = f"""
                    <html>
                    <body>
                    <h2>Dear Admins,</h2>
                    <p>We detected a potential DDoS attack on {server_name} server:</p>
                    <p><strong>{line}</strong></p>
                    <p>Best regards,<br>Block DDoS Automated System</p>
                    </body>
                    </html>
                    """
                    send_email(server_name, email_subject, email_message)

def monitor_level_change_log(server_name):
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
                email_subject = f"Protection Level Changed on {server_name} Server"
                email_message = f"""
                <html>
                <body>
                <h2>Dear Admins,</h2>
                <p>The protection level on {server_name} server has changed:</p>
                <p><strong>{line}</strong></p>
                <p>Best regards,<br>Block DDoS Automated System</p>
                </body>
                </html>
                """
                send_email(server_name, email_subject, email_message)

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
        log_level_change(old_level, CURRENT_PROTECTION_LEVEL, "Suspicious activity not detected")


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

        # Set the new protection level parameters
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

        # Reapply previously blocked IPs from the log after the rules are flushed
        reapply_blocked_ips()

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

        # Reapply previously blocked IPs before applying any accept rules
        reapply_blocked_ips()

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
            for port_chunk in chunk_ports(CT_PORTS, chunk_size=15):
                ports_str = ','.join(port_chunk)
                subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {ports_str} -j ACCEPT", shell=True, check=True)

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

        # --- NEW RULES ---

        # Drop packets with suspicious TCP flags
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP", shell=True, check=True)

        # Block non-routable IP ranges (e.g., private IPs)
        subprocess.run("iptables -A INPUT -s 224.0.0.0/3 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 169.254.0.0/16 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 172.16.0.0/12 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 192.0.2.0/24 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 192.168.0.0/16 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 10.0.0.0/8 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 0.0.0.0/8 -j DROP", shell=True, check=True)
        subprocess.run("iptables -A INPUT -s 240.0.0.0/5 -j DROP", shell=True, check=True)

        # Port scanning protection
        subprocess.run("iptables -N port-scanning", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN", shell=True, check=True)
        subprocess.run("iptables -A port-scanning -j DROP", shell=True, check=True)

    except Exception as e:
        log_error(f"Error setting up iptables: {str(e)}")

def prompt_block_countries():
    """Prompt the user to block specific countries and return the list of blocked countries."""
    BLOCKED_COUNTRIES = ['VN', 'IR', 'KP', 'CN', 'RU']  # Vietnam, Iran, North Korea, China, Russia
    block_countries_input = input(f"{Colors.LIGHT_GREEN}Do you want to block traffic from the following countries: {Colors.BOLD_WHITE}{', '.join(BLOCKED_COUNTRIES)}{Colors.LIGHT_GREEN}? (y/n): {Colors.RESET}").strip().lower()

    if block_countries_input == 'y':
        # Proceed with blocking traffic from the specified countries
        print(f"{Colors.LIGHT_GREEN}Proceeding to block traffic from the following countries: {Colors.BOLD_WHITE}{', '.join(BLOCKED_COUNTRIES)}{Colors.RESET}")
        block_countries(BLOCKED_COUNTRIES)  # Apply block
        return BLOCKED_COUNTRIES
    elif block_countries_input == 'n':
        print(f"{Colors.LIGHT_GREEN}Skipping country blocking as per user choice.{Colors.RESET}")
        flush_countryblock_if_needed()  # Only flush if there are existing entries
        return None
    else:
        print(f"{Colors.RED}Invalid input. Please enter 'y' for yes or 'n' for no.{Colors.RESET}")
        return None


def block_countries(countries):
    """
    Block traffic from specified countries using ipset and iptables.
    :param countries: List of ISO country codes (e.g., ['CN', 'RU'] for China and Russia)
    """
    try:
        if not countries:
            print(f"{Colors.YELLOW}No countries to block.{Colors.RESET}")
            return

        # Flush and apply new blocklists
        flush_countryblock()

        for country in countries:
            zone_file = f"/tmp/{country}.zone"
            if os.path.exists(zone_file):
                print(f"{Colors.GREEN}Adding IP ranges for country {country} from {zone_file} to blocklist...{Colors.RESET}")
                ipset_add_command = f"for ip in $(cat {zone_file}); do ipset add countryblock $ip; done"
                subprocess.run(ipset_add_command, shell=True, check=True)
            else:
                print(f"{Colors.RED}Error: Blocklist for {country} not found at {zone_file}.{Colors.RESET}")

        # Apply the IPSet to IPTables rules
        subprocess.run("iptables -I INPUT -m set --match-set countryblock src -j DROP", shell=True, check=True)
        print(f"{Colors.GREEN}GeoIP blocking for countries {', '.join(countries)} applied.{Colors.RESET}")

    except Exception as e:
        log_error(f"Error blocking countries: {str(e)}")


def flush_countryblock_if_needed():
    """
    Flush the existing ipset 'countryblock' only if there are entries.
    This is called if the user decides not to block countries but we need to clear previous settings.
    """
    try:
        # Check if ipset exists and if it has entries
        result = subprocess.run("ipset list countryblock", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ipset_exists = result.returncode == 0

        if ipset_exists:
            # Check if there are entries in the ipset
            entries_result = subprocess.run("ipset list countryblock | grep 'Number of entries: 0'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            has_entries = entries_result.returncode != 0  # True if there are entries

            if has_entries:
                print(f"{Colors.YELLOW}Flushing existing ipset 'countryblock'...{Colors.RESET}")
                subprocess.run("ipset flush countryblock", shell=True, check=True)  # Flush existing ipset
            else:
                print(f"{Colors.YELLOW}No entries found in 'countryblock', skipping flush.{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}No 'countryblock' ipset found, skipping flush.{Colors.RESET}")

    except Exception as e:
        log_error(f"Error flushing countryblock: {str(e)}")


def flush_countryblock():
    """Flush the 'countryblock' ipset without checking if there are entries (used during blocking)."""
    try:
        result = subprocess.run("ipset list countryblock", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ipset_exists = result.returncode == 0

        if ipset_exists:
            print(f"{Colors.YELLOW}Flushing existing ipset 'countryblock'...{Colors.RESET}")
            subprocess.run("ipset flush countryblock", shell=True, check=True)  # Flush existing ipset
        else:
            print(f"{Colors.YELLOW}Creating new ipset 'countryblock'...{Colors.RESET}")
            subprocess.run("ipset create countryblock hash:net", shell=True, check=True)  # Create new ipset if not present
    except Exception as e:
        log_error(f"Error flushing countryblock: {str(e)}")


def block_ip(ip, reason):
    """
    Block an IP using iptables and log the process if the IP is not already blocked.
    
    Args:
        ip (str): The IP address to block.
        reason (str): The reason for blocking the IP.
    """
    log_ddos_monitor(f"Attempting to block IP {ip} for reason: {reason}")

    try:
        # Ensure the script is running with root privileges
        if os.geteuid() != 0:
            log_error(f"Script is not running as root. Cannot block IP {ip}.")
            return

        # Refined check to see if the IP is already blocked in iptables
        check_ip_command = f"iptables -C INPUT -s {ip} -j DROP"
        check_result = subprocess.run(check_ip_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # If the IP is not blocked (returns non-zero exit code), block the IP
        if check_result.returncode != 0:
            # Use '-I' instead of '-A' to insert the rule at the top
            iptables_command = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            log_ddos_monitor(f"Running command to block IP: {' '.join(iptables_command)}")

            # Execute the iptables command to block the IP
            block_result = subprocess.run(iptables_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Log the results or any errors from the iptables command
            if block_result.stdout:
                log_ddos_monitor(f"iptables output: {block_result.stdout.strip()}")
            if block_result.stderr:
                log_error(f"iptables error: {block_result.stderr.strip()}")

            log_ddos_monitor(f"Successfully blocked IP {ip} for {reason}")
            log_blocked_ip(ip, reason)  # Log the blocked IP
        else:
            log_ddos_monitor(f"IP {ip} is already blocked. Skipping block operation.")

    except subprocess.CalledProcessError as e:
        log_error(f"Error occurred while trying to block IP {ip}: {str(e)}")
    except Exception as e:
        log_error(f"Unexpected error when trying to block IP {ip}: {str(e)}")

def load_blocked_ips_from_log():
    """Load blocked IPs from the blocked_ips.log file."""
    blocked_ips = set()  # Use a set to avoid duplicates
    try:
        if os.path.exists(BLOCKED_IP_LOG):
            with open(BLOCKED_IP_LOG, 'r') as f:
                for line in f:
                    # Assume the log format contains "Blocked IP: <ip>"
                    match = re.search(r"Blocked IP: (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        blocked_ips.add(match.group(1))
    except Exception as e:
        log_error(f"Error loading blocked IPs from log: {str(e)}")
    return list(blocked_ips)

def reapply_blocked_ips():
    """Reapply all blocked IPs after flushing iptables rules."""
    blocked_ips = load_blocked_ips_from_log()  # Load blocked IPs from the log
    for ip in blocked_ips:
        try:
            block_ip(ip, "Reapplying previously blocked IP")
        except Exception as e:
            log_error(f"Error reapplying blocked IP {ip}: {str(e)}")


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

    server_ips = ["145.239.1.51", "51.89.99.95"]  # Example list of server IPs
    blocked_ips_cache = set()  # Cache to keep track of blocked IPs

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
                        if ip != "127.0.0.1" and ip not in server_ips:  # Skip localhost and all server IPs
                            tcp_established_count[ip] += 1
                    elif len(split_line) >= 5 and "SYN_RECV" in split_line[-1]:
                        ip = split_line[4].split(':')[0]
                        if ip != "127.0.0.1" and ip not in server_ips:  # Skip localhost and all server IPs
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
                        if ip != "127.0.0.1" and ip not in server_ips:  # Skip localhost and all server IPs
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
                        if ip != "127.0.0.1" and ip not in server_ips:  # Skip localhost and all server IPs
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
                    if count > DDOS_THRESHOLD and ip not in blocked_ips_cache:  # Check if not already blocked
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential DDoS attack (TCP ESTABLISHED connections exceeded)")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive TCP ESTABLISHED connections")
                        blocked_ips.append(ip)
                        blocked_ips_cache.add(ip)  # Add to cache to prevent repeated blocking

            # Check for excessive SYN_RECV connections
            for ip, count in syn_recv_count.items():
                if log_proximity(ip, count, syn_threshold, "SYN_RECV"):
                    if count > syn_threshold and ip not in blocked_ips_cache:  # Check if not already blocked
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential SYN flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive SYN_RECV connections")
                        blocked_ips.append(ip)
                        blocked_ips_cache.add(ip)  # Add to cache to prevent repeated blocking

            # Check for excessive UDP connections
            for ip, count in udp_count.items():
                if log_proximity(ip, count, udp_threshold, "UDP"):
                    if count > udp_threshold and ip not in blocked_ips_cache:  # Check if not already blocked
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential UDP flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive UDP connections")
                        blocked_ips.append(ip)
                        blocked_ips_cache.add(ip)  # Add to cache to prevent repeated blocking

            # Check for excessive ICMP connections
            for ip, count in icmp_count.items():
                if log_proximity(ip, count, icmp_threshold, "ICMP"):
                    if count > icmp_threshold and ip not in blocked_ips_cache:  # Check if not already blocked
                        suspicious_activity_detected = True
                        block_ip(ip, "Potential ICMP flood attack")
                        log_ddos_monitor(f"Blocked IP {ip} for excessive ICMP connections")
                        blocked_ips.append(ip)
                        blocked_ips_cache.add(ip)  # Add to cache to prevent repeated blocking

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

            time.sleep(DDOS_MONITOR_INTERVAL)  # Adjust the interval here (e.g., 10 or 15 seconds)

    except Exception as e:
        log_error(f"Error monitoring DDoS: {str(e)}")

def monitor_ddos_with_restarts():
    """Monitor DDoS attacks and automatically restart the function in case of errors."""
    while True:
        try:
            monitor_ddos()  # Run the DDoS monitoring function
        except Exception as e:
            log_error(f"Error monitoring DDoS: {str(e)}")
            log_error(traceback.format_exc())  # Log the detailed traceback for debugging
            print(f"{Colors.RED}Error in DDoS monitoring: {str(e)}. Restarting monitor...{Colors.RESET}")
            time.sleep(5)  # Sleep for 5 seconds before restarting the monitoring function
     
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
import os

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

    try:
        # Install ipset (used to manage sets of IP addresses)
        ipset_installed = subprocess.run("command -v ipset", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ipset_installed.returncode == 0:
            print(f"{Colors.GREEN}ipset is already installed.{Colors.RESET}")
        else:
            print(f"{Colors.RED}ipset is not installed. Installing ipset...{Colors.RESET}")
            subprocess.run("yum install -y ipset", shell=True, check=True)
            print(f"{Colors.GREEN}ipset installed successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error installing ipset: {str(e)}")

    try:
        # Download IP blocklists for specific countries, but only if the files don't exist already
        print(f"{Colors.YELLOW}Checking if country-specific IP blocklists are already downloaded...{Colors.RESET}")
        
        # Define countries and their blocklist URLs
        countries = {
            "IN": "https://www.ipdeny.com/ipblocks/data/countries/in.zone",
            "VN": "https://www.ipdeny.com/ipblocks/data/countries/vn.zone",
            "IR": "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
            "KP": "https://www.ipdeny.com/ipblocks/data/countries/kp.zone",
            "CN": "https://www.ipdeny.com/ipblocks/data/countries/cn.zone",
            "RU": "https://www.ipdeny.com/ipblocks/data/countries/ru.zone",
            "TH": "https://www.ipdeny.com/ipblocks/data/countries/th.zone"
        }

        for country, url in countries.items():
            file_path = f"/tmp/{country}.zone"
            
            # Check if the blocklist file already exists
            if os.path.exists(file_path):
                print(f"{Colors.GREEN}IP blocklist for {country} already exists, skipping download.{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}Downloading IP blocklist for {country}...{Colors.RESET}")
                subprocess.run(f"wget -O {file_path} {url}", shell=True, check=True)
                print(f"{Colors.GREEN}Downloaded IP blocklist for {country}.{Colors.RESET}")
    
    except Exception as e:
        log_error(f"Error downloading IP blocklists: {str(e)}")

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

def flush_ipset():
    """Flush all existing ipset sets to remove old entries."""
    try:
        print(f"{Colors.YELLOW}Flushing all existing ipset sets...{Colors.RESET}")
        # List and flush all existing sets
        result = subprocess.run("ipset list -n", shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        sets = result.stdout.splitlines()

        for ipset_name in sets:
            subprocess.run(f"ipset flush {ipset_name}", shell=True, check=True)  # Flush each set
            subprocess.run(f"ipset destroy {ipset_name}", shell=True, check=True)  # Destroy each set

        print(f"{Colors.GREEN}All ipset sets flushed and destroyed.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error flushing ipset: {str(e)}")

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

def monitor_connections_per_ip(server_name):
    """Monitor and log the foreign IPs connected to user-specified local ports, with channel labels and total connections."""
    try:
        # Select the correct ports and channels based on the server
        if server_name == "Aphelion LC":
            server_ports = ["7843", "4585", "5212", "4968"]  # Aphelion ports
            channel_mapping = {
                "4585": "CH-1",
                "4968": "CH-2",
                "5212": "CH-3",
                "7843": "CH-4"
            }
        elif server_name == "Phoenix LC":
            server_ports = ["4101", "4102", "4103", "4104"]  # Phoenix ports
            channel_mapping = {
                "4101": "CH-1",
                "4102": "CH-2",
                "4103": "CH-3",
                "4104": "CH-4"
            }
        else:  # For Manual Input, use CT_PORTS (which contains the ports defined by the user)
            server_ports = CT_PORTS
            channel_mapping = {port: f"CH-{i+1}" for i, port in enumerate(CT_PORTS)}

        while True:
            # Get the current connections using netstat
            result = subprocess.run(["netstat", "-ntu"], stdout=subprocess.PIPE, universal_newlines=True)
            connections = result.stdout.splitlines()

            connection_count = defaultdict(set)  # Use a set to ensure unique ports per IP
            channel_totals = {channel: 0 for channel in channel_mapping.values()}  # To store total connections per channel
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

                    # Check if the local port is in the user-specified ports for the selected server
                    if local_port in server_ports:
                        ip = foreign_address.split(':')[0]  # Extract the IP part of the foreign address
                        if ip not in WHITELISTED_IPS:  # Exclude whitelisted IPs
                            connection_count[ip].add(local_port)  # Use set to avoid duplicate ports

                            # Map the ports to their respective channels and count totals
                            channel = channel_mapping.get(local_port, f"CH-{local_port}")
                            channel_totals[channel] += 1

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
                            port_labels.append(f"[{port} {channel_mapping.get(port, '')}]")

                        total_connections = len(ports)  # Calculate total unique connections (ports)
                        f.write(f"  {ip}: connected to local ports {', '.join(port_labels)} (Total connections: {total_connections})\n")
                    
                    # Log the total per channel
                    f.write(f"\nTotal connections per channel:\n")
                    for channel, total in channel_totals.items():
                        f.write(f"  {channel}: {total} connections\n")
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

        # Select the server to configure
        server_name = select_server()  # Use the select_server() function to get the user's choice
        
        # Apply settings based on server choice (Aphelion LC, Phoenix LC, or Manual Input)
        apply_server_settings(server_name)

        # Choose the protection level
        PROTECTION_LEVEL = show_menu()
        INITIAL_PROTECTION_LEVEL = PROTECTION_LEVEL
        CURRENT_PROTECTION_LEVEL = PROTECTION_LEVEL
        suspicious_activity_count = 0  # Track suspicious activity events

        print(f"{Colors.LIGHT_GREEN}Setting protection level to {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN}.{Colors.RESET}")

        # Set the DDoS threshold based on the selected protection level
        DDOS_THRESHOLD = DDOS_THRESHOLDS[PROTECTION_LEVEL]
        print(f"{Colors.LIGHT_GREEN}DDoS connection threshold set to {Colors.BOLD_WHITE}{DDOS_THRESHOLD}{Colors.LIGHT_GREEN} connections.{Colors.RESET}")

        # For Manual Input only: Ask for MariaDB IPs and ports
        if server_name == "Manual Input":
            print(f"{Colors.LIGHT_GREEN}Enter the IP addresses allowed to connect to MariaDB (separated by commas):{Colors.RESET}")
            ALLOWED_MARIADB_IPS = get_allowed_mariadb_ips()
            print(f"{Colors.LIGHT_GREEN}Allowed MariaDB IP addresses (including defaults): {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")

            print(f"{Colors.LIGHT_GREEN}Enter additional ports to protect (separated by commas):{Colors.RESET}")
            CT_PORTS = get_allowed_ports()
            print(f"{Colors.LIGHT_GREEN}Allowed ports for traffic (including defaults): {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")
        
        # Prompt to block countries
        blocked_countries = prompt_block_countries()

        print(f"{Colors.LIGHT_GREEN}Flushing existing IPTables rules...{Colors.RESET}")
        flush_iptables_rules()

        # Apply protection level and setup IPTables
        print(f"{Colors.LIGHT_GREEN}Applying protection level {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN} settings...{Colors.RESET}")
        apply_protection_level(PROTECTION_LEVEL, CT_PORTS)

        print(f"{Colors.LIGHT_GREEN}Setting up IPTables rules...{Colors.RESET}")
        setup_iptables()

        # IPTables setup details in light green with numbers in bold white
        print(f"{Colors.LIGHT_GREEN}Applying Protection Level: {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowing loopback traffic...{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Allowing MariaDB access from IP: {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Blocking all other IPs from accessing MariaDB on port 3306...{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying SYN flood protection: {Colors.BOLD_WHITE}{SYNFLOOD_RATE}{Colors.LIGHT_GREEN}, burst {Colors.BOLD_WHITE}{SYNFLOOD_BURST}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying ICMP rate limit: {Colors.BOLD_WHITE}{ICMP_RATE}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Applying UDP flood protection limit: {Colors.BOLD_WHITE}{UDP_LIMIT}{Colors.RESET}")
        print(f"{Colors.LIGHT_GREEN}Blocking invalid packets...{Colors.RESET}")

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
        email_subject = f"{server_name} - DDoS Protection Script Started"
        blocked_countries_str = ', '.join(blocked_countries) if blocked_countries else "None"

        email_message = f"""
        <html>
        <body>
        <h2>Dear Admins,</h2>
        <p>Block DDoS Automated script has started successfully on {server_name} server:</p>
        <ul>
            <li><strong>Protection Level:</strong> {PROTECTION_LEVEL}</li>
            <li><strong>Allowed MariaDB IPs:</strong> {', '.join(ALLOWED_MARIADB_IPS)}</li>
            <li><strong>Allowed Ports:</strong> {', '.join(CT_PORTS)}</li>
            <li><strong>Blocked Countries:</strong> {blocked_countries_str}</li>
        </ul>
        <p>Best regards,<br>Block DDoS Automated System</p>
        </body>
        </html>
        """
        send_email(server_name, email_subject, email_message)

        # Automated protection level adjustment based on activity  
        print(f"{Colors.ORANGE}Protection Upgrade Automation ... {Colors.RED}Active!{Colors.RESET}")

        # Start the monitoring threads with the server_name argument
        log_monitor_thread = threading.Thread(target=monitor_logs)
        ddos_monitor_thread = threading.Thread(target=monitor_ddos_with_restarts)
        ddos_log_thread = threading.Thread(target=monitor_ddos_log, args=(server_name,))
        level_change_log_thread = threading.Thread(target=monitor_level_change_log, args=(server_name,))
        connection_monitor_thread = threading.Thread(target=monitor_connections_per_ip, args=(server_name,))

        # Start threads
        log_monitor_thread.start()
        ddos_monitor_thread.start()
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
