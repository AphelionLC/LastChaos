import os

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

# DDoS thresholds for each protection level
DDOS_THRESHOLDS = {
    1: 110,
    2: 108,
    3: 106,
    4: 104,
    5: 102,
    6: 100
}

# Initial variables
INITIAL_PROTECTION_LEVEL = None
CURRENT_PROTECTION_LEVEL = None
DDOS_THRESHOLD = None
SUSPICIOUS_ACTIVITY_THRESHOLD = 3

# Empty allowed IPs and ports (will be populated by user input)
ALLOWED_MARIADB_IPS = []
DEFAULT_MARIADB_IPS = ["127.0.0.1", "79.117.116.141", "80.194.10.67", "185.62.188.4"]
CT_PORTS = []

# Default allowed ports
DEFAULT_PORTS = ["20", "22", "25", "53", "80", "110", "143", "443", "7777", "4101", "4102", "4103", "4104"]

# Log files
SCRIPT_DIR = os.getcwd()
SECURITY_DIR = os.path.join(SCRIPT_DIR, "1-Security-Bot")
BLOCKED_IP_LOG = os.path.join(SECURITY_DIR, "blocked_ips.log")
ATTEMPTED_CONNECTIONS_LOG = os.path.join(SECURITY_DIR, "connection_attempts.log")
DDOS_MONITOR_LOG = os.path.join(SECURITY_DIR, "DDoS-Monitor.log")
ERROR_LOG = os.path.join(SECURITY_DIR, "error.log")
LEVEL_CHANGE_LOG = os.path.join(SECURITY_DIR, "level_change.log")

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "aphelionlc.status@gmail.com"
SENDER_PASSWORD = "rucrdxslwkkzmkcn"
RECIPIENT_EMAILS = ["williamperez1988@hotmail.com", "lewisallum11@gmail.com"]

# Add your server's IP here
WHITELISTED_IPS = ["127.0.0.1"]

# Color codes
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    LIGHT_GREEN = "\033[92m"
    LIGHT_RED = "\033[91m"
    ORANGE = "\033[38;5;214m"
    BOLD_WHITE = "\033[1;37m"
