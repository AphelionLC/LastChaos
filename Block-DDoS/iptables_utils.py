import subprocess
from config import Colors, PROTECTION_LEVELS, CT_PORTS
from logging_utils import log_error

def chunk_ports(port_list, chunk_size=15):
    """Utility function to split ports into chunks of chunk_size to avoid iptables limit."""
    for i in range(0, len(port_list), chunk_size):
        yield port_list[i:i + chunk_size]

def flush_iptables_rules():
    """Flush all existing IPTables rules and set default policies to DROP."""
    try:
        print(f"{Colors.YELLOW}Flushing all existing IPTables rules...{Colors.RESET}")
        subprocess.run("iptables -F", shell=True, check=True)
        subprocess.run("iptables -X", shell=True, check=True)
        subprocess.run("iptables -Z", shell=True, check=True)
        subprocess.run("iptables -P INPUT DROP", shell=True, check=True)
        subprocess.run("iptables -P FORWARD DROP", shell=True, check=True)
        subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=True)
        print(f"{Colors.GREEN}All IPTables rules flushed and default policies applied.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error flushing IPTables rules: {str(e)}")

def apply_iptables_rules(level, allowed_ports, allowed_mariadb_ips):
    """Apply IPTables rules based on the protection level, allowed ports, and configuration."""
    try:
        config = PROTECTION_LEVELS.get(level)
        if not config:
            raise ValueError(f"Invalid protection level: {level}")

        # Flush existing rules
        flush_iptables_rules()

        # Allow all outgoing traffic
        subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=True)

        # Accept loopback traffic (for local processes)
        subprocess.run("iptables -A INPUT -i lo -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A OUTPUT -o lo -j ACCEPT", shell=True, check=True)

        # Allow established/related incoming traffic (ensures response traffic gets through)
        subprocess.run("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", shell=True, check=True)

        # Allow MariaDB access from allowed IPs
        if allowed_mariadb_ips:
            for ip in allowed_mariadb_ips:
                subprocess.run(f"iptables -A INPUT -p tcp --dport 3306 -s {ip} -j ACCEPT", shell=True, check=True)

        # Block all other IPs from accessing MariaDB
        subprocess.run("iptables -A INPUT -p tcp --dport 3306 -j DROP", shell=True, check=True)

        # Allow inbound traffic on user-specified and default ports (chunked to avoid too many ports issue)
        if allowed_ports:
            for port_chunk in chunk_ports(allowed_ports, chunk_size=15):
                ports_str = ','.join(port_chunk)
                subprocess.run(f"iptables -A INPUT -p tcp -m multiport --dports {ports_str} -j ACCEPT", shell=True, check=True)

        # SYN flood protection
        subprocess.run(f"iptables -A INPUT -p tcp --syn -m limit --limit {config['SYNFLOOD_RATE']} --limit-burst {config['SYNFLOOD_BURST']} -j ACCEPT", shell=True, check=True)

        # RST Flood protection
        subprocess.run(f"iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit {config['RST_RATE']} --limit-burst {config['RST_BURST']} -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP", shell=True, check=True)

        # Apply connection limits
        subprocess.run(f"iptables -A INPUT -p tcp -m connlimit --connlimit-above {config['CT_LIMIT']} --connlimit-mask 32 -j REJECT", shell=True, check=True)

        # Apply ICMP rate limiting
        subprocess.run(f"iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {config['ICMP_RATE']} -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p icmp --icmp-type echo-request -j DROP", shell=True, check=True)

        # Apply UDP flood protection
        subprocess.run(f"iptables -A INPUT -p udp -m limit --limit {config['UDP_LIMIT']} -j ACCEPT", shell=True, check=True)
        subprocess.run("iptables -A INPUT -p udp -j DROP", shell=True, check=True)

        # Block invalid packets
        if config['BLOCK_INVALID']:
            subprocess.run("iptables -A INPUT -m state --state INVALID -j DROP", shell=True, check=True)

        # Block all other unspecified ports explicitly
        subprocess.run("iptables -A INPUT -p tcp --syn -j REJECT", shell=True, check=True)

        # Log success message
        print(f"{Colors.GREEN}IPTables rules applied successfully for protection level {level}.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error applying IPTables rules: {str(e)}")

def block_ip(ip, reason):
    """Block an IP using IPTables and drop any established connections."""
    try:
        if ip != "127.0.0.1":
            # Block incoming traffic from the IP
            subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            # Block outgoing traffic to the IP
            subprocess.run(f"iptables -A OUTPUT -d {ip} -j DROP", shell=True, check=True)
            print(f"{Colors.YELLOW}Blocked IP {ip} for reason: {reason}{Colors.RESET}")

            # Drop established connections for this IP using conntrack
            subprocess.run(f"conntrack -D -s {ip}", shell=True, check=True)  # Delete connections initiated by the IP
            subprocess.run(f"conntrack -D -d {ip}", shell=True, check=True)  # Delete connections destined for the IP
            print(f"{Colors.YELLOW}Dropped established connections for IP {ip}{Colors.RESET}")

    except Exception as e:
        log_error(f"Error blocking IP {ip}: {str(e)}")
        print(f"{Colors.RED}Error blocking IP {ip}: {str(e)}{Colors.RESET}")

def unblock_ip(ip):
    """Unblock an IP by removing the corresponding IPTables rule."""
    try:
        subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True, check=True)
        print(f"{Colors.GREEN}Unblocked IP {ip}{Colors.RESET}")
    except Exception as e:
        log_error(f"Error unblocking IP {ip}: {str(e)}")

def terminate_connections(ip):
    """Terminate active connections for a blocked IP using conntrack."""
    try:
        # Use conntrack to delete all connections from the blocked IP
        subprocess.run(f"conntrack -D -s {ip}", shell=True, check=True)
        print(f"Terminated all active connections from {ip}.")
    except subprocess.CalledProcessError as e:
        print(f"Error terminating connections for IP {ip}: {str(e)}")

def save_iptables_config():
    """Save the current IPTables configuration."""
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

        subprocess.run("systemctl daemon-reload", shell=True, check=True)
        subprocess.run("systemctl enable iptables-restore.service", shell=True, check=True)
        subprocess.run("systemctl restart iptables-restore.service", shell=True, check=True)
        print(f"{Colors.GREEN}IPTables restore service set up and restarted successfully.{Colors.RESET}")
    except Exception as e:
        log_error(f"Error setting up IPTables restore service: {str(e)}")