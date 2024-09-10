import os
import time
import threading
from collections import defaultdict
import subprocess
import psutil
from config import (
    Colors, PROTECTION_LEVELS, DDOS_THRESHOLDS, INITIAL_PROTECTION_LEVEL,
    CURRENT_PROTECTION_LEVEL, DDOS_THRESHOLD, SUSPICIOUS_ACTIVITY_THRESHOLD,
    ALLOWED_MARIADB_IPS, DEFAULT_MARIADB_IPS, CT_PORTS, DEFAULT_PORTS, WHITELISTED_IPS
)
from email_utils import notify_script_start, notify_ddos_activity, notify_level_change
from iptables_utils import (
    flush_iptables_rules, save_iptables_config, restore_iptables_config,
    setup_iptables_restore_service, apply_iptables_rules, block_ip, unblock_ip
)
from logging_utils import (
    init_logging, log_error, log_blocked_ip, log_connection_attempt,
    log_ddos_monitor, log_level_change, rotate_logs, extract_ip_from_log
)

# Global variables
blocked_ips = defaultdict(int)
failed_attempts = defaultdict(int)
suspicious_activity_count = 0
blocked_ips_set = set()

def retry_on_io_error(function, retries=3, delay=2):
    """Decorator to retry function on IOError."""
    def wrapper(*args, **kwargs):
        for attempt in range(retries):
            try:
                return function(*args, **kwargs)
            except (OSError, IOError) as e:
                log_error(f"I/O Error encountered: {str(e)}. Retrying ({attempt+1}/{retries})...")
                time.sleep(delay)
        log_error(f"Failed after {retries} attempts due to I/O error.")
        raise Exception("Maximum retries reached due to I/O error.")
    return wrapper

def display_welcome_message():
    """Display a welcome message with script details."""
    print(f"""\n{Colors.GREEN}
    =============================================================
                 WELCOME TO THE DDoS PROTECTION SCRIPT  
    =============================================================
    {Colors.RESET}
    This script will help you configure your server's security
    with multiple protection levels to guard against DDoS attacks.
    Let's get started!\n
    """)

def show_menu():
    """Display the protection level menu and validate user input."""
    print(f"\n{Colors.CYAN}Choose a protection level:{Colors.RESET}")
    level_colors = [Colors.CYAN, Colors.GREEN, Colors.YELLOW, Colors.BLUE, Colors.LIGHT_RED, Colors.RED]
    for level, config in PROTECTION_LEVELS.items():
        color = level_colors[level - 1]
        print(f"  {color}{level}. {config['description']}{Colors.RESET}")

    while True:
        try:
            choice = int(input("\nEnter the desired protection level (1-6): "))
            if 1 <= choice <= 6:
                return choice
            else:
                print(f"{Colors.RED}Invalid input. Please enter a number between 1 and 6.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number between 1 and 6.{Colors.RESET}")

def get_allowed_mariadb_ips():
    """Prompt the user to input allowed MariaDB IPs."""
    ip_input = input(f"{Colors.CYAN}Enter additional IP addresses allowed to connect to MariaDB (comma-separated): {Colors.RESET}")
    if ip_input:
        user_ips = [ip.strip() for ip in ip_input.split(',')]
        return list(set(DEFAULT_MARIADB_IPS + user_ips))
    return DEFAULT_MARIADB_IPS

def get_allowed_ports():
    """Prompt the user to input additional allowed ports."""
    port_input = input(f"{Colors.CYAN}Enter additional ports to protect (comma-separated): {Colors.RESET}")
    if port_input:
        user_ports = [port.strip() for port in port_input.split(',')]
        return list(set(DEFAULT_PORTS + user_ports))
    return DEFAULT_PORTS

def adjust_protection_level(activity):
    """Automatically upgrade or downgrade protection level based on activity."""
    global CURRENT_PROTECTION_LEVEL, INITIAL_PROTECTION_LEVEL
    old_level = CURRENT_PROTECTION_LEVEL

    if activity == "upgrade" and CURRENT_PROTECTION_LEVEL < 6:
        CURRENT_PROTECTION_LEVEL += 1
        print(f"{Colors.LIGHT_GREEN}Upgrading protection level to {Colors.BOLD_WHITE}{CURRENT_PROTECTION_LEVEL}{Colors.RESET} due to suspicious activity.")
    elif activity == "downgrade" and CURRENT_PROTECTION_LEVEL > INITIAL_PROTECTION_LEVEL:
        CURRENT_PROTECTION_LEVEL = INITIAL_PROTECTION_LEVEL
        print(f"{Colors.LIGHT_GREEN}Downgrading protection level back to the user-set level {Colors.BOLD_WHITE}{INITIAL_PROTECTION_LEVEL}{Colors.RESET} due to lower activity.")

    if old_level != CURRENT_PROTECTION_LEVEL:
        apply_iptables_rules(CURRENT_PROTECTION_LEVEL, CT_PORTS, ALLOWED_MARIADB_IPS)
        log_level_change(old_level, CURRENT_PROTECTION_LEVEL, "Automatic adjustment")
        notify_level_change(old_level, CURRENT_PROTECTION_LEVEL)

def monitor_logs():
    """Monitor /var/log/secure for SSH attempts."""
    secure_log = "/var/log/secure"
    secure_position = 0

    if os.path.exists(secure_log):
        with open(secure_log, 'r') as f:
            f.seek(0, os.SEEK_END)  # Start reading from the end of the file
            secure_position = f.tell()

    while True:
        try:
            with open(secure_log, 'r') as f:
                f.seek(secure_position)
                lines = f.readlines()
                secure_position = f.tell()

                for line in lines:
                    if not line.strip():  # Skip empty or malformed lines
                        continue

                    if "sshd" in line and ("Failed password" in line or "Accepted password" in line):
                        log_connection_attempt(line)
                        ip = extract_ip_from_log(line)

                        if ip and "Failed password" in line:
                            failed_attempts[ip] += 1
                            if failed_attempts[ip] >= PROTECTION_LEVELS[CURRENT_PROTECTION_LEVEL]['LF_TRIGGER']:
                                if ip not in blocked_ips_set:
                                    block_ip(ip, "Failed SSH attempts")
                                    log_blocked_ip(ip, "Failed SSH attempts")
                                    blocked_ips_set.add(ip)
        except (OSError, IOError) as e:
            log_error(f"I/O Error monitoring logs: {str(e)}")
            print(f"{Colors.RED}I/O Error monitoring logs: {str(e)}{Colors.RESET}")
        except Exception as e:
            log_error(f"Error monitoring logs: {str(e)}")
            print(f"{Colors.RED}Error monitoring logs: {str(e)}{Colors.RESET}")
        
        time.sleep(PROTECTION_LEVELS[CURRENT_PROTECTION_LEVEL]['LOG_MONITOR_INTERVAL'])

def monitor_ddos():
    """Monitor for potential DDoS attacks."""
    global suspicious_activity_count
    while True:
        try:
            log_ddos_monitor("Checking for DDoS activity...")
            result = subprocess.run(["netstat", "-ant"], stdout=subprocess.PIPE, universal_newlines=True)
            connections = result.stdout.splitlines()

            connection_count = defaultdict(int)
            for line in connections:
                if "ESTABLISHED" in line:
                    ip = line.split()[4].split(':')[0]
                    connection_count[ip] += 1

            suspicious_activity_detected = False
            for ip, count in connection_count.items():
                if ip not in WHITELISTED_IPS and count > DDOS_THRESHOLD:
                    suspicious_activity_detected = True
                    if ip not in blocked_ips_set:  # Block IP if not already blocked
                        blocked_ips_set.add(ip)  # Add IP to blocked set
                        block_ip(ip, "Potential DDoS attack")
                        log_blocked_ip(ip, "Potential DDoS attack")
                        log_ddos_monitor(f"Blocked IP {ip} for potential DDoS attack")
                        notify_ddos_activity(f"Potential DDoS attack from IP: {ip}, Connection count: {count}")

            if suspicious_activity_detected:
                suspicious_activity_count += 1
                print(f"Suspicious activity detected! Count: {suspicious_activity_count}")
                if suspicious_activity_count >= SUSPICIOUS_ACTIVITY_THRESHOLD:
                    adjust_protection_level("upgrade")
                    suspicious_activity_count = 0  # Reset after upgrade
            else:
                if suspicious_activity_count > 0:
                    suspicious_activity_count -= 1
                adjust_protection_level("downgrade")
                blocked_ips_set.clear()  # Clear the set after downgrading

        except Exception as e:
            log_error(f"Error monitoring DDoS: {str(e)}")
        
        time.sleep(PROTECTION_LEVELS[CURRENT_PROTECTION_LEVEL]['DDOS_MONITOR_INTERVAL'])

def kill_existing_script():
    """Check if the script is already running and kill it if found."""
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if proc.info['name'] in ['python', 'python3'] and 'main_script.py' in proc.info['cmdline'][1]:
            if proc.info['pid'] != current_pid:
                proc.terminate()
                proc.wait()

def install_dependencies():
    """Check and install necessary dependencies."""
    # Check if psutil is installed
    try:
        import psutil
        print(f"{Colors.GREEN}psutil is already installed.{Colors.RESET}")
    except ImportError:
        print(f"{Colors.RED}psutil is not installed. Installing...{Colors.RESET}")
        subprocess.run("pip install psutil", shell=True, check=True)
        print(f"{Colors.GREEN}psutil installed successfully.{Colors.RESET}")

    # List of system dependencies to check and install
    packages = {
        "net-tools": "net-tools",
        "iptables": "iptables",
        "conntrack-tools": "conntrack-tools"
    }

    for package, install_name in packages.items():
        # Check if the package is already installed using rpm -q
        package_check = subprocess.run(f"rpm -q {install_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if package_check.returncode != 0:
            print(f"{Colors.RED}{package} is not installed. Installing...{Colors.RESET}")
            subprocess.run(f"yum install -y {install_name}", shell=True, check=True)
            print(f"{Colors.GREEN}{package} installed successfully.{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}{package} is already installed.{Colors.RESET}")

def run_in_background():
    """Run the script in the background."""
    try:
        pid = os.fork()
        if pid > 0:
            print(f"{Colors.ORANGE}Script is running in the background with PID {pid}. Exiting terminal.{Colors.RESET}")
            os._exit(0)
    except AttributeError:
        log_error("Forking not supported on this platform. Running in the foreground.")

def main():
    """Main function to start the script."""
    global PROTECTION_LEVEL, ALLOWED_MARIADB_IPS, CT_PORTS, DDOS_THRESHOLD, INITIAL_PROTECTION_LEVEL, CURRENT_PROTECTION_LEVEL

    try:
        display_welcome_message()
        print(f"{Colors.LIGHT_GREEN}Killing any existing script instances...{Colors.RESET}")
        kill_existing_script()
        
        print(f"{Colors.LIGHT_GREEN}Installing necessary dependencies...{Colors.RESET}")
        install_dependencies()

        # Initialize logging setup
        init_logging()

        # Prompt user to select protection level
        PROTECTION_LEVEL = show_menu()
        INITIAL_PROTECTION_LEVEL = PROTECTION_LEVEL
        CURRENT_PROTECTION_LEVEL = PROTECTION_LEVEL

        print(f"{Colors.LIGHT_GREEN}Setting protection level to {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN}.{Colors.RESET}")

        # Set DDoS threshold based on the protection level
        DDOS_THRESHOLD = DDOS_THRESHOLDS[PROTECTION_LEVEL]
        print(f"{Colors.LIGHT_GREEN}DDoS connection threshold set to {Colors.BOLD_WHITE}{DDOS_THRESHOLD}{Colors.LIGHT_GREEN} connections.{Colors.RESET}")

        # Get allowed MariaDB IPs and user-defined ports
        ALLOWED_MARIADB_IPS = get_allowed_mariadb_ips()
        print(f"{Colors.LIGHT_GREEN}Allowed MariaDB IP addresses: {Colors.BOLD_WHITE}{', '.join(ALLOWED_MARIADB_IPS)}{Colors.RESET}")

        CT_PORTS = get_allowed_ports()
        print(f"{Colors.LIGHT_GREEN}Allowed ports for traffic: {Colors.BOLD_WHITE}{', '.join(CT_PORTS)}{Colors.RESET}")

        # Notify that IPTables rules are being flushed
        print(f"{Colors.LIGHT_GREEN}Flushing existing IPTables rules...{Colors.RESET}")
        flush_iptables_rules()

        # Apply the appropriate IPTables rules based on protection level
        print(f"{Colors.LIGHT_GREEN}Applying protection level {Colors.BOLD_WHITE}{PROTECTION_LEVEL}{Colors.LIGHT_GREEN} settings...{Colors.RESET}")
        apply_iptables_rules(PROTECTION_LEVEL, CT_PORTS, ALLOWED_MARIADB_IPS)

        # Save IPTables configuration
        print(f"{Colors.LIGHT_GREEN}Saving IPTables configuration...{Colors.RESET}")
        save_iptables_config()

        # Set up IPTables restore service to ensure rules persist after reboot
        print(f"{Colors.LIGHT_GREEN}Setting up IPTables restore service on reboot...{Colors.RESET}")
        setup_iptables_restore_service()

        # Notify via email that the script has started successfully
        notify_script_start(PROTECTION_LEVEL, ALLOWED_MARIADB_IPS, CT_PORTS)

        # Notify that the script will be running in the background
        run_in_background()        

        # Inform the user that the protection upgrade automation is active
        print(f"{Colors.ORANGE}Protection Upgrade Automation ... {Colors.RED}Active!{Colors.RESET}")

        # Start the monitoring threads for log and DDoS detection
        print(f"{Colors.LIGHT_GREEN}Starting log monitoring thread...{Colors.RESET}")
        log_monitor_thread = threading.Thread(target=monitor_logs)

        print(f"{Colors.LIGHT_GREEN}Starting DDoS monitoring thread...{Colors.RESET}")
        ddos_monitor_thread = threading.Thread(target=monitor_ddos)

        log_monitor_thread.start()
        ddos_monitor_thread.start()
        
        # Final confirmation that the script is running in the background
        print(f"{Colors.ORANGE}Script is running in the background with PID {os.getpid()}. Exiting terminal.{Colors.RESET}")
        print(f"{Colors.YELLOW}=================================================================================================")
        print(f" Security Setup finished! Your server is now protected from DDoS attacks and unauthorized access.")
        print(f"================================================================================================={Colors.RESET}")
        
        # Continuously rotate logs and check for any suspicious activity every 5 minutes
        while True:
            print(f"{Colors.CYAN}Rotating logs and checking for suspicious activity...{Colors.RESET}")
            rotate_logs()
            time.sleep(300)  # Sleep for 5 minutes before checking logs again

    except Exception as e:
        log_error(f"Error in main: {str(e)}")
        print(f"{Colors.RED}An error occurred: {str(e)}{Colors.RESET}")

if __name__ == "__main__":
    main()
