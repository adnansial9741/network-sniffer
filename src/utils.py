"""
Utility functions for the network sniffer
"""

from colorama import Fore, Style
import sys
import os
from datetime import datetime

def check_admin_privileges():
    """Check if running as administrator"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Mac
            return os.geteuid() == 0
    except:
        return False

def get_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def get_port_service(port):
    """Get service name for common ports"""
    services = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        123: 'NTP', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
        993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    return services.get(port, 'unknown')

def print_banner():
    """Print startup banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                              ║
║              NETWORK PACKET SNIFFER v1.0                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)