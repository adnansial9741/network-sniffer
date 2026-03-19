"""
Main sniffer module
"""

from scapy.all import *
from colorama import init, Fore, Style
import argparse
import time
import signal
import sys
from collections import Counter
from prettytable import PrettyTable

from src.packet_analyzer import PacketAnalyzer
from src.utils import check_admin_privileges, print_banner, get_timestamp

# Initialize colorama
init(autoreset=True)

class NetworkSniffer:
    def __init__(self, interface=None, filter_bpf=None, verbose=True):
        self.interface = interface
        self.filter_bpf = filter_bpf
        self.verbose = verbose
        self.packet_count = 0
        self.start_time = None
        
        # Statistics
        self.stats = Counter()
        
        # Analyzer
        self.analyzer = PacketAnalyzer()
        
        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print(f"\n{Fore.YELLOW}[!] Stopping...{Style.RESET_ALL}")
        self.print_stats()
        sys.exit(0)
    
    def packet_callback(self, packet):
        self.packet_count += 1
        
        try:
            # Analyze
            info = self.analyzer.analyze(packet)
            self.stats[info['protocol']] += 1
            
            # Display
            if self.verbose:
                print(self.analyzer.format_output(info, self.packet_count))
            elif self.packet_count % 10 == 0:
                print(f"{Fore.GREEN}[✓] Captured {self.packet_count} packets{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    
    def print_stats(self):
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📊 STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"Duration: {duration:.2f}s")
            print(f"Packets: {self.packet_count}")
        
        if self.stats:
            table = PrettyTable(['Protocol', 'Count'])
            for proto, count in self.stats.most_common():
                table.add_row([proto, count])
            print(table)
    
    def start(self, packet_count=0):
        print_banner()
        print(f"{Fore.GREEN}Interface: {self.interface or 'default'}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Filter: {self.filter_bpf or 'none'}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        self.start_time = time.time()
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=self.filter_bpf,
                count=packet_count if packet_count > 0 else None,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}[!] Run as Administrator!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

def list_interfaces():
    print(f"\n{Fore.CYAN}Available Interfaces:{Style.RESET_ALL}")
    for iface in get_if_list():
        print(f"  • {iface}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help='Interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets')
    parser.add_argument('-f', '--filter', help='BPF filter')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('--list', action='store_true', help='List interfaces')
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        sys.exit(0)
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_bpf=args.filter,
        verbose=not args.quiet
    )
    
    sniffer.start(packet_count=args.count)

if __name__ == "__main__":
    main()