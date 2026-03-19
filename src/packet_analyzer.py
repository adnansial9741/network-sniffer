"""
Packet analysis module for the network sniffer
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from colorama import Fore, Style
from src.utils import get_port_service

class PacketAnalyzer:
    """Handles packet analysis"""
    
    @staticmethod
    def analyze(packet):
        """Analyze packet and return info"""
        info = {
            'protocol': 'Unknown',
            'src': '?',
            'dst': '?',
            'details': [],
            'summary': str(packet.summary())
        }
        
        try:
            # Ethernet
            if Ether in packet:
                eth = packet[Ether]
                info['src_mac'] = eth.src
                info['dst_mac'] = eth.dst
            
            # IP
            if IP in packet:
                ip = packet[IP]
                info['src'] = ip.src
                info['dst'] = ip.dst
                
                # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    info['protocol'] = 'TCP'
                    info['src'] = f"{ip.src}:{tcp.sport}"
                    info['dst'] = f"{ip.dst}:{tcp.dport}"
                    info['details'].append(f"Flags: {tcp.flags}")
                    info['src_service'] = get_port_service(tcp.sport)
                    info['dst_service'] = get_port_service(tcp.dport)
                    
                    # HTTP check
                    if tcp.dport == 80 or tcp.sport == 80:
                        info['protocol'] = 'HTTP'
                
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    info['protocol'] = 'UDP'
                    info['src'] = f"{ip.src}:{udp.sport}"
                    info['dst'] = f"{ip.dst}:{udp.dport}"
                    info['src_service'] = get_port_service(udp.sport)
                    info['dst_service'] = get_port_service(udp.dport)
                    
                    # DNS check
                    if udp.dport == 53 or udp.sport == 53:
                        info['protocol'] = 'DNS'
                
                # ICMP
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    icmp = packet[ICMP]
                    info['details'].append(f"Type: {icmp.type}")
            
            # ARP
            elif ARP in packet:
                arp = packet[ARP]
                info['protocol'] = 'ARP'
                info['src'] = arp.psrc
                info['dst'] = arp.pdst
            
            # Payload
            if Raw in packet:
                info['has_payload'] = True
                info['payload_size'] = len(packet[Raw].load)
        
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    @staticmethod
    def format_output(info, packet_num):
        """Format info for display"""
        output = []
        output.append(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        output.append(f"{Fore.WHITE}[Packet #{packet_num}] {info['protocol']}{Style.RESET_ALL}")
        output.append(f"  {info['src']} -> {info['dst']}")
        
        if info.get('src_mac'):
            output.append(f"  MAC: {info['src_mac']} -> {info['dst_mac']}")
        
        for detail in info['details']:
            output.append(f"  ├─ {detail}")
        
        if info.get('src_service') and info['src_service'] != 'unknown':
            output.append(f"  ├─ Service: {info['src_service']}")
        if info.get('dst_service') and info['dst_service'] != 'unknown':
            output.append(f"  └─ Service: {info['dst_service']}")
        
        output.append(f"\n  {Fore.WHITE}Summary:{Style.RESET_ALL} {info['summary'][:80]}")
        
        return '\n'.join(output)