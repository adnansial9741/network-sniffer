import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sniffer import NetworkSniffer

sniffer = NetworkSniffer(verbose=True)
print("Capturing 10 packets...")
sniffer.start(packet_count=10)