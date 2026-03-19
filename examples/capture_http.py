#!/usr/bin/env python3
"""
HTTP traffic capture example
"""

import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sniffer import NetworkSniffer

def main():
    print("="*60)
    print("HTTP TRAFFIC SNIFFER EXAMPLE")
    print("="*60)
    print("This will capture HTTP packets only")
    print("Open a browser and visit http://example.com\n")
    
    # Create sniffer with HTTP filter
    sniffer = NetworkSniffer(
        filter_bpf="tcp port 80",
        verbose=True
    )
    
    print("Starting capture (will capture 20 HTTP packets)...")
    time.sleep(2)
    
    try:
        sniffer.start(packet_count=20)
    except KeyboardInterrupt:
        print("\nCapture stopped")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()