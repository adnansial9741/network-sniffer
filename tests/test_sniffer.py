"""
Unit tests for the network sniffer
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sniffer import NetworkSniffer
from src.packet_analyzer import PacketAnalyzer
from src.utils import get_port_service, format_mac_address

class TestUtils(unittest.TestCase):
    """Test utility functions"""
    
    def test_get_port_service(self):
        self.assertEqual(get_port_service(80), 'HTTP')
        self.assertEqual(get_port_service(443), 'HTTPS')
        self.assertEqual(get_port_service(22), 'SSH')
        self.assertEqual(get_port_service(9999), 'unknown')
    
    def test_format_mac_address(self):
        # Test with bytes
        mac_bytes = b'\x00\x1a\x2b\x3c\x4d\x5e'
        self.assertEqual(format_mac_address(mac_bytes), '00:1a:2b:3c:4d:5e')

class TestPacketAnalyzer(unittest.TestCase):
    """Test packet analyzer"""
    
    def setUp(self):
        self.analyzer = PacketAnalyzer()
    
    @patch('src.packet_analyzer.IP')
    def test_analyze_with_mock(self, mock_ip):
        # This is a basic test - in reality you'd create mock packets
        self.assertTrue(hasattr(self.analyzer, 'analyze'))

class TestNetworkSniffer(unittest.TestCase):
    """Test main sniffer class"""
    
    def setUp(self):
        self.sniffer = NetworkSniffer(verbose=False)
    
    def test_initialization(self):
        self.assertEqual(self.sniffer.packet_count, 0)
        self.assertIsNone(self.sniffer.interface)
        self.assertFalse(self.sniffer.running)
    
    def test_update_statistics(self):
        # Test with mock analysis data
        mock_analysis = {
            'protocol': 'TCP',
            'src': '192.168.1.100:12345',
            'dst': '93.184.216.34:80',
            'src_port': 12345,
            'dst_port': 80
        }
        
        self.sniffer.update_statistics(mock_analysis)
        
        self.assertEqual(self.sniffer.protocol_stats['TCP'], 1)
        self.assertEqual(self.sniffer.ip_stats['192.168.1.100'], 1)
        self.assertEqual(self.sniffer.ip_stats['93.184.216.34'], 1)
        self.assertEqual(self.sniffer.port_stats[12345], 1)
        self.assertEqual(self.sniffer.port_stats[80], 1)

if __name__ == '__main__':
    unittest.main()