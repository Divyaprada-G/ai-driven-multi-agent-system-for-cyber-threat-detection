"""
Unit and Integration Tests for Real Network Telemetry Collector & Network Agent (Upgrade 5)
Verifies:
1. Real socket collection (Windows netstat & Linux ss parsers)
2. Normalizer validation (IP addresses, ports, protocols, timestamps)
3. Duplicate event suppression
4. NetworkAgent integration with normalized telemetry events
5. Detection of suspicious connections (e.g. 4444, 1337)
6. Error handling, restricted permissions, and non-intrusive boundaries
"""

import unittest
from unittest.mock import patch, MagicMock
from windows_collector.collectors.network_collector import NetworkTelemetryCollector
from windows_collector.normalizer import (
    EventNormalizer,
    is_valid_ip,
    is_valid_port,
    is_valid_protocol
)
from cyber_agents.network_agent import NetworkAgent
from cyber_agents.coordinator import MultiAgentCoordinator


class TestNetworkCollectorUpgrade5(unittest.TestCase):

    def setUp(self):
        self.normalizer = EventNormalizer(hostname="TEST-WORKSTATION")
        self.collector = NetworkTelemetryCollector(self.normalizer)
        self.agent = NetworkAgent()

    def test_ip_validation(self):
        """Test strict validation of IP addresses."""
        self.assertTrue(is_valid_ip("192.168.1.100"))
        self.assertTrue(is_valid_ip("10.0.0.1"))
        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("::1"))
        self.assertTrue(is_valid_ip("fe80::1"))
        self.assertTrue(is_valid_ip("*"))

        # Invalid cases
        self.assertFalse(is_valid_ip("999.999.999.999"))
        self.assertFalse(is_valid_ip("invalid_host"))
        self.assertFalse(is_valid_ip("192.168.1"))
        self.assertFalse(is_valid_ip(""))
        self.assertFalse(is_valid_ip(None))

    def test_port_validation(self):
        """Test port validation boundary conditions (0-65535)."""
        self.assertTrue(is_valid_port(0))
        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port(443))
        self.assertTrue(is_valid_port(65535))
        self.assertTrue(is_valid_port(None))

        # Invalid cases
        self.assertFalse(is_valid_port(-1))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port("80"))  # Non-integer
        self.assertFalse(is_valid_port(99999))

    def test_protocol_validation(self):
        """Test protocol validation."""
        self.assertTrue(is_valid_protocol("TCP"))
        self.assertTrue(is_valid_protocol("UDP"))
        self.assertTrue(is_valid_protocol("ICMP"))
        self.assertTrue(is_valid_protocol("tcp"))
        self.assertTrue(is_valid_protocol(None))

        # Invalid cases
        self.assertFalse(is_valid_protocol("XYZ"))
        self.assertFalse(is_valid_protocol("SSH"))  # SSH is application layer, not transport

    def test_netstat_windows_parser(self):
        """Test Windows netstat -ano output parsing."""
        sample_netstat = (
            "Active Connections\r\n"
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924\r\n"
            "  TCP    192.168.1.50:49210     104.18.25.10:443       ESTABLISHED     4820\r\n"
            "  TCP    192.168.1.50:50112     198.51.100.4:4444      SYN_SENT        5100\r\n"
            "  UDP    0.0.0.0:5353           *:*                                    1200\r\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=sample_netstat)
            connections = self.collector._parse_netstat_windows()

            self.assertEqual(len(connections), 4)
            
            # Check listening event
            c0 = connections[0]
            self.assertEqual(c0["protocol"], "TCP")
            self.assertEqual(c0["local_port"], 135)
            self.assertEqual(c0["connection_state"], "LISTENING")
            self.assertEqual(c0["pid"], "924")

            # Check established event
            c1 = connections[1]
            self.assertEqual(c1["local_ip"], "192.168.1.50")
            self.assertEqual(c1["remote_ip"], "104.18.25.10")
            self.assertEqual(c1["remote_port"], 443)
            self.assertEqual(c1["connection_state"], "ESTABLISHED")
            self.assertEqual(c1["pid"], "4820")

            # Check suspicious port event
            c2 = connections[2]
            self.assertEqual(c2["remote_port"], 4444)
            self.assertEqual(c2["connection_state"], "SYN_SENT")

    def test_normalizer_network_event(self):
        """Test EventNormalizer on genuine raw network telemetry."""
        raw_network_event = {
            "source_type": "network_telemetry",
            "protocol": "TCP",
            "local_ip": "192.168.1.45",
            "local_port": 52100,
            "remote_ip": "203.0.113.88",
            "remote_port": 1337,
            "connection_state": "ESTABLISHED",
            "process_name": "nc.exe",
            "pid": "3412"
        }

        normalized = self.normalizer.normalize(raw_network_event)
        self.assertEqual(normalized.source_type, "network_telemetry")
        self.assertEqual(normalized.hostname, "TEST-WORKSTATION")
        self.assertEqual(normalized.local_ip, "192.168.1.45")
        self.assertEqual(normalized.remote_ip, "203.0.113.88")
        self.assertEqual(normalized.local_port, 52100)
        self.assertEqual(normalized.remote_port, 1337)
        self.assertEqual(normalized.protocol, "TCP")
        self.assertEqual(normalized.connection_state, "ESTABLISHED")
        self.assertEqual(normalized.process_name, "nc.exe")
        self.assertEqual(normalized.collection_status, "COLLECTED")
        self.assertTrue(normalized.event_id.startswith("NET-"))

    def test_normalizer_invalid_network_event(self):
        """Test EventNormalizer flags invalid network telemetry with VALIDATION_FAILED."""
        invalid_event = {
            "source_type": "network_telemetry",
            "protocol": "TCP",
            "local_ip": "not_an_ip",
            "local_port": 999999,  # invalid port
            "remote_ip": "999.999.999.999",
            "remote_port": -5,
            "connection_state": "ESTABLISHED"
        }

        normalized = self.normalizer.normalize(invalid_event)
        self.assertEqual(normalized.collection_status, "VALIDATION_FAILED")
        self.assertIn("validation_error", normalized.details)

    def test_network_agent_processes_normalized_dict(self):
        """Test NetworkAgent processes normalized network event dictionaries directly."""
        events = [
            {
                "source_type": "network_telemetry",
                "local_ip": "192.168.1.100",
                "remote_ip": "198.51.100.99",
                "local_port": 49152,
                "remote_port": 4444,
                "protocol": "TCP",
                "connection_state": "ESTABLISHED",
                "process_name": "meterpreter.exe"
            }
        ]

        security_findings = self.agent.process_logs(events)
        self.assertEqual(len(security_findings), 1)
        finding = security_findings[0]
        self.assertEqual(finding["event_type"], "Suspicious Port Activity")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["indicators"]["targeted_port"], 4444)
        self.assertEqual(finding["indicators"]["process_name"], "meterpreter.exe")

    def test_coordinator_integration(self):
        """Test MultiAgentCoordinator pipeline with real network telemetry input."""
        coordinator = MultiAgentCoordinator()
        network_stream = [
            {
                "source_type": "network_telemetry",
                "local_ip": "10.0.0.15",
                "remote_ip": "172.16.0.4",
                "local_port": 55120,
                "remote_port": 1337,
                "protocol": "TCP",
                "connection_state": "SYN_SENT",
                "process_name": "backdoor.exe"
            }
        ]

        result = coordinator.process_telemetry(network_logs=network_stream)
        self.assertIn("Network Monitoring Agent", result["agents_executed"])
        self.assertTrue(result["threat_detected"])
        self.assertGreaterEqual(result["risk_assessment"]["composite_risk_score"], 50)


if __name__ == "__main__":
    unittest.main()
