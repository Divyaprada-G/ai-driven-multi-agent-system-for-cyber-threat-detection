"""
Unit Tests for All 6 Defensive Cybersecurity Monitoring Agents
Runs under standard Python 3 unittest without external dependencies.
"""
import unittest
import sys
import os

# Ensure cyber_agents module is discoverable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_agents.network_agent import NetworkAgent
from cyber_agents.system_agent import SystemAgent
from cyber_agents.application_agent import ApplicationAgent
from cyber_agents.correlation_agent import CorrelationAgent
from cyber_agents.threat_detection_agent import ThreatDetectionAgent
from cyber_agents.alert_response_agent import AlertResponseAgent
from cyber_agents.coordinator import MultiAgentCoordinator
from cyber_agents.sample_logs import (
    SAMPLE_NETWORK_LOGS,
    SAMPLE_SYSTEM_LOGS,
    SAMPLE_APPLICATION_LOGS,
    SAMPLE_BENIGN_LOGS
)

class TestNetworkAgent(unittest.TestCase):
    def setUp(self):
        self.agent = NetworkAgent(port_scan_threshold=4)

    def test_parse_network_line(self):
        line = "2026-09-17T10:15:01Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=22 proto=TCP SYN"
        parsed = self.agent.parse_network_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["source_ip"], "192.168.1.105")
        self.assertEqual(parsed["destination_ip"], "10.0.0.5")
        self.assertEqual(parsed["port"], 22)
        self.assertEqual(parsed["protocol"], "TCP")

    def test_detect_port_scan(self):
        events = self.agent.process_logs(SAMPLE_NETWORK_LOGS)
        self.assertTrue(len(events) > 0)
        types = [e["event_type"] for e in events]
        self.assertIn("Port Scanning", types)

    def test_structured_event_schema(self):
        events = self.agent.process_logs(SAMPLE_NETWORK_LOGS)
        first = events[0]
        required_keys = [
            "event_id", "agent_name", "timestamp", "event_type",
            "severity", "source", "description", "indicators", "recommended_action"
        ]
        for k in required_keys:
            self.assertIn(k, first, f"Missing required key '{k}' in output")

class TestSystemAgent(unittest.TestCase):
    def setUp(self):
        self.agent = SystemAgent(brute_force_threshold=3)

    def test_detect_brute_force_and_sudo(self):
        events = self.agent.process_logs(SAMPLE_SYSTEM_LOGS)
        self.assertTrue(len(events) >= 2)
        types = [e["event_type"] for e in events]
        self.assertIn("Brute Force Authentication Attack", types)
        self.assertIn("Privilege Escalation", types)

    def test_benign_logs(self):
        events = self.agent.process_logs(["Sep 17 10:30:10 server01 sshd: Accepted password for developer from 10.0.0.12"])
        self.assertEqual(len(events), 0)

class TestApplicationAgent(unittest.TestCase):
    def setUp(self):
        self.agent = ApplicationAgent()

    def test_detect_sqli_and_xss_and_traversal(self):
        events = self.agent.process_logs(SAMPLE_APPLICATION_LOGS)
        self.assertTrue(len(events) >= 3)
        types = [e["event_type"] for e in events]
        self.assertIn("SQL Injection (SQLi)", types)
        self.assertIn("Cross-Site Scripting (XSS)", types)
        self.assertIn("Path Traversal", types)

class TestCorrelationAgent(unittest.TestCase):
    def setUp(self):
        self.net_agent = NetworkAgent(port_scan_threshold=4)
        self.sys_agent = SystemAgent(brute_force_threshold=3)
        self.app_agent = ApplicationAgent()
        self.corr_agent = CorrelationAgent()

    def test_cross_agent_correlation(self):
        net_ev = self.net_agent.process_logs(SAMPLE_NETWORK_LOGS)
        sys_ev = self.sys_agent.process_logs(SAMPLE_SYSTEM_LOGS)
        app_ev = self.app_agent.process_logs(SAMPLE_APPLICATION_LOGS)
        all_ev = net_ev + sys_ev + app_ev

        res = self.corr_agent.correlate(all_ev)
        self.assertTrue(res["correlated_count"] > 0)
        self.assertTrue(res["attack_chain_detected"])
        self.assertIn("192.168.1.105", res["unique_source_ips"])

class TestThreatDetectionAgent(unittest.TestCase):
    def setUp(self):
        self.agent = ThreatDetectionAgent()

    def test_threat_detection_with_ml_and_rules(self):
        sample_events = [
            {
                "event_id": "EVT-1",
                "event_type": "Port Scanning",
                "severity": "HIGH",
                "description": "Port scan from 192.168.1.105",
                "indicators": {"source_ip": "192.168.1.105"}
            }
        ]
        result = self.agent.detect(sample_events)
        self.assertTrue(result["threat_detected"])
        self.assertIn(result["overall_severity"], ["HIGH", "CRITICAL"])
        self.assertIn("machine_learning_analysis", result)
        self.assertEqual(result["machine_learning_analysis"]["predicted_class"], "PortScan")
        self.assertTrue(result["machine_learning_analysis"]["anomaly_detected"])

    def test_benign_evaluation(self):
        result = self.agent.detect([])
        self.assertFalse(result["threat_detected"])
        self.assertEqual(result["overall_severity"], "LOW")
        self.assertEqual(result["machine_learning_analysis"]["predicted_class"], "BENIGN")

class TestAlertResponseAgent(unittest.TestCase):
    def setUp(self):
        self.agent = AlertResponseAgent()

    def test_alert_generation_and_incident_lifecycle(self):
        events = [
            {
                "event_id": "EVT-TEST",
                "agent_name": "Application Monitoring Agent",
                "event_type": "SQL Injection (SQLi)",
                "severity": "CRITICAL",
                "source": "Web Application Layer",
                "description": "SQL injection detected",
                "indicators": {"source_ip": "192.168.1.105"},
                "recommended_action": "Sanitize inputs."
            }
        ]
        alerts = self.agent.generate_alerts(events, [])
        self.assertEqual(len(alerts), 1)
        alert_id = alerts[0]["alert_id"]

        # Incident Lifecycle: Create -> Acknowledge -> Add Note -> Resolve
        inc = self.agent.create_incident(
            title="Critical SQL Injection Incident",
            description="Automated incident from test",
            severity="CRITICAL",
            associated_alerts=[alert_id],
            primary_ip="192.168.1.105"
        )
        self.assertEqual(inc["status"], "NEW")
        inc_id = inc["incident_id"]

        ack = self.agent.acknowledge_incident(inc_id, actor="Security Analyst")
        self.assertEqual(ack["status"], "ACKNOWLEDGED")

        noted = self.agent.add_investigation_note(inc_id, "Verified malicious user agent", actor="Forensic Investigator")
        self.assertEqual(len(noted["investigation_notes"]), 3)

        closed = self.agent.close_incident(inc_id, "WAF signature deployed", actor="SOC Lead")
        self.assertEqual(closed["status"], "RESOLVED")

class TestCoordinatorResilience(unittest.TestCase):
    def setUp(self):
        self.coord = MultiAgentCoordinator()

    def test_resilience_with_empty_and_partial_sources(self):
        # Even if 2 of 3 sources are empty, coordinator succeeds
        res1 = self.coord.process_telemetry(network_logs=SAMPLE_NETWORK_LOGS, system_logs=[], application_logs=[])
        self.assertEqual(res1["pipeline_status"], "COMPLETED")
        self.assertTrue(res1["events_detected_count"] > 0)

        # Completely empty input handling
        res2 = self.coord.process_telemetry([], [], [])
        self.assertEqual(res2["pipeline_status"], "COMPLETED")
        self.assertEqual(res2["events_detected_count"], 0)

if __name__ == "__main__":
    unittest.main()
