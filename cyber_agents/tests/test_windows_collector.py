"""
Unit Tests for Windows Security & Application Telemetry Collector
Tests parsing, deduplication, permission failures, and unavailable sources.
Runs under standard Python 3 unittest without external dependencies.
"""
import sys
import os
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from windows_collector.config import CollectorConfig
from windows_collector.normalizer import EventNormalizer, Deduplicator
from windows_collector.collectors.event_log_collector import WindowsEventLogCollector
from windows_collector.collectors.file_tail_collector import AppFileTailCollector
from windows_collector.collectors.network_collector import NetworkTelemetryCollector
from windows_collector.service import WindowsCollectorService

# Sample genuine Windows Event Log XML representations (as output by wevtutil)
SAMPLE_SECURITY_4625_XML = """
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
      <EventID>4625</EventID>
      <Version>0</Version>
      <Level>0</Level>
      <Task>12544</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8010000000000000</Keywords>
      <TimeCreated SystemTime="2026-09-17T17:15:30.123456Z" />
      <EventRecordID>98142</EventRecordID>
      <Correlation />
      <Execution ProcessID="688" ThreadID="1904" />
      <Channel>Security</Channel>
      <Computer>WIN-SEC-SRV01.corp.local</Computer>
      <Security />
    </System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-0-0</Data>
      <Data Name="SubjectUserName">-</Data>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="TargetDomainName">CORP</Data>
      <Data Name="Status">0xc000006d</Data>
      <Data Name="FailureReason">%%2313</Data>
      <Data Name="SubStatus">0xc000006a</Data>
      <Data Name="LogonType">3</Data>
      <Data Name="LogonProcessName">NtLmSsp</Data>
      <Data Name="AuthenticationPackageName">NTLM</Data>
      <Data Name="WorkstationName">ATTACKER-PC</Data>
      <Data Name="IpAddress">192.168.1.150</Data>
      <Data Name="IpPort">54321</Data>
    </EventData>
  </Event>
</Events>
"""

SAMPLE_SYSTEM_7045_XML = """
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7045</EventID>
      <Level>2</Level>
      <TimeCreated SystemTime="2026-09-17T17:20:00.000000Z" />
      <EventRecordID>45102</EventRecordID>
      <Channel>System</Channel>
      <Computer>WIN-SEC-SRV01.corp.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">PwnService</Data>
      <Data Name="ImagePath">C:\\Windows\\Temp\\backdoor.exe</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">auto start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>
</Events>
"""

SAMPLE_AUDIT_1102_XML = """
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" />
      <EventID>1102</EventID>
      <Level>4</Level>
      <TimeCreated SystemTime="2026-09-17T17:25:00.000000Z" />
      <EventRecordID>98150</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WIN-SEC-SRV01.corp.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">AdminBob</Data>
    </EventData>
  </Event>
</Events>
"""

class TestWindowsEventLogParsing(unittest.TestCase):
    def setUp(self):
        self.normalizer = EventNormalizer(default_hostname="WIN-SEC-SRV01")
        self.collector = WindowsEventLogCollector(self.normalizer)

    def test_parse_security_failed_logon_4625(self):
        """Verifies parsing of Windows Event ID 4625 (Failed Logon - Brute Force)."""
        events = self.collector.parse_wevtutil_xml(SAMPLE_SECURITY_4625_XML, "Security")
        self.assertEqual(len(events), 1)
        evt = events[0]

        # Check required schema fields
        self.assertEqual(evt["source"], "system")
        self.assertEqual(evt["severity"], "HIGH")
        self.assertEqual(evt["username"], "Administrator")
        self.assertEqual(evt["sourceIp"], "192.168.1.150")
        self.assertIn("4625", evt["eventType"])
        self.assertFalse(evt["isSimulated"])
        self.assertEqual(evt["telemetrySource"], "EXTERNAL_AGENT")

        # Check mandatory source metadata
        meta = evt["sourceMetadata"]
        self.assertEqual(meta["source_type"], "windows_event_log")
        self.assertEqual(meta["collector_name"], "WindowsEventLogCollector")
        self.assertEqual(meta["collection_status"], "COLLECTED")
        self.assertIn("Administrator", meta["raw_message"])

    def test_parse_system_service_installation_7045(self):
        """Verifies parsing of Windows Event ID 7045 (New Service Installed - Persistence)."""
        events = self.collector.parse_wevtutil_xml(SAMPLE_SYSTEM_7045_XML, "System")
        self.assertEqual(len(events), 1)
        evt = events[0]

        self.assertEqual(evt["source"], "system")
        self.assertEqual(evt["severity"], "HIGH")
        self.assertIn("7045", evt["eventType"])
        self.assertIn("T1543.003", evt["eventType"])
        self.assertFalse(evt["isSimulated"])

    def test_parse_audit_log_cleared_1102(self):
        """Verifies parsing of Windows Event ID 1102 (Audit Log Cleared - Defense Evasion)."""
        events = self.collector.parse_wevtutil_xml(SAMPLE_AUDIT_1102_XML, "Security")
        self.assertEqual(len(events), 1)
        evt = events[0]

        self.assertEqual(evt["severity"], "CRITICAL")
        self.assertIn("T1070.001", evt["eventType"])
        self.assertEqual(evt["username"], "AdminBob")

    def test_non_windows_environment_graceful_handling(self):
        """Verifies that non-Windows hosts gracefully report SOURCE_UNAVAILABLE and never fabricate fake data."""
        # Force is_windows = False
        self.collector.is_windows = False
        events = self.collector.collect()
        
        # Zero fabricated events
        self.assertEqual(len(events), 0)
        status = self.collector.get_status()
        self.assertEqual(status["channels"]["System"]["status"], "SOURCE_UNAVAILABLE")
        self.assertIn("require Microsoft Windows", status["channels"]["System"]["last_error"])


class TestDeduplicationEngine(unittest.TestCase):
    def setUp(self):
        self.dedup = Deduplicator(capacity=50)

    def test_duplicate_detection(self):
        fp1 = self.dedup.compute_hash("win_event", 1234, "2026-09-17T10:00:00Z")
        fp2 = self.dedup.compute_hash("win_event", 5678, "2026-09-17T10:00:01Z")

        # First time seen: not duplicate
        self.assertFalse(self.dedup.is_duplicate(fp1))
        self.assertFalse(self.dedup.is_duplicate(fp2))

        # Second time seen: duplicate
        self.assertTrue(self.dedup.is_duplicate(fp1))
        self.assertTrue(self.dedup.is_duplicate(fp2))

        stats = self.dedup.get_stats()
        self.assertEqual(stats["total_checked"], 4)
        self.assertEqual(stats["total_duplicates_dropped"], 2)

    def test_normalizer_drops_duplicates(self):
        normalizer = EventNormalizer()
        evt1 = normalizer.normalize(
            source_type="windows_event_log",
            collector_name="WindowsEventLogCollector",
            raw_message="Sample raw log line 1",
            event_id="EVT-001",
            timestamp="2026-09-17T10:00:00Z"
        )
        self.assertIsNotNone(evt1)

        # Duplicate normalization with identical ID and raw message
        evt2 = normalizer.normalize(
            source_type="windows_event_log",
            collector_name="WindowsEventLogCollector",
            raw_message="Sample raw log line 1",
            event_id="EVT-001",
            timestamp="2026-09-17T10:00:00Z"
        )
        self.assertIsNone(evt2, "Normalizer must drop duplicate event")


class TestFileTailingAndAppCollector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="win_collector_test_")
        self.normalizer = EventNormalizer()
        self.collector = AppFileTailCollector(
            normalizer=self.normalizer,
            directories=[self.test_dir],
            extensions=[".log", ".json"]
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tail_plain_text_log_and_threat_detection(self):
        log_file = os.path.join(self.test_dir, "web_access.log")
        with open(log_file, "w") as f:
            f.write("2026-09-17 10:00:00 GET /index.html 200 - 192.168.1.50\n")

        # Cycle 1: Read initial line
        events_1 = self.collector.collect()
        self.assertEqual(len(events_1), 1)
        self.assertEqual(events_1[0]["source"], "application")

        # Append new attack line (SQL Injection)
        with open(log_file, "a") as f:
            f.write("2026-09-17 10:00:05 GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users 500 - 203.0.113.88\n")

        # Cycle 2: Read newly appended line only
        events_2 = self.collector.collect()
        self.assertEqual(len(events_2), 1)
        sqli_evt = events_2[0]
        self.assertEqual(sqli_evt["severity"], "HIGH")
        self.assertIn("SQL Injection", sqli_evt["eventType"])
        self.assertEqual(sqli_evt["sourceIp"], "203.0.113.88")
        self.assertEqual(sqli_evt["sourceMetadata"]["source_type"], "application_log_file")

    def test_tail_json_log_format(self):
        json_log = os.path.join(self.test_dir, "app_service.json")
        with open(json_log, "w") as f:
            entry = {
                "timestamp": "2026-09-17T10:10:00Z",
                "level": "ERROR",
                "client_ip": "10.0.0.99",
                "user": "developer1",
                "message": "Failed login attempt: authentication failed"
            }
            f.write(f"{json.dumps(entry)}\n")

        events = self.collector.collect()
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt["username"], "developer1")
        self.assertEqual(evt["sourceIp"], "10.0.0.99")
        self.assertEqual(evt["severity"], "HIGH")
        self.assertIn("Authentication Failure", evt["eventType"])

    def test_log_rotation_handling(self):
        log_file = os.path.join(self.test_dir, "rotating.log")
        with open(log_file, "w") as f:
            f.write("Line 1" * 50 + "\n")
            f.write("Line 2" * 50 + "\n")

        self.collector.collect()
        tracked = self.collector.file_states[log_file]
        initial_offset = tracked["offset"]
        self.assertGreater(initial_offset, 0)

        # Rotate: rewrite file with smaller content
        with open(log_file, "w") as f:
            f.write("Rotated new line\n")

        # Next collect must detect smaller size and reset offset to 0
        events = self.collector.collect()
        self.assertEqual(len(events), 1)
        self.assertIn("Rotated new line", events[0]["rawPayload"])

    def test_unavailable_directory_graceful_handling(self):
        non_existent = os.path.join(self.test_dir, "does_not_exist_12345")
        collector = AppFileTailCollector(
            normalizer=self.normalizer,
            directories=[non_existent]
        )
        events = collector.collect()
        self.assertEqual(len(events), 0)
        status = collector.get_status()
        self.assertEqual(status["directories"][non_existent]["status"], "SOURCE_UNAVAILABLE")


class TestNetworkTelemetryCollector(unittest.TestCase):
    def setUp(self):
        self.normalizer = EventNormalizer()
        self.collector = NetworkTelemetryCollector(self.normalizer)

    def test_safe_telemetry_metadata(self):
        """Verifies collector explicitly declares socket inspection and NOT packet sniffing."""
        status = self.collector.get_status()
        self.assertFalse(status["is_packet_sniffing"])
        self.assertEqual(status["telemetry_type"], "socket_and_interface_state")

    def test_parse_netstat_line(self):
        line = "  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       1234"
        parsed = self.collector._parse_netstat_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["local_ip"], "0.0.0.0")
        self.assertEqual(parsed["local_port"], 3000)
        self.assertEqual(parsed["state"], "LISTENING")
        self.assertEqual(parsed["pid"], "1234")

    def test_network_collection_produces_real_events(self):
        events = self.collector.collect()
        self.assertGreaterEqual(len(events), 1)
        first = events[0]
        self.assertEqual(first["source"], "network")
        self.assertFalse(first["isSimulated"])
        self.assertEqual(first["sourceMetadata"]["source_type"], "network_telemetry")


class TestWindowsCollectorService(unittest.TestCase):
    def test_service_initialization_and_single_cycle(self):
        config = CollectorConfig(
            enabled_collectors=["network"],
            backend_api_url="http://127.0.0.1:3000",
            health_server_port=0  # Don't bind port in unit test
        )
        service = WindowsCollectorService(config)
        res = service.run_single_cycle()

        self.assertEqual(res["cycle"], 1)
        self.assertGreaterEqual(res["events_collected"], 1)

        health = service.get_health()
        self.assertEqual(health["cycles_completed"], 1)
        self.assertEqual(health["total_events_collected"], res["events_collected"])


if __name__ == "__main__":
    unittest.main()
