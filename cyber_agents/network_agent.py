"""
Agent 1: Network Monitoring Agent
Extracts IP addresses, ports, protocols, timestamps, and detects suspicious network patterns.
Outputs strictly compliant SecurityEvent dictionaries.
"""
import re
import json
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import logging
from cyber_agents.schemas import SecurityEvent, utc_now_iso

logger = logging.getLogger("NetworkAgent")

class NetworkAgent:
    """
    Defensive network traffic monitoring agent:
    - Extracts source/destination IP, destination port, transport protocol, timestamps
    - Identifies port scans, SYN packet sweeps, brute connection sweeps, and high connection bursts
    - Supports raw string logs, JSON string records, and normalized telemetry dictionaries
    - Does not execute active attacks or intrusive sniffing
    """

    IP_PATTERN = re.compile(r'(?:src_ip=|from\s+|host\s+|^|\b)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b')
    DST_IP_PATTERN = re.compile(r'(?:dst_ip=|to\s+)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b')
    PORT_PATTERN = re.compile(r'\bport[=:\s]+([0-9]{1,5})\b', re.IGNORECASE)
    PROTO_PATTERN = re.compile(r'\bproto[=:\s]+(TCP|UDP|ICMP)\b', re.IGNORECASE)

    def __init__(self, port_scan_threshold: int = 4, burst_threshold: int = 15):
        self.port_scan_threshold = port_scan_threshold
        self.burst_threshold = burst_threshold

    def parse_network_line(self, line: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Extract network telemetry fields from log entry line or normalized dict safely."""
        if not line:
            return None

        # Handle structured dictionary (e.g. from telemetry normalizer or pipeline)
        if isinstance(line, dict):
            src_ip = line.get("source_ip") or line.get("local_ip") or line.get("sourceIp") or line.get("src_ip")
            dst_ip = line.get("destination_ip") or line.get("remote_ip") or line.get("destinationIp") or line.get("dst_ip")
            
            port = line.get("remote_port") or line.get("destinationPort") or line.get("destination_port") or line.get("port")
            if port is None and line.get("local_port") is not None and str(line.get("connection_state")).upper() == "LISTENING":
                port = line.get("local_port")
            
            if port is not None:
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    port = None

            protocol = str(line.get("protocol") or "TCP").upper()
            timestamp = line.get("timestamp") or utc_now_iso()
            conn_state = str(line.get("connection_state") or line.get("state") or "").upper()
            is_syn = conn_state == "SYN_SENT" or "SYN" in str(line.get("flags", "")).upper()
            raw = line.get("raw") or line.get("raw_message") or line.get("rawPayload") or json.dumps(line)
            process_name = line.get("process_name")

            return {
                "timestamp": timestamp,
                "source_ip": str(src_ip) if src_ip else None,
                "destination_ip": str(dst_ip) if dst_ip else None,
                "port": port,
                "protocol": protocol,
                "is_syn": is_syn,
                "connection_state": conn_state,
                "process_name": process_name,
                "raw": raw
            }

        if not isinstance(line, str):
            return None

        clean_line = line.strip()
        if not clean_line:
            return None

        # Check if line is a JSON object
        if clean_line.startswith("{") and clean_line.endswith("}"):
            try:
                parsed_json = json.loads(clean_line)
                if isinstance(parsed_json, dict):
                    return self.parse_network_line(parsed_json)
            except Exception:
                pass

        # Text regex extraction
        src_ip_match = self.IP_PATTERN.search(clean_line)
        src_ip = src_ip_match.group(1) if src_ip_match else None

        dst_ip_match = self.DST_IP_PATTERN.search(clean_line)
        dst_ip = dst_ip_match.group(1) if dst_ip_match else None

        port_match = self.PORT_PATTERN.search(clean_line)
        port = int(port_match.group(1)) if port_match else None

        proto_match = self.PROTO_PATTERN.search(clean_line)
        protocol = proto_match.group(1).upper() if proto_match else "TCP"

        # Timestamp extract
        ts_match = re.search(r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', clean_line)
        timestamp = ts_match.group(0) if ts_match else utc_now_iso()

        is_syn = "SYN" in clean_line.upper() or "action=connect" in clean_line.lower() or "flags=S" in clean_line

        return {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": port,
            "protocol": protocol,
            "is_syn": is_syn,
            "raw": clean_line
        }

    def process_logs(self, logs: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Process batch of network log lines or normalized dicts and return standard structured SecurityEvent dicts.
        """
        if not logs or not isinstance(logs, list):
            return []

        events: List[SecurityEvent] = []
        ip_scanned_ports: Dict[str, Dict[int, List[str]]] = {}
        ip_connection_bursts: Dict[str, int] = {}
        parsed_entries = []

        for line in logs:
            try:
                parsed = self.parse_network_line(line)
                if not parsed:
                    continue
                parsed_entries.append(parsed)

                src = parsed["source_ip"]
                port = parsed["port"]

                if src and port:
                    if src not in ip_scanned_ports:
                        ip_scanned_ports[src] = {}
                    if port not in ip_scanned_ports[src]:
                        ip_scanned_ports[src][port] = []
                    ip_scanned_ports[src][port].append(parsed["raw"])

                if src:
                    ip_connection_bursts[src] = ip_connection_bursts.get(src, 0) + 1

                # Check for individual high-risk signatures (e.g. suspicious ports: 4444, 31337, 1337, 6667, 5555)
                if port in [4444, 31337, 1337, 6667, 5555]:
                    events.append(SecurityEvent(
                        agent_name="Network Monitoring Agent",
                        event_type="Suspicious Port Activity",
                        severity="HIGH",
                        source="Network Flow Telemetry",
                        description=f"Direct connection activity observed targeting known suspicious backdoor/Trojan/C2 port {port}.",
                        indicators={
                            "source_ip": src,
                            "destination_ip": parsed["destination_ip"],
                            "targeted_port": port,
                            "protocol": parsed["protocol"],
                            "process_name": parsed.get("process_name"),
                            "raw_log": parsed["raw"]
                        },
                        recommended_action="Inspect source host reputation and verify whether targeted port is an authorized listener."
                    ))

            except Exception as e:
                logger.warning(f"Error parsing network line: {e}")
                continue

        # Aggregated Rule 1: Port Scan Detection
        for ip, ports_dict in ip_scanned_ports.items():
            unique_ports = list(ports_dict.keys())
            if len(unique_ports) >= self.port_scan_threshold:
                evidence = []
                for p in unique_ports[:5]:
                    evidence.extend(ports_dict[p][:1])

                events.append(SecurityEvent(
                    agent_name="Network Monitoring Agent",
                    event_type="Port Scanning",
                    severity="HIGH",
                    source="Network Flow Analyzer",
                    description=f"Horizontal/Vertical port scan detected from host {ip} probing {len(unique_ports)} distinct ports.",
                    indicators={
                        "source_ip": ip,
                        "probed_ports_count": len(unique_ports),
                        "ports_sample": unique_ports[:10],
                        "evidence_sample": evidence
                    },
                    recommended_action=f"Apply temporary rate-limiting or firewall drop rule for IP {ip}; review perimeter access control list."
                ))

        # Aggregated Rule 2: Connection Burst / Volume Anomaly
        for ip, count in ip_connection_bursts.items():
            if count >= self.burst_threshold:
                events.append(SecurityEvent(
                    agent_name="Network Monitoring Agent",
                    event_type="High-Volume Network Burst",
                    severity="MEDIUM",
                    source="Flow Rate Monitor",
                    description=f"Abnormally high connection frequency ({count} requests) observed from {ip}.",
                    indicators={
                        "source_ip": ip,
                        "connection_count": count,
                        "threshold": self.burst_threshold
                    },
                    recommended_action=f"Monitor host {ip} for potential denial of service or automated scanning tool activity."
                ))

        return [e.to_dict() for e in events]
