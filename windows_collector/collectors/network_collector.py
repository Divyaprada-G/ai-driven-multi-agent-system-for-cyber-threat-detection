"""
Safe, Passive Network Telemetry Collector
Collects socket states, listening ports, and interface metrics from local host tables.
Explicitly non-intrusive: does NOT send scan packets, does NOT execute offensive probes,
and explicitly declares socket-level (non-packet) telemetry.
"""
import sys
import os
import re
import socket
import subprocess
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from windows_collector.normalizer import EventNormalizer

logger = logging.getLogger("NetworkTelemetryCollector")

class NetworkTelemetryCollector:
    """
    Collects passive local network socket states and interface configurations.
    Non-intrusive, zero external probing.
    """
    def __init__(
        self,
        normalizer: EventNormalizer,
        max_batch_size: int = 50,
        monitored_ports: Optional[List[int]] = None
    ):
        self.normalizer = normalizer
        self.max_batch_size = max_batch_size
        self.monitored_ports = monitored_ports or [21, 22, 23, 25, 80, 443, 445, 1433, 3000, 3389, 8080]
        
        # State tracking
        self.last_sockets_count = 0
        self.last_listening_ports: List[int] = []
        self.status = "INITIALIZING"
        self.last_error = None
        self.events_collected = 0

    def get_status(self) -> Dict[str, Any]:
        return {
            "collector_name": "NetworkTelemetryCollector",
            "telemetry_type": "socket_and_interface_state",
            "is_packet_sniffing": False,
            "status": self.status,
            "last_error": self.last_error,
            "events_collected": self.events_collected,
            "last_listening_ports": self.last_listening_ports,
            "active_sockets_count": self.last_sockets_count
        }

    def collect(self) -> List[Dict[str, Any]]:
        """
        Gathers local active TCP sockets and listening ports using safe OS utilities (netstat).
        """
        all_events: List[Dict[str, Any]] = []

        try:
            # 1. Query interface info
            interfaces = self._get_local_interfaces()

            # 2. Query active sockets safely
            connections = self._get_active_connections()
            self.last_sockets_count = len(connections)

            # 3. Extract listening ports
            listening_ports = sorted(list(set(
                c["local_port"] for c in connections if c.get("state") == "LISTENING" and c.get("local_port")
            )))
            self.last_listening_ports = listening_ports

            # 4. Check for anomalous connection states (e.g., SYN_SENT floods, suspicious ports)
            syn_sent_connections = [c for c in connections if c.get("state") == "SYN_SENT"]
            suspicious_external = []
            for c in connections:
                foreign_port = c.get("foreign_port")
                state = c.get("state", "")
                foreign_ip = c.get("foreign_ip", "")
                # Flag connections to sensitive administrative ports
                if foreign_port in [4444, 1337, 31337, 6667] and foreign_ip not in ["127.0.0.1", "0.0.0.0"]:
                    suspicious_external.append(c)

            # Generate Periodic Network State Telemetry
            now_iso = datetime.now(timezone.utc).isoformat()
            raw_summary = (
                f"ActiveSockets: {len(connections)}, "
                f"ListeningPorts: {listening_ports[:15]}, "
                f"Interfaces: {[i['ip'] for i in interfaces]}"
            )

            # Base periodic state event
            base_event = self.normalizer.normalize(
                source_type="network_telemetry",
                collector_name="NetworkTelemetryCollector",
                raw_message=raw_summary,
                collection_status="COLLECTED",
                timestamp=now_iso,
                source="network",
                event_type="Network Socket & Interface Telemetry",
                severity="LOW",
                source_ip=interfaces[0]["ip"] if interfaces else "127.0.0.1",
                destination_ip="127.0.0.1",
                details=f"Passive socket inspection: {len(connections)} active sockets, {len(listening_ports)} listening ports.",
                features={
                    "total_sockets": len(connections),
                    "listening_ports_count": len(listening_ports),
                    "syn_sent_count": len(syn_sent_connections),
                    "is_packet_sniffing": False
                },
                custom_metadata={
                    "telemetry_type": "socket_and_interface_state",
                    "inspection_mode": "passive_local_tables",
                    "interfaces_count": len(interfaces)
                }
            )
            if base_event:
                all_events.append(base_event)

            # If anomalous SYN_SENT flood is observed (possible outbound port scan or unresponsive target)
            if len(syn_sent_connections) >= 5:
                syn_event = self.normalizer.normalize(
                    source_type="network_telemetry",
                    collector_name="NetworkTelemetryCollector",
                    raw_message=f"High volume of SYN_SENT sockets detected: {len(syn_sent_connections)} connections pending.",
                    collection_status="COLLECTED",
                    timestamp=now_iso,
                    source="network",
                    event_type="Anomalous Socket State: High SYN_SENT Volume",
                    severity="MEDIUM",
                    details=f"High SYN_SENT state count ({len(syn_sent_connections)}) indicates potential outbound port sweep or half-open connections.",
                    features={
                        "syn_sent_count": len(syn_sent_connections),
                        "mitre_technique": "T1046"
                    }
                )
                if syn_event:
                    all_events.append(syn_event)

            # If connections to high-risk malware/reverse-shell ports observed
            for susp in suspicious_external:
                susp_event = self.normalizer.normalize(
                    source_type="network_telemetry",
                    collector_name="NetworkTelemetryCollector",
                    raw_message=f"Suspicious foreign connection detected: {susp.get('foreign_ip')}:{susp.get('foreign_port')} (PID {susp.get('pid')})",
                    collection_status="COLLECTED",
                    timestamp=now_iso,
                    source="network",
                    event_type="Suspicious Socket Connection to High-Risk Port",
                    severity="HIGH",
                    source_ip="127.0.0.1",
                    destination_ip=susp.get("foreign_ip", "0.0.0.0"),
                    destination_port=susp.get("foreign_port"),
                    details=f"Established socket to suspicious port {susp.get('foreign_port')} by PID {susp.get('pid')}.",
                    features={
                        "foreign_port": susp.get("foreign_port"),
                        "pid": susp.get("pid"),
                        "mitre_technique": "T1071"
                    }
                )
                if susp_event:
                    all_events.append(susp_event)

            self.status = "LIVE"
            self.last_error = None
            self.events_collected += len(all_events)
        except Exception as e:
            self.status = "ERROR"
            self.last_error = str(e)
            logger.error(f"Error collecting network socket telemetry: {e}")

        return all_events

    def _get_local_interfaces(self) -> List[Dict[str, Any]]:
        """
        Enumerates local network interfaces safely using standard library.
        """
        interfaces: List[Dict[str, Any]] = []
        try:
            hostname = socket.gethostname()
            # Primary host IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.2)
                s.connect(("8.8.8.8", 80))
                primary_ip = s.getsockname()[0]
                s.close()
                interfaces.append({"name": "Primary Adapter", "ip": primary_ip, "is_loopback": False})
            except Exception:
                pass

            # Loopback
            interfaces.append({"name": "Loopback", "ip": "127.0.0.1", "is_loopback": True})
        except Exception as e:
            logger.debug(f"Interface lookup notice: {e}")

        return interfaces

    def _get_active_connections(self) -> List[Dict[str, Any]]:
        """
        Parses active TCP connection table via OS-native netstat command.
        Compatible with Windows, Linux, and macOS.
        """
        connections: List[Dict[str, Any]] = []
        is_win = sys.platform == "win32"

        cmd = ["netstat", "-ano"] if is_win else ["netstat", "-ant"]

        try:
            startupinfo = None
            if is_win:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=6,
                startupinfo=startupinfo
            )
            if res.returncode != 0 or not res.stdout:
                return []

            lines = res.stdout.splitlines()
            for line in lines:
                parsed = self._parse_netstat_line(line)
                if parsed:
                    connections.append(parsed)
        except Exception as e:
            logger.debug(f"Netstat query note: {e}")

        return connections

    def _parse_netstat_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single line from 'netstat -ano' or 'netstat -ant'.
        """
        parts = line.strip().split()
        if not parts or len(parts) < 4:
            return None

        proto = parts[0].upper()
        if not proto.startswith("TCP") and not proto.startswith("UDP"):
            return None

        try:
            local_addr = parts[1]
            foreign_addr = parts[2]
            
            # Split host and port (handles IPv4 and IPv6)
            local_ip, local_port = self._split_ip_port(local_addr)
            foreign_ip, foreign_port = self._split_ip_port(foreign_addr)

            state = "LISTENING" if "LIST" in parts[3].upper() else parts[3].upper() if len(parts) > 3 else "UNKNOWN"
            pid = parts[4] if len(parts) >= 5 else None

            return {
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "foreign_ip": foreign_ip,
                "foreign_port": foreign_port,
                "state": state,
                "pid": pid
            }
        except Exception:
            return None

    def _split_ip_port(self, addr_str: str) -> (str, Optional[int]):
        """
        Splits IP:Port or [IPv6]:Port string.
        """
        if not addr_str or addr_str == "*:*":
            return "*", None

        # IPv6 format e.g. [::1]:80 or [::]:3000
        if addr_str.startswith("["):
            end_bracket = addr_str.find("]")
            if end_bracket > 0:
                ip = addr_str[1:end_bracket]
                port_str = addr_str[end_bracket+2:] if len(addr_str) > end_bracket + 2 else None
                port = int(port_str) if port_str and port_str.isdigit() else None
                return ip, port

        # IPv4 format e.g. 127.0.0.1:3000 or 0.0.0.0:80
        if ":" in addr_str:
            last_colon = addr_str.rfind(":")
            ip = addr_str[:last_colon]
            port_str = addr_str[last_colon+1:]
            port = int(port_str) if port_str and port_str.isdigit() else None
            return ip, port

        return addr_str, None
