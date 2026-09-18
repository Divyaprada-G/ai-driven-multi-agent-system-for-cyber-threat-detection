"""
Safe, Passive Network Telemetry Collector
Collects socket states, listening ports, active connections, and interface metrics from local host tables.
Explicitly non-intrusive: does NOT send scan packets, does NOT execute offensive probes,
does NOT inspect packet payloads (passive socket tables only), and follows least-privilege principles.
"""
import sys
import os
import re
import socket
import subprocess
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from windows_collector.normalizer import EventNormalizer, is_valid_ip, is_valid_port, is_valid_protocol

logger = logging.getLogger("NetworkTelemetryCollector")

class NetworkTelemetryCollector:
    """
    Collects passive local network socket states, active connections, and interface configurations.
    Non-intrusive, zero external probing or packet sniffing.
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
        
        # Process name resolution cache (PID -> process name)
        self._process_cache: Dict[str, str] = {}

        # State tracking
        self.last_sockets_count = 0
        self.last_listening_ports: List[int] = []
        self.last_active_connections: List[Dict[str, Any]] = []
        self.status = "INITIALIZING"
        self.last_error: Optional[str] = None
        self.events_collected = 0
        self.last_event_timestamp: Optional[str] = None

    def get_status(self) -> Dict[str, Any]:
        return {
            "collector_name": "NetworkTelemetryCollector",
            "telemetry_type": "socket_and_interface_state",
            "telemetry_source": "OS_SOCKET_TABLES",
            "is_packet_sniffing": False,
            "status": self.status,
            "last_error": self.last_error,
            "events_collected": self.events_collected,
            "last_event_timestamp": self.last_event_timestamp,
            "last_listening_ports": self.last_listening_ports,
            "active_sockets_count": self.last_sockets_count,
            "active_connections_sample": self.last_active_connections[:10]
        }

    def collect(self) -> List[Dict[str, Any]]:
        """
        Gathers local active TCP/UDP sockets, connection states, process associations, and listening ports.
        Emits normalized connection telemetry events conforming strictly to Upgrade 5 schema.
        """
        all_events: List[Dict[str, Any]] = []

        try:
            # 1. Query interface info
            interfaces = self._get_local_interfaces()
            primary_ip = interfaces[0]["ip"] if interfaces else "127.0.0.1"

            # 2. Query active sockets safely from local OS tables
            connections = self._get_active_connections()
            self.last_sockets_count = len(connections)
            self.last_active_connections = connections

            # 3. Extract listening ports
            listening_ports = sorted(list(set(
                c["local_port"] for c in connections if c.get("state") == "LISTENING" and c.get("local_port")
            )))
            self.last_listening_ports = listening_ports

            # 4. Check for anomalous connection states (e.g., SYN_SENT floods, suspicious ports)
            syn_sent_connections = [c for c in connections if c.get("state") == "SYN_SENT"]
            now_iso = datetime.now(timezone.utc).isoformat()
            self.last_event_timestamp = now_iso

            # 5. Emit normalized events for distinct active connections (Requirement: Active network connections)
            # Bound per-cycle to avoid flooding, deduplicator drops previously seen active sockets
            connections_to_emit = connections[:self.max_batch_size]

            for conn in connections_to_emit:
                loc_ip = conn.get("local_ip") or primary_ip
                loc_port = conn.get("local_port") or 0
                rem_ip = conn.get("foreign_ip") or "0.0.0.0"
                rem_port = conn.get("foreign_port") or 0
                proto = conn.get("protocol") or "TCP"
                state = conn.get("state") or "UNKNOWN"
                pid = conn.get("pid")
                proc_name = conn.get("process_name") or self._resolve_process_name(pid)

                # Validation of IP, port, protocol
                valid_ips = is_valid_ip(loc_ip) and is_valid_ip(rem_ip)
                valid_ports = is_valid_port(loc_port) and is_valid_port(rem_port)
                valid_proto = is_valid_protocol(proto)

                col_status = "COLLECTED"
                if not (valid_ips and valid_ports and valid_proto):
                    col_status = "VALIDATION_FAILED"
                elif proc_name == "RESTRICTED_ACCESS":
                    col_status = "RESTRICTED_ACCESS"

                # Check if this connection targets a high-risk / backdoor port
                is_suspicious_port = rem_port in [4444, 1337, 31337, 6667, 5555] and rem_ip not in ["127.0.0.1", "0.0.0.0"]
                severity = "HIGH" if is_suspicious_port else "MEDIUM" if state == "SYN_SENT" else "LOW"
                event_type = "Suspicious Socket Connection" if is_suspicious_port else (
                    "Socket Listening State" if state == "LISTENING" else "Active Network Connection"
                )

                raw_msg = (
                    f"Proto={proto} Local={loc_ip}:{loc_port} Foreign={rem_ip}:{rem_port} "
                    f"State={state} PID={pid or 'N/A'} Proc={proc_name or 'Unknown'}"
                )

                event = self.normalizer.normalize(
                    source_type="network_telemetry",
                    collector_name="NetworkTelemetryCollector",
                    raw_message=raw_msg,
                    collection_status=col_status,
                    timestamp=now_iso,
                    source="network",
                    event_type=event_type,
                    severity=severity,
                    source_ip=loc_ip,
                    destination_ip=rem_ip,
                    source_port=loc_port,
                    destination_port=rem_port,
                    local_ip=loc_ip,
                    remote_ip=rem_ip,
                    local_port=loc_port,
                    remote_port=rem_port,
                    protocol=proto,
                    connection_state=state,
                    process_name=proc_name,
                    details=f"Passive socket inspection: {proto} {loc_ip}:{loc_port} -> {rem_ip}:{rem_port} ({state})",
                    features={
                        "Destination Port": rem_port,
                        "Flow Duration": 1000.0,
                        "Total Fwd Packets": 2,
                        "Total Backward Packets": 2,
                        "Flow Bytes/s": 500.0,
                        "Flow Packets/s": 2.0,
                        "SYN Flag Count": 1 if state == "SYN_SENT" else 0,
                        "ACK Flag Count": 1 if state == "ESTABLISHED" else 0
                    },
                    custom_metadata={
                        "telemetry_type": "socket_connection",
                        "inspection_mode": "passive_local_tables",
                        "pid": pid,
                        "process_name": proc_name,
                        "connection_state": state
                    }
                )

                if event:
                    all_events.append(event)

            # 6. Base periodic state summary event (if no connection events were emitted or for heartbeat)
            if not all_events:
                raw_summary = (
                    f"ActiveSockets: {len(connections)}, "
                    f"ListeningPorts: {listening_ports[:15]}, "
                    f"Interfaces: {[i['ip'] for i in interfaces]}"
                )
                base_event = self.normalizer.normalize(
                    source_type="network_telemetry",
                    collector_name="NetworkTelemetryCollector",
                    raw_message=raw_summary,
                    collection_status="COLLECTED",
                    timestamp=now_iso,
                    source="network",
                    event_type="Network Socket & Interface Telemetry",
                    severity="LOW",
                    source_ip=primary_ip,
                    destination_ip="0.0.0.0",
                    source_port=0,
                    destination_port=listening_ports[0] if listening_ports else 3000,
                    local_ip=primary_ip,
                    remote_ip="0.0.0.0",
                    local_port=0,
                    remote_port=listening_ports[0] if listening_ports else 3000,
                    protocol="TCP",
                    connection_state="LISTENING" if listening_ports else "IDLE",
                    process_name=None,
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
            # Primary host IP via standard socket connect (no traffic transmitted)
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

    def _resolve_process_name(self, pid: Optional[str]) -> Optional[str]:
        """
        Safely resolves process executable name given a PID.
        Follows least-privilege principles and handles permission restrictions gracefully.
        """
        if not pid or pid in ["0", "-", "N/A"]:
            return None

        if pid in self._process_cache:
            return self._process_cache[pid]

        # Windows resolution
        if sys.platform == "win32":
            try:
                cmd = ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]
                kwargs = {}
                if hasattr(subprocess, "STARTUPINFO"):
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    kwargs["startupinfo"] = startupinfo
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2, **kwargs)
                if res.returncode == 0 and res.stdout:
                    # e.g. "node.exe","1234","Console","1","50,124 K"
                    lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                    if lines and not lines[0].startswith("INFO:"):
                        proc_name = lines[0].split(",")[0].replace('"', '')
                        self._process_cache[pid] = proc_name
                        return proc_name
            except Exception:
                return "RESTRICTED_ACCESS"

        # Linux resolution via /proc
        try:
            comm_path = f"/proc/{pid}/comm"
            if os.path.exists(comm_path):
                with open(comm_path, "r") as f:
                    name = f.read().strip()
                    self._process_cache[pid] = name
                    return name
        except (PermissionError, IOError):
            return "RESTRICTED_ACCESS"
        except Exception:
            pass

        return None

    def _parse_netstat_windows(self, custom_output: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parses Windows netstat -ano output.
        If custom_output is provided (e.g. in tests), parses that text directly.
        Otherwise executes netstat -ano via subprocess.
        """
        connections: List[Dict[str, Any]] = []
        stdout = custom_output

        if stdout is None:
            try:
                kwargs = {}
                if hasattr(subprocess, "STARTUPINFO"):
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    kwargs["startupinfo"] = startupinfo
                res = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    **kwargs
                )
                if res.returncode == 0 and res.stdout:
                    stdout = res.stdout
            except Exception as e:
                logger.debug(f"Windows netstat query note: {e}")
                return []

        if stdout:
            for line in stdout.splitlines():
                parsed = self._parse_netstat_line(line)
                if parsed:
                    connections.append(parsed)

        return connections

    def _get_active_connections(self) -> List[Dict[str, Any]]:
        """
        Parses active TCP connection table via OS-native netstat or ss commands.
        Compatible with Windows (netstat -ano / PowerShell), Linux (ss -tunap / netstat), and macOS.
        """
        connections: List[Dict[str, Any]] = []
        is_win = sys.platform == "win32"

        # Primary command selection based on OS
        if is_win:
            connections = self._parse_netstat_windows()
            if connections:
                return connections

        # Linux / Unix environment: prefer 'ss -tunap', fallback to 'ss -tuna', then 'netstat -ant'
        for cmd in [["ss", "-tunap"], ["ss", "-tuna"], ["netstat", "-ant"], ["netstat", "-ano"]]:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0 and res.stdout:
                    for line in res.stdout.splitlines():
                        parsed = self._parse_ss_line(line) if cmd[0] == "ss" else self._parse_netstat_line(line)
                        if parsed:
                            connections.append(parsed)
                    if connections:
                        return connections
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.debug(f"Command {cmd} query note: {e}")

        # If OS utilities unavailable, record status note
        if not connections:
            self.last_error = "OS socket inspection utilities (netstat/ss) unavailable or returned empty."

        return connections

    def _parse_ss_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single line from 'ss -tuna' or 'ss -tunap'.
        Example line:
        tcp   LISTEN 0 0 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=349,fd=24))
        """
        parts = line.strip().split()
        if not parts or len(parts) < 5:
            return None

        proto = parts[0].upper()
        if not (proto.startswith("TCP") or proto.startswith("UDP")):
            return None

        try:
            # Map ss states to standard TCP states
            raw_state = parts[1].upper()
            state_map = {
                "LISTEN": "LISTENING",
                "ESTAB": "ESTABLISHED",
                "TIME-WAIT": "TIME_WAIT",
                "CLOSE-WAIT": "CLOSE_WAIT",
                "FIN-WAIT-1": "FIN_WAIT_1",
                "FIN-WAIT-2": "FIN_WAIT_2",
                "SYN-SENT": "SYN_SENT",
                "SYN-RECV": "SYN_RECV",
                "LAST-ACK": "LAST_ACK",
                "CLOSING": "CLOSING",
                "UNCONN": "UNCONNECTED"
            }
            state = state_map.get(raw_state, raw_state)

            local_addr = parts[4]
            foreign_addr = parts[5] if len(parts) > 5 else "*:*"

            local_ip, local_port = self._split_ip_port(local_addr)
            foreign_ip, foreign_port = self._split_ip_port(foreign_addr)

            # Process / PID extraction from users:(("node",pid=349,fd=24))
            proc_name = None
            pid = None
            if len(parts) >= 7 and "pid=" in parts[6]:
                pid_match = re.search(r'pid=([0-9]+)', parts[6])
                if pid_match:
                    pid = pid_match.group(1)
                proc_match = re.search(r'"([^"]+)"', parts[6])
                if proc_match:
                    proc_name = proc_match.group(1)

            return {
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port or 0,
                "foreign_ip": foreign_ip,
                "foreign_port": foreign_port or 0,
                "state": state,
                "pid": pid,
                "process_name": proc_name
            }
        except Exception:
            return None

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

            if proto.startswith("UDP"):
                state = "UNCONNECTED"
                pid = parts[3] if len(parts) >= 4 else None
            else:
                state = "LISTENING" if "LIST" in parts[3].upper() else parts[3].upper() if len(parts) > 3 else "UNKNOWN"
                pid = parts[4] if len(parts) >= 5 else None

            return {
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "foreign_ip": foreign_ip,
                "foreign_port": foreign_port,
                "remote_ip": foreign_ip,
                "remote_port": foreign_port,
                "state": state,
                "connection_state": state,
                "pid": pid
            }
        except Exception:
            return None

    def _split_ip_port(self, addr_str: str) -> (str, Optional[int]):
        """
        Splits IP:Port or [IPv6]:Port string.
        """
        if not addr_str or addr_str in ["*:*", "*:*.*", ":::*"]:
            return "*", None

        # IPv6 format e.g. [::1]:80 or [::]:3000 or [::ffff:127.0.0.1]:8000
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
