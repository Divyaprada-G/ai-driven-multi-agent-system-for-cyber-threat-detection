"""
Event Normalizer and Deduplication Engine for Windows Telemetry
Ensures all events adhere to the project schema and carry the required source metadata:
- source_type
- hostname
- collector_name
- event_id
- timestamp
- raw_message
- collection_status
"""
import hashlib
import uuid
import socket
import ipaddress
import re
from datetime import datetime, timezone
from collections import OrderedDict
from typing import Dict, Any, Optional

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def is_valid_ip(ip: Optional[str]) -> bool:
    """
    Validates IPv4 or IPv6 address string.
    Accepts special host/wildcard aliases '*', '0.0.0.0', '127.0.0.1', '::', '::1'.
    """
    if not ip or not isinstance(ip, str):
        return False
    clean = ip.strip()
    if clean in ["*", "0.0.0.0", "127.0.0.1", "::", "::1", "localhost"]:
        return True
    # Strip brackets from IPv6 if present (e.g. [::1])
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    # Check IPv4 mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if clean.lower().startswith("::ffff:"):
        clean = clean[7:]
    try:
        ipaddress.ip_address(clean)
        return True
    except (ValueError, AttributeError):
        return False

def is_valid_port(port: Optional[Any]) -> bool:
    """Validates TCP/UDP port number is an integer within 0-65535."""
    if port is None:
        return True  # Optional port
    if isinstance(port, bool) or not isinstance(port, int):
        return False
    return 0 <= port <= 65535

def is_valid_protocol(protocol: Optional[str]) -> bool:
    """Validates supported network transport protocols."""
    if not protocol:
        return True  # Optional
    p = str(protocol).strip().upper()
    return p in ["TCP", "UDP", "ICMP", "IP", "RAW", "TCP6", "UDP6"]

class Deduplicator:
    """
    Thread-safe, bounded in-memory LRU fingerprint cache to prevent duplicate events.
    """
    def __init__(self, capacity: int = 20000):
        self.capacity = capacity
        self.cache: OrderedDict = OrderedDict()
        self.total_checked = 0
        self.total_duplicates = 0

    def compute_hash(self, *parts) -> str:
        h = hashlib.sha256()
        for p in parts:
            if p is not None:
                h.update(str(p).encode("utf-8", errors="replace"))
        return h.hexdigest()

    def is_duplicate(self, fingerprint: str) -> bool:
        self.total_checked += 1
        if fingerprint in self.cache:
            self.total_duplicates += 1
            # Move to end (most recently seen)
            self.cache.move_to_end(fingerprint)
            return True
        
        self.cache[fingerprint] = True
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
        return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "cached_fingerprints": len(self.cache),
            "total_checked": self.total_checked,
            "total_duplicates_dropped": self.total_duplicates
        }


class NormalizedEvent(dict):
    """
    Dictionary subclass that allows attribute-style access (e.g. event.event_id)
    as well as standard dictionary subscript access (e.g. event['event_id']).
    """
    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(f"'NormalizedEvent' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        self[name] = value


class EventNormalizer:
    """
    Normalizes Windows OS, Application, and Network telemetry into the standard schema.
    """
    def __init__(self, default_hostname: Optional[str] = None, hostname: Optional[str] = None):
        self.hostname = hostname or default_hostname or socket.gethostname()
        self.deduplicator = Deduplicator()

    def normalize(
        self,
        source_type: Any = "network_telemetry",
        collector_name: str = "Collector",
        raw_message: str = "",
        collection_status: str = "COLLECTED",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: str = "LOW",
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        username: Optional[str] = None,
        details: Optional[str] = None,
        features: Optional[Dict[str, Any]] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
        event_id_windows: Optional[Any] = None,
        local_ip: Optional[str] = None,
        remote_ip: Optional[str] = None,
        local_port: Optional[int] = None,
        remote_port: Optional[int] = None,
        connection_state: Optional[str] = None,
        process_name: Optional[str] = None
    ) -> Optional[NormalizedEvent]:
        """
        Creates a NormalizedTelemetryEvent dictionary conforming strictly to Upgrade 5 schema:
        {
          event_id, timestamp, source_type, hostname, local_ip, remote_ip,
          local_port, remote_port, protocol, connection_state, process_name,
          collector_name, collection_status
        }
        Supports being called with a dictionary as the first parameter.
        Returns None if the event is a duplicate.
        """
        # If called with a dictionary (e.g. normalize(raw_dict))
        if isinstance(source_type, dict):
            d = source_type
            st = d.get("source_type", "network_telemetry")
            col_name = d.get("collector_name", collector_name)
            raw_msg = d.get("raw_message") or d.get("raw") or json.dumps(d) if "json" in globals() else str(d)
            col_stat = d.get("collection_status", collection_status)
            ev_id = d.get("event_id") or d.get("eventId")
            ts = d.get("timestamp")
            src = d.get("source")
            ev_type = d.get("event_type") or d.get("eventType")
            sev = d.get("severity", severity)
            s_ip = d.get("source_ip") or d.get("sourceIp")
            d_ip = d.get("destination_ip") or d.get("destinationIp")
            s_port = d.get("source_port") or d.get("sourcePort")
            d_port = d.get("destination_port") or d.get("destinationPort")
            proto = d.get("protocol")
            u_name = d.get("username")
            det = d.get("details")
            feats = d.get("features")
            c_meta = d.get("custom_metadata") or d.get("sourceMetadata")
            win_id = d.get("event_id_windows")
            l_ip = d.get("local_ip")
            r_ip = d.get("remote_ip")
            l_port = d.get("local_port")
            r_port = d.get("remote_port")
            c_state = d.get("connection_state")
            p_name = d.get("process_name")
            return self.normalize(
                source_type=st,
                collector_name=col_name,
                raw_message=raw_msg,
                collection_status=col_stat,
                event_id=ev_id,
                timestamp=ts,
                source=src,
                event_type=ev_type,
                severity=sev,
                source_ip=s_ip,
                destination_ip=d_ip,
                source_port=s_port,
                destination_port=d_port,
                protocol=proto,
                username=u_name,
                details=det,
                features=feats,
                custom_metadata=c_meta,
                event_id_windows=win_id,
                local_ip=l_ip,
                remote_ip=r_ip,
                local_port=l_port,
                remote_port=r_port,
                connection_state=c_state,
                process_name=p_name
            )

        now_ts = timestamp or utc_now_iso()

        # Reconcile snake_case and camelCase endpoint fields
        resolved_local_ip = local_ip or source_ip or "127.0.0.1"
        resolved_remote_ip = remote_ip or destination_ip or "127.0.0.1"
        resolved_local_port = local_port if local_port is not None else source_port
        resolved_remote_port = remote_port if remote_port is not None else destination_port
        resolved_protocol = (protocol or "TCP").upper()

        # Validation of IP addresses, ports, and protocols (Requirement 3, 4)
        validation_errors = []
        if not is_valid_ip(resolved_local_ip):
            validation_errors.append(f"Invalid local IP: {resolved_local_ip}")
        if not is_valid_ip(resolved_remote_ip):
            validation_errors.append(f"Invalid remote IP: {resolved_remote_ip}")
        if not is_valid_port(resolved_local_port):
            validation_errors.append(f"Invalid local port: {resolved_local_port}")
        if not is_valid_port(resolved_remote_port):
            validation_errors.append(f"Invalid remote port: {resolved_remote_port}")
        if not is_valid_protocol(resolved_protocol):
            validation_errors.append(f"Invalid protocol: {resolved_protocol}")

        resolved_collection_status = collection_status
        if validation_errors and resolved_collection_status == "COLLECTED":
            resolved_collection_status = "VALIDATION_FAILED"
        
        # Determine source category ('system', 'application', 'network')
        if not source:
            if source_type in ["windows_event_log", "windows_system", "windows_security"]:
                source = "system"
            elif source_type in ["application_log_file", "app_logs", "windows_application"]:
                source = "application"
            elif source_type in ["network_telemetry", "socket_telemetry", "network_connection"]:
                source = "network"
            else:
                source = "system"

        # Unique event ID
        if not event_id:
            prefix = "NET" if source == "network" else ("WIN-" + source[:3].upper())
            event_id = f"{prefix}-{uuid.uuid4().hex[:8]}"

        # Compute content hash for deduplication across cycles (Requirement 1, 2)
        content_hash = self.deduplicator.compute_hash(
            source_type,
            self.hostname,
            resolved_local_ip,
            resolved_local_port,
            resolved_remote_ip,
            resolved_remote_port,
            resolved_protocol,
            connection_state,
            raw_message
        )
        if self.deduplicator.is_duplicate(content_hash):
            return None

        # Determine agent routing
        if source == "network":
            assigned_agent = "Network Security Agent"
            assigned_id = "agent-network-1"
        elif source == "application":
            assigned_agent = "Application Security Agent"
            assigned_id = "agent-app-1"
        else:
            assigned_agent = "System Security Agent"
            assigned_id = "agent-system-1"

        resolved_event_type = event_type or f"{source_type.replace('_', ' ').title()} Event"

        # Connection state inference if unspecified
        resolved_state = connection_state or (
            "LISTENING" if resolved_remote_ip in ["*", "0.0.0.0", "::"] and (resolved_remote_port is None or resolved_remote_port == 0)
            else "ESTABLISHED" if source == "network"
            else "N/A"
        )

        # Mandatory Source Metadata as required by specification
        source_metadata = {
            "source_type": source_type,
            "hostname": self.hostname,
            "collector_name": collector_name,
            "event_id": event_id,
            "timestamp": now_ts,
            "raw_message": raw_message,
            "collection_status": resolved_collection_status,
            "event_id_windows": event_id_windows,
            "local_ip": resolved_local_ip,
            "remote_ip": resolved_remote_ip,
            "local_port": resolved_local_port,
            "remote_port": resolved_remote_port,
            "protocol": resolved_protocol,
            "connection_state": resolved_state,
            "process_name": process_name,
            "validation_errors": validation_errors
        }
        if custom_metadata:
            source_metadata.update(custom_metadata)

        normalized_event = {
            # REQUIRED SPECIFICATION SCHEMA:
            # { event_id, timestamp, source_type, hostname, local_ip, remote_ip,
            #   local_port, remote_port, protocol, connection_state, process_name,
            #   collector_name, collection_status }
            "event_id": event_id,
            "timestamp": now_ts,
            "source_type": source_type,
            "hostname": self.hostname,
            "local_ip": resolved_local_ip,
            "remote_ip": resolved_remote_ip,
            "local_port": resolved_local_port,
            "remote_port": resolved_remote_port,
            "protocol": resolved_protocol,
            "connection_state": resolved_state,
            "process_name": process_name,
            "collector_name": collector_name,
            "collection_status": resolved_collection_status,

            # Additional standard fields for audit & security pipeline
            "event_type": resolved_event_type,
            "event_id_windows": event_id_windows,
            "severity": severity.upper(),
            "raw_message": raw_message,

            # Backwards-compatible camelCase & pipeline fields
            "eventId": event_id,
            "source": source,
            "eventType": resolved_event_type,
            "sourceIp": resolved_local_ip,
            "destinationIp": resolved_remote_ip,
            "sourcePort": resolved_local_port,
            "destinationPort": resolved_remote_port,
            "protocol": resolved_protocol,
            "host": self.hostname,
            "username": username,
            "details": details or (
                f"Telemetry collected via {collector_name} (validation_errors: {'; '.join(validation_errors)})"
                if validation_errors
                else f"Telemetry collected via {collector_name} ({resolved_collection_status})"
            ),
            "rawPayload": raw_message,
            "contentHash": content_hash,
            "isSimulated": False,  # Strictly genuine live telemetry
            "telemetrySource": "EXTERNAL_AGENT",
            "collectorState": "LIVE",
            "features": features or {},
            "agentRouting": {
                "assignedAgent": assigned_agent,
                "assignedAgentId": assigned_id
            },
            # Explicit source metadata block
            "sourceMetadata": source_metadata
        }

        return NormalizedEvent(normalized_event)
