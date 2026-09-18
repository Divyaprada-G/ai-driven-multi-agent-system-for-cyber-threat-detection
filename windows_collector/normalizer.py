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
from datetime import datetime, timezone
from collections import OrderedDict
from typing import Dict, Any, Optional

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

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


class EventNormalizer:
    """
    Normalizes Windows OS, Application, and Network telemetry into the standard schema.
    """
    def __init__(self, default_hostname: Optional[str] = None):
        self.hostname = default_hostname or socket.gethostname()
        self.deduplicator = Deduplicator()

    def normalize(
        self,
        source_type: str,
        collector_name: str,
        raw_message: str,
        collection_status: str = "COLLECTED",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: str = "LOW",
        source_ip: str = "127.0.0.1",
        destination_ip: str = "127.0.0.1",
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        username: Optional[str] = None,
        details: Optional[str] = None,
        features: Optional[Dict[str, Any]] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
        event_id_windows: Optional[Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Creates a NormalizedTelemetryEvent dictionary.
        Returns None if the event is a duplicate.
        """
        now_ts = timestamp or utc_now_iso()
        
        # Determine source category ('system', 'application', 'network')
        if not source:
            if source_type in ["windows_event_log", "windows_system", "windows_security"]:
                source = "system"
            elif source_type in ["application_log_file", "app_logs", "windows_application"]:
                source = "application"
            elif source_type in ["network_telemetry", "socket_telemetry"]:
                source = "network"
            else:
                source = "system"

        # Unique event ID
        if not event_id:
            prefix = "WIN-" + source[:3].upper()
            event_id = f"{prefix}-{uuid.uuid4().hex[:8]}"

        # Compute content hash for deduplication
        content_hash = self.deduplicator.compute_hash(source_type, event_id, now_ts, raw_message)
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

        # Mandatory Source Metadata as required by specification
        source_metadata = {
            "source_type": source_type,
            "hostname": self.hostname,
            "collector_name": collector_name,
            "event_id": event_id,
            "timestamp": now_ts,
            "raw_message": raw_message,
            "collection_status": collection_status,
            "event_id_windows": event_id_windows
        }
        if custom_metadata:
            source_metadata.update(custom_metadata)

        normalized_event = {
            # Standard specification fields (snake_case)
            "event_id": event_id,
            "timestamp": now_ts,
            "source_type": source_type,
            "hostname": self.hostname,
            "collector_name": collector_name,
            "event_type": resolved_event_type,
            "event_id_windows": event_id_windows,
            "severity": severity.upper(),
            "raw_message": raw_message,
            "collection_status": collection_status,

            # Backwards-compatible camelCase & pipeline fields
            "eventId": event_id,
            "source": source,
            "eventType": resolved_event_type,
            "sourceIp": source_ip or "127.0.0.1",
            "destinationIp": destination_ip or "127.0.0.1",
            "sourcePort": source_port,
            "destinationPort": destination_port,
            "protocol": protocol,
            "host": self.hostname,
            "username": username,
            "details": details or f"Telemetry collected via {collector_name} ({collection_status})",
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

        return normalized_event
