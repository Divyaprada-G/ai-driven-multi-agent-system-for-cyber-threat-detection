"""
AI-Driven Multi-Agent Cyber Threat Detection System
Standard Structured Event and Result Schemas
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

def generate_event_id(prefix: str = "EVT") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class SecurityEvent:
    """
    Standard Structured Event Output required by all monitoring agents:
    - event_id
    - agent_name
    - timestamp
    - event_type
    - severity
    - source
    - description
    - indicators
    - recommended_action
    """
    def __init__(
        self,
        agent_name: str,
        event_type: str,
        severity: str,
        source: str,
        description: str,
        indicators: Dict[str, Any],
        recommended_action: str,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None
    ):
        self.event_id = event_id or generate_event_id(agent_name[:3].upper())
        self.agent_name = agent_name
        self.timestamp = timestamp or utc_now_iso()
        self.event_type = event_type
        self.severity = severity.upper()  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.source = source
        self.description = description
        self.indicators = indicators or {}
        self.recommended_action = recommended_action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "indicators": self.indicators,
            "recommended_action": self.recommended_action
        }
