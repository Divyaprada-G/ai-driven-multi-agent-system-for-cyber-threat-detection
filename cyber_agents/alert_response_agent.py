"""
Agent 6: Alert and Response Agent
Generates structured alerts for suspicious incidents and supports dashboard notifications.
Implements defensive response actions:
- Create incident
- Mark as acknowledged
- Assign severity
- Add investigation notes
- Close / resolve incident
Safeguard Rule: Strictly defensive; no arbitrary IP drops, destructive system executions, or file deletions.
"""
from typing import List, Dict, Any, Optional
import uuid
import logging
from cyber_agents.schemas import SecurityEvent, utc_now_iso

logger = logging.getLogger("AlertResponseAgent")

class AlertResponseAgent:
    """
    Alert generation and defensive incident response agent:
    - Synthesizes findings, correlations, and ML threat outputs into structured alerts
    - Dispatches alerts to dashboard queues and notification hooks
    - Manages stateful incident lifecycles (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, CLOSED)
    - Safeguards: Strictly authorized containment advice, non-destructive
    """

    def __init__(self):
        # In-memory alert and incident repository for stateful operations
        self.alerts_store: Dict[str, Dict[str, Any]] = {}
        self.incidents_store: Dict[str, Dict[str, Any]] = {}

    def generate_alerts(
        self,
        security_events: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]],
        ml_result: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Transforms security events and correlated chains into structured alerts.
        """
        generated_alerts = []

        # 1. Generate alerts for critical & high severity events
        for ev in security_events:
            sev = ev.get("severity", "LOW")
            if sev in ["CRITICAL", "HIGH", "MEDIUM"]:
                alert_id = f"ALT-{uuid.uuid4().hex[:8]}"
                alert_record = {
                    "alert_id": alert_id,
                    "title": f"[{ev.get('agent_name')}] {ev.get('event_type')}",
                    "severity": sev,
                    "event_type": ev.get("event_type"),
                    "source": ev.get("source"),
                    "description": ev.get("description"),
                    "status": "NEW",
                    "timestamp": utc_now_iso(),
                    "indicators": ev.get("indicators", {}),
                    "recommended_action": ev.get("recommended_action"),
                    "response_safeguard": "Manual review advised before perimeter modification."
                }
                self.alerts_store[alert_id] = alert_record
                generated_alerts.append(alert_record)

        # 2. Generate priority alerts for multi-agent correlations
        for corr in correlations:
            alert_id = f"ALT-CORR-{uuid.uuid4().hex[:8]}"
            alert_record = {
                "alert_id": alert_id,
                "title": f"[Correlated Chain] {corr.get('correlation_type')}",
                "severity": "CRITICAL" if corr.get("strength") == "STRONG" else "HIGH",
                "event_type": "Correlated Attack Chain",
                "source": "Event Correlation Agent",
                "description": corr.get("description"),
                "status": "NEW",
                "timestamp": utc_now_iso(),
                "indicators": {
                    "source_ip": corr.get("source_ip"),
                    "agents_involved": corr.get("agents_involved"),
                    "threat_types": corr.get("threat_types"),
                    "evidence_events": corr.get("evidence_events")
                },
                "recommended_action": corr.get("recommended_action"),
                "response_safeguard": "Coordinated defensive action required."
            }
            self.alerts_store[alert_id] = alert_record
            generated_alerts.append(alert_record)

        return generated_alerts

    def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        associated_alerts: List[str],
        primary_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a formal security incident ticket.
        """
        inc_id = f"INC-{uuid.uuid4().hex[:6]}"
        incident = {
            "incident_id": inc_id,
            "title": title,
            "description": description,
            "severity": severity.upper(),
            "status": "NEW",
            "priority": "P1" if severity.upper() == "CRITICAL" else "P2" if severity.upper() == "HIGH" else "P3",
            "primary_ip": primary_ip or "Unknown",
            "associated_alerts": associated_alerts,
            "created_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
            "investigation_notes": [
                {
                    "timestamp": utc_now_iso(),
                    "author": "AlertAndResponseAgent",
                    "note": "Incident automatically initialized from correlated multi-agent alerts."
                }
            ]
        }
        self.incidents_store[inc_id] = incident
        return incident

    def acknowledge_incident(self, incident_id: str, actor: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
        """
        Marks an incident as acknowledged and underway.
        """
        inc = self.incidents_store.get(incident_id)
        if not inc:
            return None
        inc["status"] = "ACKNOWLEDGED"
        inc["updated_at"] = utc_now_iso()
        inc["investigation_notes"].append({
            "timestamp": utc_now_iso(),
            "author": actor,
            "note": "Incident formally acknowledged. Triage investigation commenced."
        })
        return inc

    def add_investigation_note(self, incident_id: str, note_text: str, actor: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
        """
        Appends defensive analysis note or forensic findings to incident record.
        """
        inc = self.incidents_store.get(incident_id)
        if not inc:
            return None
        inc["updated_at"] = utc_now_iso()
        inc["investigation_notes"].append({
            "timestamp": utc_now_iso(),
            "author": actor,
            "note": note_text
        })
        return inc

    def close_incident(self, incident_id: str, resolution_summary: str, actor: str = "SOC Lead") -> Optional[Dict[str, Any]]:
        """
        Closes an incident upon verification of threat containment.
        """
        inc = self.incidents_store.get(incident_id)
        if not inc:
            return None
        inc["status"] = "RESOLVED"
        inc["updated_at"] = utc_now_iso()
        inc["resolution_summary"] = resolution_summary
        inc["investigation_notes"].append({
            "timestamp": utc_now_iso(),
            "author": actor,
            "note": f"Incident resolved and closed. Resolution: {resolution_summary}"
        })
        return inc
