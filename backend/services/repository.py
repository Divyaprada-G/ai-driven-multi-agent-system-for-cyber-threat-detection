"""
Repository / Storage layer for backend security events, alerts, and incidents.
Provides thread-safe access and querying.
"""

from typing import Dict, Any, List, Optional
import threading

class SecurityDataRepository:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.pipeline.get_events(limit=limit)

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self.pipeline._lock:
            for ev in self.pipeline.processed_events:
                if ev.get("eventId") == event_id or ev.get("event_id") == event_id:
                    return ev
            for q_item in self.pipeline.queue:
                if q_item.get("eventId") == event_id or q_item.get("event_id") == event_id:
                    return q_item
        return None

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.pipeline.get_alerts(limit=limit)

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.pipeline._lock:
            for al in self.pipeline.alerts:
                if al.get("alertId") == alert_id or al.get("alert_id") == alert_id or al.get("id") == alert_id:
                    return al
        return None

    def update_alert(self, alert_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self.pipeline._lock:
            for al in self.pipeline.alerts:
                if al.get("alertId") == alert_id or al.get("alert_id") == alert_id or al.get("id") == alert_id:
                    al.update(updates)
                    return al
        return None
