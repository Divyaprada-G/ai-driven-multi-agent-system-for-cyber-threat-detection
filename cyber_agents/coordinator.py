"""
Multi-Agent Cyber Threat Detection Coordinator Orchestrator
Coordinates all 6 defensive security agents:
1. NetworkAgent
2. SystemAgent
3. ApplicationAgent
4. CorrelationAgent
5. ThreatDetectionAgent
6. AlertResponseAgent
Resilient: Gracefully continues if any input source is absent.
"""
from typing import List, Dict, Any, Optional
import logging
from cyber_agents.network_agent import NetworkAgent
from cyber_agents.system_agent import SystemAgent
from cyber_agents.application_agent import ApplicationAgent
from cyber_agents.correlation_agent import CorrelationAgent
from cyber_agents.threat_detection_agent import ThreatDetectionAgent
from cyber_agents.alert_response_agent import AlertResponseAgent
from cyber_agents.schemas import utc_now_iso

logger = logging.getLogger("MultiAgentCoordinator")

class MultiAgentCoordinator:
    """
    Central orchestration engine for the 6-agent cyber threat detection pipeline.
    Ensures decoupled, resilient execution even when one or more data streams are empty or unavailable.
    """

    def __init__(self):
        self.network_agent = NetworkAgent()
        self.system_agent = SystemAgent()
        self.application_agent = ApplicationAgent()
        self.correlation_agent = CorrelationAgent()
        self.threat_agent = ThreatDetectionAgent()
        self.alert_agent = AlertResponseAgent()

    def process_telemetry(
        self,
        network_logs: Optional[List[str]] = None,
        system_logs: Optional[List[str]] = None,
        application_logs: Optional[List[str]] = None,
        source_label: str = "Enterprise Live Stream"
    ) -> Dict[str, Any]:
        """
        Executes end-to-end multi-agent detection and correlation across all 3 data tiers.
        """
        net_logs = network_logs or []
        sys_logs = system_logs or []
        app_logs = application_logs or []

        all_detected_events = []
        agents_executed = []

        # 1. Network Monitoring Agent
        try:
            net_events = self.network_agent.process_logs(net_logs)
            all_detected_events.extend(net_events)
            if net_events:
                agents_executed.append("Network Monitoring Agent")
        except Exception as e:
            logger.error(f"NetworkAgent execution warning: {e}")
            net_events = []

        # 2. System Monitoring Agent
        try:
            sys_events = self.system_agent.process_logs(sys_logs)
            all_detected_events.extend(sys_events)
            if sys_events:
                agents_executed.append("System Monitoring Agent")
        except Exception as e:
            logger.error(f"SystemAgent execution warning: {e}")
            sys_events = []

        # 3. Application Monitoring Agent
        try:
            app_events = self.application_agent.process_logs(app_logs)
            all_detected_events.extend(app_events)
            if app_events:
                agents_executed.append("Application Monitoring Agent")
        except Exception as e:
            logger.error(f"ApplicationAgent execution warning: {e}")
            app_events = []

        # 4. Event Correlation Agent
        try:
            correlation_result = self.correlation_agent.correlate(all_detected_events)
            if correlation_result["correlated_count"] > 0:
                agents_executed.append("Event Correlation Agent")
        except Exception as e:
            logger.error(f"CorrelationAgent error: {e}")
            correlation_result = {"correlated_count": 0, "correlations": [], "deduplicated_events_count": len(all_detected_events), "attack_chain_detected": False}

        # 5. Threat Detection Agent (Rule-based + ML)
        try:
            threat_eval = self.threat_agent.detect(all_detected_events)
            agents_executed.append("Threat Detection Agent")
        except Exception as e:
            logger.error(f"ThreatDetectionAgent error: {e}")
            threat_eval = {"threat_detected": len(all_detected_events) > 0, "overall_severity": "LOW", "rule_based_findings": [], "machine_learning_analysis": {}}

        # 6. Alert and Response Agent
        try:
            alerts = self.alert_agent.generate_alerts(
                all_detected_events,
                correlation_result.get("correlations", []),
                threat_eval.get("machine_learning_analysis")
            )
            incident = None
            if alerts or threat_eval["threat_detected"]:
                top_event = all_detected_events[0] if all_detected_events else {}
                incident = self.alert_agent.create_incident(
                    title=f"Coordinated {threat_eval['overall_severity']} Incident: {top_event.get('event_type', 'Multi-Vector Threat')}",
                    description=f"Automated incident ticket initialized from {len(alerts)} alerts across {len(agents_executed)} agents.",
                    severity=threat_eval["overall_severity"],
                    associated_alerts=[a["alert_id"] for a in alerts],
                    primary_ip=top_event.get("indicators", {}).get("source_ip", "10.0.1.50")
                )
            if alerts:
                agents_executed.append("Alert and Response Agent")
        except Exception as e:
            logger.error(f"AlertResponseAgent error: {e}")
            alerts = []
            incident = None

        return {
            "pipeline_status": "COMPLETED",
            "timestamp": utc_now_iso(),
            "source_label": source_label,
            "raw_log_counts": {
                "network": len(net_logs),
                "system": len(sys_logs),
                "application": len(app_logs),
                "total": len(net_logs) + len(sys_logs) + len(app_logs)
            },
            "events_detected_count": len(all_detected_events),
            "events": all_detected_events,
            "correlations": correlation_result.get("correlations", []),
            "attack_chain_detected": correlation_result.get("attack_chain_detected", False),
            "threat_detection": threat_eval,
            "alerts_generated": alerts,
            "incident": incident,
            "active_agents": sorted(list(set(agents_executed)))
        }
