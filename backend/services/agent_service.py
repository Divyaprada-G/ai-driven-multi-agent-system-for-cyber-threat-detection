"""
Agent Service layer providing operational status, telemetry, and capabilities
for Network, System, and Application security agents.
"""

from typing import Dict, Any, List, Optional
import time

class AgentService:
    @staticmethod
    def get_all_agents(pipeline_status: Dict[str, Any]) -> List[Dict[str, Any]]:
        total_events = pipeline_status.get("eventsProcessed", 0)
        threats_flagged = pipeline_status.get("threatsDetected", 0)

        # Distribute realistic event ratios across multi-agent specialties
        net_events = int(total_events * 0.55)
        sys_events = int(total_events * 0.25)
        app_events = total_events - net_events - sys_events

        net_threats = int(threats_flagged * 0.50)
        sys_threats = int(threats_flagged * 0.30)
        app_threats = threats_flagged - net_threats - sys_threats

        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return [
            {
                "agent_name": "network-agent",
                "agent_type": "network",
                "status": "ACTIVE",
                "description": "Monitors network traffic flows, IP reputation, port scans, SynFloods, and volumetric DDoS indicators.",
                "events_monitored": net_events,
                "threats_flagged": net_threats,
                "active_heuristics": [
                    "PortScanDetector",
                    "SynFloodEvaluator",
                    "DDoSVolumeHeuristic",
                    "SuricataFlowParser"
                ],
                "mitre_tactics": ["TA0043 Reconnaissance", "TA0040 Impact", "TA0011 Command and Control"],
                "last_active": now_str
            },
            {
                "agent_name": "system-agent",
                "agent_type": "system",
                "status": "ACTIVE",
                "description": "Inspects host syslogs, authentication failures, root escalations, and anomalous process executions.",
                "events_monitored": sys_events,
                "threats_flagged": sys_threats,
                "active_heuristics": [
                    "SshBruteForceDetector",
                    "PrivilegeEscalationWatcher",
                    "SudoAbuseDetector",
                    "ProcessSpikeAnomaly"
                ],
                "mitre_tactics": ["TA0001 Initial Access", "TA0004 Privilege Escalation", "TA0006 Credential Access"],
                "last_active": now_str
            },
            {
                "agent_name": "application-agent",
                "agent_type": "application",
                "status": "ACTIVE",
                "description": "Analyzes HTTP/HTTPS access logs, SQL injection, XSS signatures, and web application attack vectors.",
                "events_monitored": app_events,
                "threats_flagged": app_threats,
                "active_heuristics": [
                    "SqlInjectionHeuristic",
                    "XssPatternMatcher",
                    "DirectoryTraversalWatcher",
                    "AdminPathProbeDetector"
                ],
                "mitre_tactics": ["TA0001 Initial Access", "TA0002 Execution", "TA0005 Defense Evasion"],
                "last_active": now_str
            }
        ]

    @staticmethod
    def get_agent_by_name(agent_name: str, pipeline_status: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        agents = AgentService.get_all_agents(pipeline_status)
        normalized = agent_name.lower().replace("_", "-").replace(" ", "-")
        for ag in agents:
            if ag["agent_name"] == normalized or ag["agent_type"] == normalized or ag["agent_name"] == f"{normalized}-agent":
                return ag
        return None
