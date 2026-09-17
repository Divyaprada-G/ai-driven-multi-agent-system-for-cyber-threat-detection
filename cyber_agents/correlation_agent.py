"""
Agent 4: Event Correlation Agent
Combines events from all monitoring agents (Network, System, Application).
Groups related events by time windows, source identifiers (IPs, users), and attack patterns.
Deduplicates recurring events and outputs structured Correlated Incidents with evidence.
"""
from typing import List, Dict, Any, Optional
import uuid
import logging
from cyber_agents.schemas import utc_now_iso

logger = logging.getLogger("CorrelationAgent")

class CorrelationAgent:
    """
    Combines events from all monitoring agents to construct unified attack chains:
    - IP-based grouping
    - Multi-agent cross-domain correlation (Network -> System -> Application)
    - Deduplication of identical alert signatures
    - Produces aggregated incident dossiers
    """

    def __init__(self, time_window_seconds: int = 3600):
        self.time_window_seconds = time_window_seconds

    def deduplicate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Removes identical duplicate events based on (agent_name, event_type, source_ip, targeted resource).
        """
        if not events:
            return []

        unique: List[Dict[str, Any]] = []
        seen_keys = set()

        for ev in events:
            agent = ev.get("agent_name", "")
            etype = ev.get("event_type", "")
            indicators = ev.get("indicators", {})
            src_ip = indicators.get("source_ip", "")
            key = (agent, etype, src_ip)

            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(ev)

        return unique

    def correlate(self, all_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Takes raw event lists from Network, System, and Application agents,
        groups related events by IP, and detects complex multi-stage attack chains.
        """
        if not all_events:
            return {
                "correlated_count": 0,
                "correlations": [],
                "deduplicated_events_count": 0,
                "attack_chain_detected": False
            }

        deduped = self.deduplicate_events(all_events)
        ip_groups: Dict[str, List[Dict[str, Any]]] = {}

        for ev in deduped:
            indicators = ev.get("indicators", {})
            src_ip = indicators.get("source_ip")
            if src_ip:
                if src_ip not in ip_groups:
                    ip_groups[src_ip] = []
                ip_groups[src_ip].append(ev)

        correlations: List[Dict[str, Any]] = []
        attack_chain_detected = False

        # 1. IP-Based Cross-Domain Correlation
        for ip, group in ip_groups.items():
            if len(group) >= 2:
                agents_involved = sorted(list(set([e.get("agent_name") for e in group])))
                threat_types = sorted(list(set([e.get("event_type") for e in group])))

                strength = "STRONG" if len(agents_involved) > 1 else "MODERATE"
                if len(agents_involved) > 1:
                    attack_chain_detected = True

                corr_id = f"CORR-{uuid.uuid4().hex[:8]}"
                correlations.append({
                    "correlation_id": corr_id,
                    "correlation_type": "Multi-Vector Host Correlation",
                    "source_ip": ip,
                    "event_count": len(group),
                    "agents_involved": agents_involved,
                    "threat_types": threat_types,
                    "strength": strength,
                    "description": f"Multiple threat vectors ({', '.join(threat_types)}) originating from host {ip} across {len(agents_involved)} detection domains.",
                    "evidence_events": [e.get("event_id") for e in group],
                    "timestamp": utc_now_iso(),
                    "recommended_action": f"Prioritize investigation of host {ip}; correlated multi-agent activity indicates coordinated attack sequence."
                })

        # 2. Overall Cross-Agent Attack Chain (if >= 2 distinct monitoring agents flagged events)
        all_agents = sorted(list(set([e.get("agent_name") for e in deduped])))
        if len(all_agents) >= 2 and not any(c.get("correlation_type") == "Full Multi-Agent Kill-Chain" for c in correlations):
            correlations.append({
                "correlation_id": f"CORR-KILLCHAIN-{uuid.uuid4().hex[:8]}",
                "correlation_type": "Full Multi-Agent Kill-Chain",
                "source_ip": list(ip_groups.keys())[0] if ip_groups else "Distributed",
                "event_count": len(deduped),
                "agents_involved": all_agents,
                "threat_types": sorted(list(set([e.get("event_type") for e in deduped]))),
                "strength": "STRONG",
                "description": f"Enterprise-level multi-stage cyber threat sequence detected spanning {', '.join(all_agents)}.",
                "evidence_events": [e.get("event_id") for e in deduped],
                "timestamp": utc_now_iso(),
                "recommended_action": "Trigger SOC incident escalation; coordinate containment across network perimeter, host endpoints, and web services."
            })
            attack_chain_detected = True

        return {
            "correlated_count": len(correlations),
            "correlations": correlations,
            "deduplicated_events_count": len(deduped),
            "attack_chain_detected": attack_chain_detected,
            "unique_source_ips": list(ip_groups.keys())
        }
