"""
CLI runner for the Multi-Agent Cybersecurity Monitoring Pipeline.
Allows running the pipeline via terminal command and stdout JSON.
"""
import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_agents.coordinator import MultiAgentCoordinator
from cyber_agents.sample_logs import (
    SAMPLE_NETWORK_LOGS,
    SAMPLE_SYSTEM_LOGS,
    SAMPLE_APPLICATION_LOGS,
    SAMPLE_BENIGN_LOGS
)

def main():
    parser = argparse.ArgumentParser(description="Run Multi-Agent Cyber Threat Detection Pipeline")
    parser.add_argument("--scenario", choices=["mixed", "network", "system", "app", "benign"], default="mixed",
                        help="Scenario to run: mixed, network, system, app, or benign")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")

    args = parser.parse_args()
    coordinator = MultiAgentCoordinator()

    if args.scenario == "network":
        net_logs = SAMPLE_NETWORK_LOGS
        sys_logs, app_logs = [], []
    elif args.scenario == "system":
        sys_logs = SAMPLE_SYSTEM_LOGS
        net_logs, app_logs = [], []
    elif args.scenario == "app":
        app_logs = SAMPLE_APPLICATION_LOGS
        net_logs, sys_logs = [], []
    elif args.scenario == "benign":
        net_logs = SAMPLE_BENIGN_LOGS
        sys_logs, app_logs = [], []
    else:  # mixed
        net_logs = SAMPLE_NETWORK_LOGS
        sys_logs = SAMPLE_SYSTEM_LOGS
        app_logs = SAMPLE_APPLICATION_LOGS

    result = coordinator.process_telemetry(net_logs, sys_logs, app_logs, source_label=f"Scenario: {args.scenario}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n=======================================================")
        print(f" CYBER THREAT DETECTION: MULTI-AGENT RUN REPORT")
        print(f"=======================================================")
        print(f"Status:             {result['pipeline_status']}")
        print(f"Active Agents:      {', '.join(result['active_agents'])}")
        print(f"Events Detected:    {result['events_detected_count']}")
        print(f"Correlations:       {len(result['correlations'])}")
        print(f"Attack Chain:       {result['attack_chain_detected']}")
        print(f"Overall Severity:   {result['threat_detection']['overall_severity']}")
        print(f"Alerts Generated:   {len(result['alerts_generated'])}")
        if result['incident']:
            print(f"Incident Created:   {result['incident']['incident_id']} - {result['incident']['title']}")
        print(f"-------------------------------------------------------")
        print(f"ML Model Analysis:")
        ml = result['threat_detection']['machine_learning_analysis']
        print(f"  Predicted Class:  {ml.get('predicted_class')}")
        print(f"  Confidence:       {ml.get('confidence')}")
        print(f"  Anomaly Detected: {ml.get('anomaly_detected')} (Score: {ml.get('anomaly_score')})")
        print(f"=======================================================\n")

if __name__ == "__main__":
    main()
