"""
Agent 2: System Monitoring Agent
Accepts system logs (authentication events, OS/syslog events, sudo execution).
Identifies repeated authentication failures, privilege escalations, account lockouts, and suspicious commands.
Outputs structured SecurityEvent dictionaries.
"""
import re
from typing import List, Dict, Any, Optional
import logging
from cyber_agents.schemas import SecurityEvent, utc_now_iso

logger = logging.getLogger("SystemAgent")

class SystemAgent:
    """
    Defensive OS and system host telemetry monitor:
    - Parses Linux auth.log, syslog, secure logs, systemd records
    - Detects SSH brute force (repeated auth failures), unauthorized sudo privilege escalation,
      and critical administrative tampering.
    """

    IP_PATTERN = re.compile(r'\b(?:from|rhost=|client=)?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b')
    USER_PATTERN = re.compile(r'\b(?:user|for)\s+([a-zA-Z0-9_\-\.]+)\b', re.IGNORECASE)

    def __init__(self, brute_force_threshold: int = 3):
        self.brute_force_threshold = brute_force_threshold

    def parse_system_line(self, line: str) -> Optional[Dict[str, Any]]:
        if not line or not isinstance(line, str):
            return None
        clean_line = line.strip()
        if not clean_line:
            return None

        lower = clean_line.lower()
        ip_match = self.IP_PATTERN.search(clean_line)
        src_ip = ip_match.group(1) if ip_match else None

        user_match = self.USER_PATTERN.search(clean_line)
        user = user_match.group(1) if user_match else None

        is_auth_failure = "failed password" in lower or "authentication failure" in lower or "pam_unix" in lower and "failure" in lower
        is_auth_success = "accepted password" in lower or "accepted publickey" in lower or "session opened" in lower
        is_sudo_elevation = "sudo:" in lower and ("root" in lower or "/bin/bash" in lower or "/bin/sh" in lower or "command=" in lower)

        return {
            "source_ip": src_ip,
            "user": user,
            "is_auth_failure": is_auth_failure,
            "is_auth_success": is_auth_success,
            "is_sudo_elevation": is_sudo_elevation,
            "raw": clean_line
        }

    def process_logs(self, logs: List[str]) -> List[Dict[str, Any]]:
        """
        Processes list of syslog / authlog strings and returns structured SecurityEvent dicts.
        """
        if not logs or not isinstance(logs, list):
            return []

        events: List[SecurityEvent] = []
        ip_auth_failures: Dict[str, List[Dict[str, Any]]] = {}
        user_auth_failures: Dict[str, int] = {}

        for line in logs:
            try:
                parsed = self.parse_system_line(line)
                if not parsed:
                    continue

                lower = parsed["raw"].lower()
                src_ip = parsed["source_ip"]
                user = parsed["user"]

                # 1. Track failed auth attempts
                if parsed["is_auth_failure"]:
                    if src_ip:
                        if src_ip not in ip_auth_failures:
                            ip_auth_failures[src_ip] = []
                        ip_auth_failures[src_ip].append(parsed)
                    if user:
                        user_auth_failures[user] = user_auth_failures.get(user, 0) + 1

                # 2. Detect Sudo Privilege Escalation
                if parsed["is_sudo_elevation"]:
                    events.append(SecurityEvent(
                        agent_name="System Monitoring Agent",
                        event_type="Privilege Escalation",
                        severity="HIGH",
                        source="System Audit Subsystem",
                        description=f"Administrative root shell or high-privilege command invoked via sudo{' by user ' + user if user else ''}.",
                        indicators={
                            "user": user or "unknown",
                            "source_ip": src_ip,
                            "command_log": parsed["raw"],
                            "target_user": "root"
                        },
                        recommended_action="Audit user authorization for administrative sudo access; verify command parameters."
                    ))

                # 3. Detect sensitive system file modification / service tampering
                if "crontab" in lower and ("edit" in lower or "replace" in lower) or "shadow" in lower or "authorized_keys" in lower:
                    events.append(SecurityEvent(
                        agent_name="System Monitoring Agent",
                        event_type="Persistence / Configuration Modification",
                        severity="MEDIUM",
                        source="System File Integrity Monitor",
                        description="Access or modification detected on sensitive security credential or scheduling file.",
                        indicators={
                            "user": user,
                            "source_ip": src_ip,
                            "raw_log": parsed["raw"]
                        },
                        recommended_action="Validate integrity of scheduled jobs and SSH authorized keys on the target host."
                    ))

            except Exception as e:
                logger.warning(f"Error processing system log line: {e}")
                continue

        # Aggregated Rule: SSH/System Brute Force Detection
        for ip, fail_records in ip_auth_failures.items():
            fail_count = len(fail_records)
            if fail_count >= self.brute_force_threshold:
                severity = "HIGH" if fail_count >= 5 else "MEDIUM"
                targeted_users = list(set([r["user"] for r in fail_records if r.get("user")]))

                events.append(SecurityEvent(
                    agent_name="System Monitoring Agent",
                    event_type="Brute Force Authentication Attack",
                    severity=severity,
                    source="Host Authentication Watcher",
                    description=f"Multiple repeated login failures ({fail_count} attempts) detected targeting host from source IP {ip}.",
                    indicators={
                        "source_ip": ip,
                        "failure_count": fail_count,
                        "targeted_accounts": targeted_users[:5],
                        "sample_evidence": [r["raw"] for r in fail_records[:3]]
                    },
                    recommended_action=f"Enforce IP fail2ban lock for {ip}, require multi-factor authentication (MFA), and audit account locks."
                ))

        return [e.to_dict() for e in events]
