"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Log Analyzer — Multi-Agent Analysis Engine

Contains:
- LogPreprocessor: Normalizes raw logs into common event format
- NetworkAgent: Detects network-level threats (port scan, brute force, suspicious IPs)
- SystemAgent: Detects system-level threats (failed logins, privilege escalation)
- ApplicationAgent: Detects application-level threats (SQLi, XSS, command injection)
- EventCorrelator: Correlates related events by IP, time, type
- RiskScorer: Deterministic 0-100 risk scoring with explanation
- analyze_logs(): Main orchestrator function
"""

import re
import json
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple


# =============================================================================
# LOG PREPROCESSOR
# =============================================================================

class LogPreprocessor:
    """Normalizes raw log input into a list of common event dicts."""

    @staticmethod
    def preprocess(raw_text: str, source_type: str = "auto") -> List[Dict[str, Any]]:
        """
        Accepts raw log text and returns a list of normalized event dicts.
        Handles JSON, CSV, and plain text log formats.
        Never crashes on malformed input.
        """
        if not raw_text or not raw_text.strip():
            return []

        raw_text = raw_text.strip()
        events = []

        # Try JSON array first
        if raw_text.startswith("["):
            try:
                parsed = json.loads(raw_text)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            events.append(LogPreprocessor._normalize_dict(item, source_type))
                    return LogPreprocessor._deduplicate(events)
            except json.JSONDecodeError:
                pass

        # Try single JSON object
        if raw_text.startswith("{") and raw_text.endswith("}") and "\n" not in raw_text:
            try:
                parsed = json.loads(raw_text)
                if isinstance(parsed, dict):
                    events.append(LogPreprocessor._normalize_dict(parsed, source_type))
                    return events
            except json.JSONDecodeError:
                pass

        # Line-by-line processing
        lines = raw_text.split("\n")
        header = None
        is_csv = False

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            # Try JSONL
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        events.append(LogPreprocessor._normalize_dict(parsed, source_type))
                        continue
                except json.JSONDecodeError:
                    pass

            # CSV header detection
            if i == 0 and "," in line and not LogPreprocessor._looks_like_log_line(line):
                header = [h.strip().lower() for h in line.split(",")]
                is_csv = True
                continue

            # CSV data rows
            if is_csv and header:
                values = line.split(",")
                if len(values) >= len(header) // 2:
                    row = {}
                    for j, h in enumerate(header):
                        if j < len(values):
                            row[h] = values[j].strip()
                    events.append(LogPreprocessor._normalize_dict(row, source_type))
                    continue

            # Plain text log line
            events.append(LogPreprocessor._normalize_text_line(line, source_type))

        return LogPreprocessor._deduplicate(events)

    @staticmethod
    def _looks_like_log_line(line: str) -> bool:
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}',
            r'\d{2}/\w{3}/\d{4}',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        ]
        for pat in timestamp_patterns:
            if re.search(pat, line):
                return True
        return False

    @staticmethod
    def _normalize_dict(d: Dict[str, Any], source_type: str) -> Dict[str, Any]:
        event = {
            "id": f"EVT-{uuid.uuid4().hex[:12]}",
            "timestamp": None,
            "source": source_type if source_type != "auto" else None,
            "source_ip": None,
            "destination_ip": None,
            "event_type": None,
            "message": None,
            "raw_log": json.dumps(d) if isinstance(d, dict) else str(d),
            "username": None,
            "port": None,
            "protocol": None,
            "status_code": None,
            "url": None,
            "process": None,
        }

        field_mappings = {
            "timestamp": ["timestamp", "time", "datetime", "date", "ts", "@timestamp", "event_time"],
            "source_ip": ["source_ip", "src_ip", "src", "sourceip", "source_address", "client_ip", "ip", "remote_addr"],
            "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "dst", "destip", "dest", "destination_address", "server_ip"],
            "event_type": ["event_type", "eventtype", "type", "action", "event", "category", "event_id"],
            "message": ["message", "msg", "log", "description", "detail", "details", "text", "summary"],
            "username": ["username", "user", "account", "login", "user_name", "account_name"],
            "port": ["port", "dst_port", "dest_port", "destination_port", "src_port", "source_port"],
            "protocol": ["protocol", "proto", "service"],
            "status_code": ["status_code", "status", "http_status", "response_code", "code"],
            "url": ["url", "uri", "path", "request_uri", "request_url", "endpoint", "request"],
            "process": ["process", "process_name", "program", "application", "app"],
        }

        d_lower = {k.lower().strip(): v for k, v in d.items()}

        for target, aliases in field_mappings.items():
            for alias in aliases:
                if alias in d_lower and d_lower[alias]:
                    event[target] = str(d_lower[alias]).strip()
                    break

        if not event["source"] or event["source"] == "auto":
            event["source"] = LogPreprocessor._detect_source_type(event, d_lower)

        if not event["message"]:
            parts = []
            for k, v in d.items():
                if v and k.lower() not in ["raw", "raw_log"]:
                    parts.append(f"{k}={v}")
            event["message"] = " | ".join(parts[:6]) if parts else str(d)

        event["timestamp"] = LogPreprocessor._parse_timestamp(event.get("timestamp"))
        return event

    @staticmethod
    def _normalize_text_line(line: str, source_type: str) -> Dict[str, Any]:
        event = {
            "id": f"EVT-{uuid.uuid4().hex[:12]}",
            "timestamp": None,
            "source": source_type if source_type != "auto" else None,
            "source_ip": None,
            "destination_ip": None,
            "event_type": None,
            "message": line,
            "raw_log": line,
            "username": None,
            "port": None,
            "protocol": None,
            "status_code": None,
            "url": None,
            "process": None,
        }

        ts_match = re.search(
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',
            line
        )
        if ts_match:
            event["timestamp"] = LogPreprocessor._parse_timestamp(ts_match.group(1))
        else:
            syslog_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if syslog_match:
                event["timestamp"] = syslog_match.group(1)

        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        ips = re.findall(ip_pattern, line)
        if len(ips) >= 1:
            event["source_ip"] = ips[0]
        if len(ips) >= 2:
            event["destination_ip"] = ips[1]

        port_match = re.search(r'port\s+(\d+)', line, re.IGNORECASE)
        if port_match:
            event["port"] = port_match.group(1)

        user_match = re.search(r'(?:user|username|account|for)\s+["\']?(\w+)', line, re.IGNORECASE)
        if user_match:
            event["username"] = user_match.group(1)

        url_match = re.search(r'((?:GET|POST|PUT|DELETE|PATCH)\s+\S+|/[\w/.-]+\??[\w=&]*)', line)
        if url_match:
            event["url"] = url_match.group(1)

        if not event["source"] or event["source"] == "auto":
            event["source"] = LogPreprocessor._detect_source_type_from_text(line)

        if not event["timestamp"]:
            event["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        return event

    @staticmethod
    def _detect_source_type(event: Dict, raw_dict: Dict) -> str:
        text = json.dumps(raw_dict).lower()
        network_keywords = ["tcp", "udp", "icmp", "port", "packet", "firewall", "dns",
                          "syn", "ack", "connection", "socket", "bandwidth", "traffic",
                          "network", "router", "switch", "vlan", "subnet"]
        system_keywords = ["login", "logout", "privilege", "sudo", "su ", "auth",
                          "sshd", "pam", "cron", "process", "service", "daemon",
                          "systemd", "kernel", "syslog", "eventid", "security log",
                          "failed password", "accepted password", "session opened"]
        app_keywords = ["http", "https", "api", "get ", "post ", "put ", "delete ",
                       "response", "request", "status_code", "url", "endpoint",
                       "sql", "query", "injection", "xss", "script", "cookie",
                       "session", "web", "application", "apache", "nginx"]

        net_score = sum(1 for kw in network_keywords if kw in text)
        sys_score = sum(1 for kw in system_keywords if kw in text)
        app_score = sum(1 for kw in app_keywords if kw in text)

        if net_score > sys_score and net_score > app_score:
            return "network"
        elif sys_score > app_score:
            return "system"
        elif app_score > 0:
            return "application"
        return "network"

    @staticmethod
    def _detect_source_type_from_text(line: str) -> str:
        lower = line.lower()
        if any(kw in lower for kw in ["tcp", "udp", "port", "syn", "firewall", "packet", "connection"]):
            return "network"
        if any(kw in lower for kw in ["login", "password", "sudo", "privilege", "sshd", "pam", "auth"]):
            return "system"
        if any(kw in lower for kw in ["http", "get ", "post ", "/api/", "sql", "injection", "script"]):
            return "application"
        return "network"

    @staticmethod
    def _parse_timestamp(ts: Optional[str]) -> str:
        if not ts:
            return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        formats = [
            "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S", "%b %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts.strip(), fmt)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
        return ts

    @staticmethod
    def _deduplicate(events: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for e in events:
            h = hashlib.md5((e.get("raw_log") or "").encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(e)
        return unique


# =============================================================================
# NETWORK AGENT
# =============================================================================

class NetworkAgent:
    """Detects network-level security threats."""
    SUSPICIOUS_PORTS = {22, 23, 25, 53, 135, 139, 445, 1433, 1434, 3306, 3389,
                       4444, 5900, 5901, 6667, 8080, 8443, 9090, 31337}
    KNOWN_BAD_IP_PREFIXES = ["10.66.6", "192.168.66", "172.16.66", "203.0.113",
                              "198.51.100", "185.220", "45.33.32"]

    def analyze(self, events: List[Dict]) -> List[Dict[str, Any]]:
        findings = []
        ip_connections: Dict[str, List[Dict]] = {}
        ip_ports: Dict[str, set] = {}

        for event in events:
            if event.get("source") != "network":
                continue
            src_ip = event.get("source_ip", "")
            dst_ip = event.get("destination_ip", "")
            port = event.get("port")
            raw = (event.get("raw_log") or "").lower()

            if src_ip:
                ip_connections.setdefault(src_ip, []).append(event)
                if port:
                    ip_ports.setdefault(src_ip, set()).add(str(port))

            if port:
                try:
                    if int(port) in self.SUSPICIOUS_PORTS:
                        findings.append(self._finding(event, "Suspicious Port Access",
                            f"Connection to suspicious port {port}", 0.6,
                            [f"Port {port} is commonly targeted", event.get("raw_log", "")]))
                except ValueError:
                    pass

            for prefix in self.KNOWN_BAD_IP_PREFIXES:
                if (src_ip and src_ip.startswith(prefix)) or (dst_ip and dst_ip.startswith(prefix)):
                    findings.append(self._finding(event, "Suspicious IP Activity",
                        f"Traffic involving suspicious IP range ({prefix}.*)", 0.7,
                        [f"IP matches suspicious range", event.get("raw_log", "")]))
                    break

            if any(kw in raw for kw in ["syn flood", "syn/fin", "tcp flag", "rst flood"]):
                findings.append(self._finding(event, "TCP Flood Attack",
                    "SYN flood or TCP flag manipulation detected", 0.8,
                    ["Anomalous TCP flags", event.get("raw_log", "")]))

            if any(kw in raw for kw in ["icmp", "ping sweep", "echo request"]):
                findings.append(self._finding(event, "Network Reconnaissance",
                    "ICMP ping sweep detected", 0.5,
                    ["ICMP activity", event.get("raw_log", "")]))

        # Port scan detection
        for ip, ports in ip_ports.items():
            if len(ports) >= 5:
                findings.append({
                    "id": f"FIND-NET-{uuid.uuid4().hex[:8]}", "agent": "NetworkAgent",
                    "threat_type": "Port Scanning",
                    "description": f"IP {ip} scanned {len(ports)} ports: {', '.join(sorted(ports)[:10])}",
                    "confidence": min(0.95, 0.5 + len(ports) * 0.05),
                    "severity": "HIGH" if len(ports) >= 10 else "MEDIUM",
                    "source_ip": ip, "evidence": [f"Ports: {', '.join(sorted(ports)[:15])}"],
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

        # Repeated connections
        for ip, conns in ip_connections.items():
            if len(conns) >= 10:
                findings.append({
                    "id": f"FIND-NET-{uuid.uuid4().hex[:8]}", "agent": "NetworkAgent",
                    "threat_type": "Repeated Connection Attempts",
                    "description": f"IP {ip} made {len(conns)} connection attempts",
                    "confidence": min(0.9, 0.4 + len(conns) * 0.03),
                    "severity": "HIGH" if len(conns) >= 20 else "MEDIUM",
                    "source_ip": ip, "evidence": [f"{len(conns)} connections from {ip}"],
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                })
        return findings

    def _finding(self, event, threat_type, description, confidence, evidence):
        severity = "CRITICAL" if confidence >= 0.8 else "HIGH" if confidence >= 0.6 else "MEDIUM"
        return {
            "id": f"FIND-NET-{uuid.uuid4().hex[:8]}", "agent": "NetworkAgent",
            "threat_type": threat_type, "description": description,
            "confidence": confidence, "severity": severity,
            "source_ip": event.get("source_ip"), "destination_ip": event.get("destination_ip"),
            "evidence": evidence,
            "timestamp": event.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
        }


# =============================================================================
# SYSTEM AGENT
# =============================================================================

class SystemAgent:
    """Detects system-level security threats."""
    def analyze(self, events: List[Dict]) -> List[Dict[str, Any]]:
        findings = []
        failed_logins: Dict[str, int] = {}

        for event in events:
            if event.get("source") != "system":
                continue
            msg = (event.get("message") or "").lower()
            raw = (event.get("raw_log") or "").lower()
            username = event.get("username", "unknown")
            src_ip = event.get("source_ip", "")
            combined = msg + " " + raw

            if any(kw in combined for kw in ["failed password", "failed login",
                    "authentication failure", "invalid user", "login failed",
                    "incorrect password", "access denied", "logon failure"]):
                key = src_ip or username
                failed_logins[key] = failed_logins.get(key, 0) + 1
                if failed_logins[key] >= 3:
                    findings.append(self._finding(event, "Brute Force Attack",
                        f"Multiple failed login attempts ({failed_logins[key]}) from {key}",
                        min(0.95, 0.5 + failed_logins[key] * 0.05),
                        [f"{failed_logins[key]} failed logins from {key}", raw]))

            if any(kw in combined for kw in ["privilege escalation", "sudo", "su ",
                    "runas", "elevated", "root access", "admin access",
                    "nt authority", "setuid", "chmod +s"]):
                findings.append(self._finding(event, "Privilege Escalation",
                    f"Privilege escalation activity for user '{username}'", 0.7,
                    ["Privilege elevation indicator", raw]))

            if any(kw in combined for kw in ["cmd.exe", "powershell", "bash -c",
                    "wget ", "curl ", "nc ", "netcat", "nmap", "reverse shell",
                    "base64 -d", "python -c"]):
                findings.append(self._finding(event, "Suspicious Process",
                    "Suspicious command execution detected", 0.65,
                    ["Suspicious tool usage", raw]))

            if any(kw in combined for kw in ["accepted password", "session opened", "logged in"]):
                if src_ip and failed_logins.get(src_ip, 0) >= 3:
                    findings.append(self._finding(event, "Successful Login After Brute Force",
                        f"Successful login from {src_ip} after {failed_logins[src_ip]} failed attempts", 0.85,
                        [f"IP {src_ip} had failed attempts before success", raw]))

        return findings

    def _finding(self, event, threat_type, description, confidence, evidence):
        severity = "CRITICAL" if confidence >= 0.8 else "HIGH" if confidence >= 0.6 else "MEDIUM"
        return {
            "id": f"FIND-SYS-{uuid.uuid4().hex[:8]}", "agent": "SystemAgent",
            "threat_type": threat_type, "description": description,
            "confidence": confidence, "severity": severity,
            "source_ip": event.get("source_ip"), "username": event.get("username"),
            "evidence": evidence,
            "timestamp": event.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
        }


# =============================================================================
# APPLICATION AGENT
# =============================================================================

class ApplicationAgent:
    """Detects application-level security threats."""
    SQL_PATTERNS = [
        r"(?:union\s+select|select\s+.*\s+from\s+|insert\s+into|delete\s+from|drop\s+table)",
        r"(?:'\s*or\s+'?\d|'\s*or\s+'[^']*'='|1\s*=\s*1|'\s*--)",
        r"(?:sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay)",
    ]
    XSS_PATTERNS = [
        r"<script[^>]*>", r"javascript\s*:",
        r"on(?:load|error|click|mouseover)\s*=",
    ]
    CMD_PATTERNS = [
        r"(?:;\s*(?:ls|cat|whoami|id|pwd|uname|wget|curl|rm|chmod))",
        r"(?:\|\s*(?:sh|bash|cmd|powershell))",
        r"(?:\.\./\.\./|/etc/passwd|/etc/shadow)",
    ]

    def analyze(self, events: List[Dict]) -> List[Dict[str, Any]]:
        findings = []
        auth_failures: Dict[str, int] = {}

        for event in events:
            if event.get("source") != "application":
                continue
            msg = (event.get("message") or "").lower()
            raw = (event.get("raw_log") or "").lower()
            url = (event.get("url") or "").lower()
            combined = msg + " " + raw + " " + url
            src_ip = event.get("source_ip", "")

            for pattern in self.SQL_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    findings.append(self._finding(event, "SQL Injection",
                        "SQL injection pattern detected", 0.85,
                        ["SQL injection pattern matched", event.get("raw_log", "")]))
                    break

            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    findings.append(self._finding(event, "Cross-Site Scripting (XSS)",
                        "XSS pattern detected", 0.8,
                        ["XSS pattern matched", event.get("raw_log", "")]))
                    break

            for pattern in self.CMD_PATTERNS:
                if re.search(pattern, combined, re.IGNORECASE):
                    findings.append(self._finding(event, "Command Injection",
                        "Command injection pattern detected", 0.8,
                        ["Command injection pattern", event.get("raw_log", "")]))
                    break

            if re.search(r'(?:\.\./|\.\.\\|%2e%2e)', combined, re.IGNORECASE):
                findings.append(self._finding(event, "Path Traversal",
                    "Directory traversal attempt", 0.75,
                    ["Path traversal pattern", event.get("raw_log", "")]))

            if any(kw in combined for kw in ["401", "403", "unauthorized", "forbidden",
                    "auth failed", "login failed"]):
                key = src_ip or "unknown"
                auth_failures[key] = auth_failures.get(key, 0) + 1
                if auth_failures[key] >= 5:
                    findings.append(self._finding(event, "Application Brute Force",
                        f"Repeated auth failures ({auth_failures[key]}) from {key}",
                        min(0.9, 0.5 + auth_failures[key] * 0.04),
                        [f"{auth_failures[key]} failures from {key}", event.get("raw_log", "")]))

            if any(kw in combined for kw in ["/admin", "/debug", "/console",
                    "/.env", "/wp-admin", "/phpmyadmin", "/.git"]):
                findings.append(self._finding(event, "Suspicious URL Access",
                    "Access to sensitive endpoint", 0.6,
                    ["Sensitive endpoint access", event.get("raw_log", "")]))

        return findings

    def _finding(self, event, threat_type, description, confidence, evidence):
        severity = "CRITICAL" if confidence >= 0.8 else "HIGH" if confidence >= 0.6 else "MEDIUM"
        return {
            "id": f"FIND-APP-{uuid.uuid4().hex[:8]}", "agent": "ApplicationAgent",
            "threat_type": threat_type, "description": description,
            "confidence": confidence, "severity": severity,
            "source_ip": event.get("source_ip"), "url": event.get("url"),
            "evidence": evidence,
            "timestamp": event.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
        }


# =============================================================================
# EVENT CORRELATOR
# =============================================================================

class EventCorrelator:
    """Correlates related security findings using IP, time, and type matching."""
    def correlate(self, findings: List[Dict], events: List[Dict]) -> List[Dict[str, Any]]:
        if not findings:
            return []
        correlations = []

        ip_groups: Dict[str, List[Dict]] = {}
        for f in findings:
            ip = f.get("source_ip")
            if ip:
                ip_groups.setdefault(ip, []).append(f)

        for ip, group in ip_groups.items():
            if len(group) >= 2:
                types = list(set(f["threat_type"] for f in group))
                agents = list(set(f["agent"] for f in group))
                strength = "STRONG" if len(agents) > 1 else "MODERATE"
                score = min(95, 40 + len(group) * 10 + (20 if len(agents) > 1 else 0))
                correlations.append({
                    "id": f"CORR-{uuid.uuid4().hex[:8]}",
                    "type": "IP-Based Correlation",
                    "description": f"Multiple threats from IP {ip}: {', '.join(types[:4])}",
                    "related_findings": [f["id"] for f in group],
                    "source_ip": ip, "threat_types": types,
                    "agents_involved": agents, "event_count": len(group),
                    "correlation_score": score, "strength": strength,
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

        agent_findings: Dict[str, List[Dict]] = {}
        for f in findings:
            agent_findings.setdefault(f["agent"], []).append(f)

        if len(agent_findings) >= 2:
            all_types = []
            all_agents = []
            for agent, group in agent_findings.items():
                all_types.extend([f["threat_type"] for f in group])
                all_agents.append(agent)
            correlations.append({
                "id": f"CORR-{uuid.uuid4().hex[:8]}",
                "type": "Multi-Agent Attack Chain",
                "description": f"Cross-domain threats by {', '.join(all_agents)}",
                "related_findings": [f["id"] for f in findings],
                "threat_types": list(set(all_types)),
                "agents_involved": all_agents, "event_count": len(findings),
                "correlation_score": min(95, 50 + len(all_agents) * 15),
                "strength": "STRONG",
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        return correlations


# =============================================================================
# RISK SCORER
# =============================================================================

class RiskScorer:
    """Calculates a deterministic 0-100 risk score with explanation."""
    SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    THREAT_WEIGHTS = {
        "SQL Injection": 25, "Command Injection": 25, "Cross-Site Scripting (XSS)": 20,
        "Path Traversal": 18, "Brute Force Attack": 22, "Port Scanning": 15,
        "Privilege Escalation": 25, "TCP Flood Attack": 20, "DNS Tunneling": 18,
        "Suspicious IP Activity": 12, "Successful Login After Brute Force": 28,
        "Application Brute Force": 20,
    }

    def score(self, findings: List[Dict], correlations: List[Dict]) -> Dict[str, Any]:
        if not findings:
            return {"risk_score": 0, "risk_band": "Low", "priority": "P4", "factors": {},
                    "explanation": "No threats detected."}

        factors = {}

        severities = [f.get("severity", "LOW") for f in findings]
        max_sev = "LOW"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if s in severities:
                max_sev = s
                break
        sev_score = self.SEVERITY_WEIGHTS.get(max_sev, 5)
        factors["severity"] = {"value": max_sev, "contribution": sev_score}

        threat_types = [f.get("threat_type", "") for f in findings]
        max_type_score = 0
        dominant_type = "Unknown"
        for tt in threat_types:
            tw = self.THREAT_WEIGHTS.get(tt, 8)
            if tw > max_type_score:
                max_type_score = tw
                dominant_type = tt
        factors["threat_type"] = {"value": dominant_type, "contribution": max_type_score}

        volume_score = min(15, len(findings) * 3)
        factors["event_volume"] = {"value": len(findings), "contribution": volume_score}

        avg_conf = sum(f.get("confidence", 0) for f in findings) / len(findings)
        conf_score = round(avg_conf * 15, 1)
        factors["confidence"] = {"value": round(avg_conf, 2), "contribution": conf_score}

        corr_score = 0
        if correlations:
            max_corr = max(c.get("correlation_score", 0) for c in correlations)
            corr_score = min(15, max_corr * 0.15)
        factors["correlation"] = {"value": len(correlations), "contribution": round(corr_score, 1)}

        total = sev_score + max_type_score + volume_score + conf_score + corr_score
        risk_score = round(min(100, max(0, total)), 1)

        if risk_score >= 80:
            risk_band, priority = "Critical", "P1"
        elif risk_score >= 60:
            risk_band, priority = "High", "P2"
        elif risk_score >= 30:
            risk_band, priority = "Medium", "P3"
        else:
            risk_band, priority = "Low", "P4"

        parts = []
        for name, info in sorted(factors.items(), key=lambda x: x[1]["contribution"], reverse=True):
            if info["contribution"] > 0:
                parts.append(f"{name}: {info['value']} (+{info['contribution']}pts)")

        return {"risk_score": risk_score, "risk_band": risk_band, "priority": priority,
                "factors": factors, "explanation": "Risk breakdown: " + " | ".join(parts)}


# =============================================================================
# ORCHESTRATOR
# =============================================================================

_network_agent = NetworkAgent()
_system_agent = SystemAgent()
_application_agent = ApplicationAgent()
_correlator = EventCorrelator()
_risk_scorer = RiskScorer()


def analyze_logs(raw_text: str, source_type: str = "auto", model_service=None) -> Dict[str, Any]:
    """Main orchestrator: raw log text -> full analysis result."""
    start_time = time.time()

    events = LogPreprocessor.preprocess(raw_text, source_type)
    if not events:
        return {
            "status": "NO_EVENTS", "message": "No valid events could be parsed.",
            "events_parsed": 0, "threat_detected": False, "findings": [], "correlations": [],
            "risk_assessment": {"risk_score": 0, "risk_band": "Low", "priority": "P4",
                                "explanation": "No events to analyze."},
            "incident": None,
            "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        }

    net_events = [e for e in events if e.get("source") == "network"]
    sys_events = [e for e in events if e.get("source") == "system"]
    app_events = [e for e in events if e.get("source") == "application"]

    all_findings = []
    agents_used = []

    if net_events:
        nf = _network_agent.analyze(net_events)
        all_findings.extend(nf)
        if nf: agents_used.append("NetworkAgent")
    if sys_events:
        sf = _system_agent.analyze(sys_events)
        all_findings.extend(sf)
        if sf: agents_used.append("SystemAgent")
    if app_events:
        af = _application_agent.analyze(app_events)
        all_findings.extend(af)
        if af: agents_used.append("ApplicationAgent")

    correlations = _correlator.correlate(all_findings, events)

    ml_result = None
    if model_service and all_findings:
        try:
            sample_features = {"Flow Duration": 1000.0, "Total Fwd Packets": 5.0,
                "Total Backward Packets": 3.0, "Flow Bytes/s": 1500.0,
                "Flow Packets/s": 10.0, "Fwd Packet Length Mean": 200.0,
                "Bwd Packet Length Mean": 150.0, "Flow IAT Mean": 100.0}
            ml_result = model_service.predict(model_id=None, feature_values=sample_features)
        except Exception:
            pass

    risk_assessment = _risk_scorer.score(all_findings, correlations)
    threat_detected = len(all_findings) > 0
    incident = None

    if threat_detected and risk_assessment["risk_score"] >= 20:
        top = max(all_findings, key=lambda f: f.get("confidence", 0))
        src_ips = list(set(f.get("source_ip") for f in all_findings if f.get("source_ip")))
        dst_ips = list(set(f.get("destination_ip") for f in all_findings if f.get("destination_ip")))
        incident = {
            "incident_id": f"INC-{int(time.time() * 1000) % 1000000}",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "title": f"{top['threat_type']} \u2014 {risk_assessment['risk_band']} Risk",
            "source": top.get("agent", "Unknown"),
            "agent": ", ".join(agents_used) if agents_used else top.get("agent", "Unknown"),
            "threat_type": top["threat_type"], "severity": risk_assessment["risk_band"].upper(),
            "risk_score": risk_assessment["risk_score"],
            "confidence": round(top.get("confidence", 0), 2),
            "source_ip": src_ips[0] if src_ips else None,
            "destination_ip": dst_ips[0] if dst_ips else None,
            "description": top["description"],
            "evidence": [f["description"] for f in all_findings[:5]],
            "status": "NEW", "findings_count": len(all_findings),
            "correlation_count": len(correlations),
            "risk_explanation": risk_assessment["explanation"],
        }

    return {
        "status": "COMPLETED", "events_parsed": len(events),
        "events_by_source": {"network": len(net_events), "system": len(sys_events), "application": len(app_events)},
        "threat_detected": threat_detected, "findings": all_findings,
        "findings_count": len(all_findings), "agents_used": agents_used,
        "correlations": correlations, "risk_assessment": risk_assessment,
        "ml_result": ml_result, "incident": incident,
        "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        "analyzed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# =============================================================================
# DEMO LOG DATA
# =============================================================================

DEMO_LOGS = {
    "network_port_scan": """2026-09-17T10:15:01Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=22 proto=TCP action=connect status=open
2026-09-17T10:15:02Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=23 proto=TCP action=connect status=closed
2026-09-17T10:15:03Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=80 proto=TCP action=connect status=open
2026-09-17T10:15:04Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=443 proto=TCP action=connect status=open
2026-09-17T10:15:05Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=3306 proto=TCP action=connect status=filtered
2026-09-17T10:15:06Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=5432 proto=TCP action=connect status=closed
2026-09-17T10:15:07Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=8080 proto=TCP action=connect status=open
2026-09-17T10:15:08Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=3389 proto=TCP action=connect status=filtered""",

    "system_brute_force": """Sep 17 10:20:01 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54321 ssh2
Sep 17 10:20:03 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54322 ssh2
Sep 17 10:20:05 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54323 ssh2
Sep 17 10:20:07 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54324 ssh2
Sep 17 10:20:09 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54325 ssh2
Sep 17 10:20:11 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54326 ssh2
Sep 17 10:20:13 server01 sshd[12345]: Accepted password for admin from 10.0.1.50 port 54327 ssh2
Sep 17 10:20:15 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash""",

    "application_sql_injection": """2026-09-17T10:25:01Z 192.168.1.200 GET /api/users?id=1' OR '1'='1 HTTP/1.1 200 text/html
2026-09-17T10:25:02Z 192.168.1.200 POST /api/login HTTP/1.1 401 application/json auth failed username=admin
2026-09-17T10:25:03Z 192.168.1.200 POST /api/login HTTP/1.1 401 application/json auth failed username=admin
2026-09-17T10:25:04Z 192.168.1.200 GET /api/users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1 500 text/html
2026-09-17T10:25:05Z 192.168.1.200 GET /admin/console HTTP/1.1 403 text/html
2026-09-17T10:25:06Z 192.168.1.200 GET /api/data?file=../../etc/passwd HTTP/1.1 400 text/html
2026-09-17T10:25:07Z 192.168.1.200 POST /api/search HTTP/1.1 200 application/json query=<script>alert('xss')</script>""",

    "normal_traffic": """2026-09-17T10:30:01Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP action=connect status=established
2026-09-17T10:30:05Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP bytes_sent=1500 bytes_recv=3200
Sep 17 10:30:10 server01 sshd[99999]: Accepted password for developer from 192.168.1.10 port 55000 ssh2
Sep 17 10:30:15 server01 systemd[1]: Started Daily apt download activities.
2026-09-17T10:30:20Z 192.168.1.10 GET /api/dashboard HTTP/1.1 200 application/json
2026-09-17T10:30:25Z 192.168.1.10 GET /api/profile HTTP/1.1 200 application/json""",

    "mixed_attack": """2026-09-17T11:00:01Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=22 proto=TCP SYN action=connect
2026-09-17T11:00:02Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=80 proto=TCP SYN action=connect
2026-09-17T11:00:03Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=443 proto=TCP SYN action=connect
2026-09-17T11:00:04Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=3306 proto=TCP SYN action=connect
2026-09-17T11:00:05Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=5432 proto=TCP SYN action=connect
Sep 17 11:01:01 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54321 ssh2
Sep 17 11:01:03 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54322 ssh2
Sep 17 11:01:05 server01 sshd[12345]: Failed password for root from 203.0.113.50 port 54323 ssh2
Sep 17 11:01:07 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54324 ssh2
Sep 17 11:01:09 server01 sshd[12345]: Accepted password for admin from 203.0.113.50 port 54325 ssh2
Sep 17 11:01:11 server01 sudo: admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash
2026-09-17T11:02:01Z 203.0.113.50 POST /api/data HTTP/1.1 200 application/json body=1' UNION SELECT * FROM users--
2026-09-17T11:02:05Z 203.0.113.50 GET /admin/console HTTP/1.1 403 text/html"""
}


def get_demo_log(scenario: str = "mixed_attack") -> Tuple[str, str]:
    """Returns (log_text, source_type) for a demo scenario."""
    if scenario in DEMO_LOGS:
        source = "auto"
        if "network" in scenario: source = "network"
        elif "system" in scenario: source = "system"
        elif "application" in scenario: source = "application"
        return DEMO_LOGS[scenario], source
    return DEMO_LOGS["mixed_attack"], "auto"


def get_available_demos() -> List[Dict[str, str]]:
    return [
        {"id": "network_port_scan", "name": "Network Port Scan", "source": "network",
         "description": "Port scanning from single IP"},
        {"id": "system_brute_force", "name": "System Brute Force", "source": "system",
         "description": "SSH brute force + privilege escalation"},
        {"id": "application_sql_injection", "name": "Application SQL Injection", "source": "application",
         "description": "SQL injection, XSS, path traversal attempts"},
        {"id": "normal_traffic", "name": "Normal Traffic", "source": "auto",
         "description": "Benign activity (should NOT trigger threats)"},
        {"id": "mixed_attack", "name": "Mixed Multi-Agent Attack", "source": "auto",
         "description": "Network scan + brute force + web attack chain"},
    ]
