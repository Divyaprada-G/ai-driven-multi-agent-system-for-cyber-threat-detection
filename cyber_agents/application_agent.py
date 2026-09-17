"""
Agent 3: Application Monitoring Agent
Accepts application logs (HTTP access, API transactions, application server logs).
Detects SQL injection patterns, Cross-Site Scripting (XSS), path traversal,
unauthorized administrative probing, and repeated 500 server error spikes.
Outputs structured SecurityEvent dictionaries.
"""
import re
from typing import List, Dict, Any, Optional
import logging
from cyber_agents.schemas import SecurityEvent, utc_now_iso

logger = logging.getLogger("ApplicationAgent")

class ApplicationAgent:
    """
    Defensive application security monitoring agent:
    - Parses HTTP access, REST API, and web server logs
    - Inspects request paths, query parameters, status codes, and HTTP verbs
    - Identifies OWASP Web Top 10 indicators (SQLi, XSS, Path Traversal, Admin Probing)
    """

    IP_PATTERN = re.compile(r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b')
    HTTP_METHOD_PATTERN = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')
    STATUS_CODE_PATTERN = re.compile(r'\s([1-5][0-9]{2})\s')

    SQLI_PATTERNS = [
        re.compile(r"union\s+select", re.IGNORECASE),
        re.compile(r"['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
        re.compile(r"['\"]\s*or\s*1\s*=\s*1", re.IGNORECASE),
        re.compile(r"from\s+users\s*--", re.IGNORECASE),
        re.compile(r"waitfor\s+delay", re.IGNORECASE),
        re.compile(r"benchmark\s*\(", re.IGNORECASE),
        re.compile(r"information_schema", re.IGNORECASE)
    ]

    XSS_PATTERNS = [
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE)
    ]

    TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./\.\.", re.IGNORECASE),
        re.compile(r"\.\.\\\.\.", re.IGNORECASE),
        re.compile(r"%2e%2e%2f", re.IGNORECASE),
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"win\.ini", re.IGNORECASE)
    ]

    ADMIN_PATHS = ["/admin", "/console", "/wp-admin", "/manager/html", "/actuator", "/.env", "/phpmyadmin"]

    def __init__(self, error_spike_threshold: int = 5):
        self.error_spike_threshold = error_spike_threshold

    def parse_app_line(self, line: str) -> Optional[Dict[str, Any]]:
        if not line or not isinstance(line, str):
            return None
        clean_line = line.strip()
        if not clean_line:
            return None

        ip_match = self.IP_PATTERN.search(clean_line)
        src_ip = ip_match.group(1) if ip_match else None

        method_match = self.HTTP_METHOD_PATTERN.search(clean_line)
        method = method_match.group(1) if method_match else "GET"

        status_match = self.STATUS_CODE_PATTERN.search(clean_line)
        status_code = int(status_match.group(1)) if status_match else None

        return {
            "source_ip": src_ip,
            "method": method,
            "status_code": status_code,
            "raw": clean_line
        }

    def process_logs(self, logs: List[str]) -> List[Dict[str, Any]]:
        """
        Processes web/application logs and returns structured SecurityEvent dicts.
        """
        if not logs or not isinstance(logs, list):
            return []

        events: List[SecurityEvent] = []
        ip_error_counts: Dict[str, int] = {}

        for line in logs:
            try:
                parsed = self.parse_app_line(line)
                if not parsed:
                    continue

                raw = parsed["raw"]
                src_ip = parsed["source_ip"]
                status = parsed["status_code"]

                # 1. SQL Injection Detection
                for pat in self.SQLI_PATTERNS:
                    if pat.search(raw):
                        events.append(SecurityEvent(
                            agent_name="Application Monitoring Agent",
                            event_type="SQL Injection (SQLi)",
                            severity="CRITICAL",
                            source="Web Application Layer",
                            description="SQL injection pattern identified in HTTP request body or URI parameters.",
                            indicators={
                                "source_ip": src_ip,
                                "matched_pattern": pat.pattern,
                                "raw_log": raw
                            },
                            recommended_action="Deploy WAF rule for parameter sanitization and inspect database queries for parameterized inputs."
                        ))
                        break

                # 2. Cross-Site Scripting (XSS) Detection
                for pat in self.XSS_PATTERNS:
                    if pat.search(raw):
                        events.append(SecurityEvent(
                            agent_name="Application Monitoring Agent",
                            event_type="Cross-Site Scripting (XSS)",
                            severity="HIGH",
                            source="Application Request Inspector",
                            description="Script injection payload detected in client request parameters.",
                            indicators={
                                "source_ip": src_ip,
                                "matched_pattern": pat.pattern,
                                "raw_log": raw
                            },
                            recommended_action="Enable strict Content-Security-Policy (CSP) headers and ensure contextual HTML output encoding."
                        ))
                        break

                # 3. Path Traversal
                for pat in self.TRAVERSAL_PATTERNS:
                    if pat.search(raw):
                        events.append(SecurityEvent(
                            agent_name="Application Monitoring Agent",
                            event_type="Path Traversal",
                            severity="MEDIUM",
                            source="Application File Dispatcher",
                            description="Directory traversal markers attempting to access restricted filesystem paths.",
                            indicators={
                                "source_ip": src_ip,
                                "raw_log": raw
                            },
                            recommended_action="Normalize and strictly validate file path input parameters before resolving files on disk."
                        ))
                        break

                # 4. Unauthorized Admin Endpoint Probing
                lower_raw = raw.lower()
                for admin_path in self.ADMIN_PATHS:
                    if admin_path in lower_raw and (status in [401, 403, 404] or "403" in raw or "401" in raw):
                        events.append(SecurityEvent(
                            agent_name="Application Monitoring Agent",
                            event_type="Unauthorized Endpoint Reconnaissance",
                            severity="MEDIUM",
                            source="HTTP Endpoint Gatekeeper",
                            description=f"Automated probe targeting administrative path '{admin_path}'.",
                            indicators={
                                "source_ip": src_ip,
                                "targeted_path": admin_path,
                                "status_code": status
                            },
                            recommended_action="Ensure administrative consoles are gated behind VPN or zero-trust identity access proxies."
                        ))
                        break

                # 5. Track repeated internal server errors (500)
                if status and status >= 500 and src_ip:
                    ip_error_counts[src_ip] = ip_error_counts.get(src_ip, 0) + 1

            except Exception as e:
                logger.warning(f"Error analyzing app log line: {e}")
                continue

        # Aggregated Rule: Application Error Spike / Fuzzing
        for ip, err_count in ip_error_counts.items():
            if err_count >= self.error_spike_threshold:
                events.append(SecurityEvent(
                    agent_name="Application Monitoring Agent",
                    event_type="Application Exception Spike / Fuzzing",
                    severity="MEDIUM",
                    source="Application Health Monitor",
                    description=f"High frequency of 5xx HTTP exceptions ({err_count}) triggered by source {ip}.",
                    indicators={
                        "source_ip": ip,
                        "error_count": err_count
                    },
                    recommended_action="Review application stack traces for unhandled exceptions or potential payload fuzzing attacks."
                ))

        return [e.to_dict() for e in events]
