"""
Application Log File Tailing Collector
Monitors and tails application log files in configurable Windows directories.
Tails newly appended log lines without re-reading entire files.
Supports JSON, timestamped, and plain text formats with graceful permission & absence handling.
"""
import os
import re
import json
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from windows_collector.normalizer import EventNormalizer

logger = logging.getLogger("AppFileTailCollector")

class AppFileTailCollector:
    """
    Tails application log files across configured directories.
    Handles file rotation, newly appended lines, JSON/text formats, and permission errors.
    """
    def __init__(
        self,
        normalizer: EventNormalizer,
        directories: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        max_batch_size: int = 50
    ):
        self.normalizer = normalizer
        self.directories = directories or [r"C:\inetpub\logs", r"C:\ProgramData\AppLogs", "logs"]
        self.extensions = tuple(extensions or [".log", ".txt", ".json", ".jsonl"])
        self.max_batch_size = max_batch_size

        # File state tracking: file_path -> {"offset": int, "mtime": float, "size": int, "status": str, "last_error": str}
        self.file_states: Dict[str, Dict[str, Any]] = {}
        # Directory state tracking: dir_path -> {"status": str, "files_found": int, "last_error": str}
        self.dir_states: Dict[str, Dict[str, Any]] = {
            d: {"status": "INITIALIZING", "files_found": 0, "last_error": None}
            for d in self.directories
        }

        # Common threat detection regexes for application logs (matching ApplicationAgent patterns)
        self.re_sqli = re.compile(
            r"(\bUNION\b\s+\bSELECT\b|'\s*OR\s*'?\d+'?\s*=\s*'?\d+|1=1|--|;\s*DROP\s+TABLE|WAITFOR\s+DELAY)",
            re.IGNORECASE
        )
        self.re_xss = re.compile(
            r"(<script\b|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=)",
            re.IGNORECASE
        )
        self.re_traversal = re.compile(
            r"(\.\./|\.\.\\|/etc/passwd|windows/system32|win\.ini|boot\.ini)",
            re.IGNORECASE
        )
        self.re_auth_fail = re.compile(
            r"(failed\s+login|invalid\s+password|authentication\s+failed|access\s+denied|status=401|status=403)",
            re.IGNORECASE
        )
        self.re_ip = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    def get_status(self) -> Dict[str, Any]:
        return {
            "collector_name": "AppFileTailCollector",
            "directories": self.dir_states,
            "tracked_files_count": len(self.file_states),
            "files": {
                p: {
                    "offset": st["offset"],
                    "size": st["size"],
                    "status": st["status"],
                    "last_error": st["last_error"]
                }
                for p, st in list(self.file_states.items())[:20]
            }
        }

    def collect(self) -> List[Dict[str, Any]]:
        """
        Scans all directories, discovers active log files, tails newly appended lines,
        and returns normalized security events.
        """
        all_events: List[Dict[str, Any]] = []

        # 1. Discover log files across directories
        current_files = self._discover_files()

        # 2. Tail each file
        for file_path in current_files:
            if len(all_events) >= self.max_batch_size:
                break
            events = self._tail_file(file_path)
            all_events.extend(events)

        return all_events

    def _discover_files(self) -> List[str]:
        """
        Discovers files with matching extensions in configured directories.
        Gracefully handles unavailable folders and permission errors.
        """
        discovered: List[str] = []

        for d in self.directories:
            d_state = self.dir_states.setdefault(d, {"status": "INITIALIZING", "files_found": 0, "last_error": None})
            
            if not os.path.exists(d):
                d_state["status"] = "SOURCE_UNAVAILABLE"
                d_state["files_found"] = 0
                d_state["last_error"] = f"Directory '{d}' does not exist on host."
                continue

            if not os.path.isdir(d):
                d_state["status"] = "INVALID_PATH"
                d_state["last_error"] = f"Path '{d}' is not a directory."
                continue

            try:
                files_in_dir = []
                # Scan directory non-recursively for fast, safe operation
                for entry in os.scandir(d):
                    try:
                        if entry.is_file() and entry.name.lower().endswith(self.extensions):
                            files_in_dir.append(entry.path)
                    except PermissionError:
                        logger.warning(f"Permission denied accessing file entry {entry.name} in {d}")
                    except Exception:
                        continue

                d_state["status"] = "LIVE"
                d_state["files_found"] = len(files_in_dir)
                d_state["last_error"] = None
                discovered.extend(files_in_dir)
            except PermissionError as pe:
                d_state["status"] = "PERMISSION_DENIED"
                d_state["last_error"] = f"Permission denied scanning directory '{d}': {pe}"
                logger.warning(f"Permission denied scanning directory {d}: {pe}")
            except Exception as e:
                d_state["status"] = "ERROR"
                d_state["last_error"] = str(e)
                logger.error(f"Error scanning directory {d}: {e}")

        return discovered

    def _tail_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Reads newly appended lines from a single log file using seek offset.
        Handles log rotation and permission errors.
        """
        state = self.file_states.setdefault(file_path, {
            "offset": 0,
            "mtime": 0.0,
            "size": 0,
            "status": "INITIALIZING",
            "last_error": None
        })

        try:
            stat_res = os.stat(file_path)
        except PermissionError as pe:
            state["status"] = "PERMISSION_DENIED"
            state["last_error"] = f"Permission denied reading stat for '{file_path}': {pe}"
            return []
        except FileNotFoundError:
            state["status"] = "SOURCE_UNAVAILABLE"
            state["last_error"] = f"File '{file_path}' was removed."
            return []
        except Exception as e:
            state["status"] = "ERROR"
            state["last_error"] = str(e)
            return []

        curr_size = stat_res.st_size
        curr_mtime = stat_res.st_mtime
        state["size"] = curr_size
        state["mtime"] = curr_mtime

        # If file is empty or hasn't grown
        if curr_size == state["offset"]:
            state["status"] = "HEALTHY_IDLE"
            return []

        # Handle log rotation / truncation: file shrank
        if curr_size < state["offset"]:
            logger.info(f"Log rotation detected on {file_path}. Resetting offset to 0.")
            state["offset"] = 0

        # Read newly appended lines
        new_lines: List[str] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(state["offset"])
                # Read lines up to batch limit
                for _ in range(self.max_batch_size):
                    line = f.readline()
                    if not line:
                        break
                    new_lines.append(line.rstrip("\r\n"))
                state["offset"] = f.tell()
                state["status"] = "LIVE"
                state["last_error"] = None
        except PermissionError as pe:
            state["status"] = "PERMISSION_DENIED"
            state["last_error"] = f"Permission denied reading '{file_path}': {pe}"
            logger.warning(f"Permission denied reading application log {file_path}: {pe}")
            return []
        except Exception as e:
            state["status"] = "ERROR"
            state["last_error"] = str(e)
            logger.error(f"Error reading {file_path}: {e}")
            return []

        # Parse and normalize lines
        events: List[Dict[str, Any]] = []
        for line in new_lines:
            if not line.strip():
                continue
            parsed = self.parse_log_line(line, file_path)
            if parsed:
                events.append(parsed)

        return events

    def parse_log_line(self, line: str, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single log line (JSON or plain text) and normalizes it.
        """
        clean_line = line.strip()
        if not clean_line:
            return None

        # Check if line is JSON
        is_json = False
        json_data = {}
        if (clean_line.startswith("{") and clean_line.endswith("}")):
            try:
                json_data = json.loads(clean_line)
                is_json = True
            except Exception:
                is_json = False

        # Extract timestamp, level, message, ip
        if is_json:
            ts = json_data.get("timestamp") or json_data.get("time") or datetime.now(timezone.utc).isoformat()
            raw_level = str(json_data.get("level") or json_data.get("severity") or "INFO").upper()
            msg = str(json_data.get("message") or json_data.get("msg") or clean_line)
            src_ip = json_data.get("client_ip") or json_data.get("ip") or json_data.get("source_ip")
            user = json_data.get("user") or json_data.get("username")
        else:
            ts = datetime.now(timezone.utc).isoformat()
            raw_level = "INFO"
            msg = clean_line
            user = None
            # Find IP in text
            ip_match = self.re_ip.search(clean_line)
            src_ip = ip_match.group(1) if ip_match else "127.0.0.1"
            # Infer level from text
            lower_msg = clean_line.lower()
            if "crit" in lower_msg or "fatal" in lower_msg:
                raw_level = "CRITICAL"
            elif "error" in lower_msg or "err" in lower_msg:
                raw_level = "HIGH"
            elif "warn" in lower_msg:
                raw_level = "MEDIUM"

        # Check for web application threats (SQLi, XSS, Traversal, Auth Failures)
        threat_type = "Application Log Entry"
        raw_severity = self._map_log_level_to_severity(raw_level)

        # Unquote URL parameters if present (e.g. GET /products?id=1%20UNION%20SELECT)
        decoded_msg = urllib.parse.unquote_plus(msg)
        target_check = f"{msg} {decoded_msg}"

        threat_sev = "LOW"
        if self.re_sqli.search(target_check):
            threat_type = "SQL Injection Attempt (T1190)"
            threat_sev = "HIGH"
        elif self.re_xss.search(target_check):
            threat_type = "Cross-Site Scripting (XSS) (T1189)"
            threat_sev = "MEDIUM"
        elif self.re_traversal.search(target_check):
            threat_type = "Path Traversal / Local File Inclusion (T1083)"
            threat_sev = "HIGH"
        elif self.re_auth_fail.search(target_check):
            threat_type = "Authentication Failure (T1110)"
            threat_sev = "MEDIUM"

        def rank(s):
            return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 1)

        severity = threat_sev if rank(threat_sev) > rank(raw_severity) else raw_severity

        normalized = self.normalizer.normalize(
            source_type="application_log_file",
            collector_name="AppFileTailCollector",
            raw_message=clean_line,
            collection_status="COLLECTED",
            timestamp=ts,
            source="application",
            event_type=f"App Log: {threat_type}",
            severity=severity,
            source_ip=src_ip or "127.0.0.1",
            destination_ip="127.0.0.1",
            username=user,
            details=f"Tailed from {os.path.basename(file_path)}: {msg[:120]}",
            features={
                "file_path": file_path,
                "is_json": is_json,
                "threat_type": threat_type,
                "line_length": len(clean_line)
            },
            custom_metadata={
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "is_json": is_json
            }
        )

        return normalized

    def _map_log_level_to_severity(self, level_str: str) -> str:
        lvl = level_str.upper()
        if lvl in ["CRITICAL", "FATAL"]:
            return "CRITICAL"
        if lvl in ["ERROR", "ERR"]:
            return "HIGH"
        if lvl in ["WARN", "WARNING"]:
            return "MEDIUM"
        return "LOW"
