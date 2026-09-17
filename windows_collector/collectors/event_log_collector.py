"""
Windows Event Log Collector
Safely queries System, Application, and Security event logs on Windows hosts.
Handles permissions (e.g. Administrator requirement for Security log) gracefully.
Does NOT fabricate events on failure or on non-Windows platforms.
"""
import sys
import platform
import subprocess
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from windows_collector.normalizer import EventNormalizer

logger = logging.getLogger("WindowsEventLogCollector")

# XML Namespace for Windows Event Log XML schema
WIN_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

class WindowsEventLogCollector:
    """
    Modular collector for Windows System, Application, and Security event logs.
    """
    def __init__(
        self,
        normalizer: EventNormalizer,
        channels: Optional[List[str]] = None,
        max_batch_size: int = 50
    ):
        self.normalizer = normalizer
        self.channels = channels or ["System", "Application", "Security"]
        self.max_batch_size = max_batch_size
        self.is_windows = sys.platform == "win32" or platform.system() == "Windows"
        
        # State tracking per channel
        # channel -> {"last_record_id": int, "status": str, "events_collected": int, "error": str}
        self.channel_states: Dict[str, Dict[str, Any]] = {
            ch: {
                "last_record_id": 0,
                "status": "INITIALIZING" if self.is_windows else "SOURCE_UNAVAILABLE",
                "events_collected": 0,
                "last_error": None,
                "last_collection_time": None
            }
            for ch in self.channels
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "collector_name": "WindowsEventLogCollector",
            "is_windows": self.is_windows,
            "channels": self.channel_states,
            "overall_status": "READY" if self.is_windows else "SOURCE_UNAVAILABLE"
        }

    def collect(self) -> List[Dict[str, Any]]:
        """
        Executes a collection cycle across all configured channels.
        Returns a list of normalized events.
        """
        if not self.is_windows:
            for ch in self.channels:
                self.channel_states[ch]["status"] = "SOURCE_UNAVAILABLE"
                self.channel_states[ch]["last_error"] = (
                    "Windows Event Log queries require Microsoft Windows environment (wevtutil). "
                    f"Current OS is {platform.system()}."
                )
            return []

        all_events: List[Dict[str, Any]] = []

        for channel in self.channels:
            events = self._collect_channel(channel)
            all_events.extend(events)

        return all_events

    def _collect_channel(self, channel: str) -> List[Dict[str, Any]]:
        """
        Queries a single Windows Event Log channel using wevtutil.
        Detects permission failures (especially on Security log) and non-existent logs.
        """
        state = self.channel_states[channel]
        now_iso = datetime.now(timezone.utc).isoformat()
        state["last_collection_time"] = now_iso

        # Build wevtutil command: query latest events reverse-chronologically in XML format
        cmd = [
            "wevtutil.exe",
            "qe",
            channel,
            "/q:*",
            "/f:xml",
            f"/c:{self.max_batch_size}",
            "/rd:true"
        ]

        try:
            # Execute wevtutil without opening console window on Windows
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                startupinfo=startupinfo
            )
        except FileNotFoundError:
            state["status"] = "SOURCE_UNAVAILABLE"
            state["last_error"] = "wevtutil.exe not found on system PATH."
            logger.warning(f"wevtutil.exe not found when querying {channel}")
            return []
        except subprocess.TimeoutExpired:
            state["status"] = "TIMEOUT"
            state["last_error"] = f"Query timed out after 12s on channel {channel}."
            logger.warning(f"wevtutil timeout querying {channel}")
            return []
        except Exception as e:
            state["status"] = "ERROR"
            state["last_error"] = str(e)
            logger.error(f"Unexpected error executing wevtutil on {channel}: {e}")
            return []

        # Check return code
        if process.returncode != 0:
            err_msg = (process.stderr or process.stdout or "").strip()
            # Check for Access Denied / Administrator elevation required (typical for Security channel)
            if "access is denied" in err_msg.lower() or "error 5" in err_msg.lower() or "privilege" in err_msg.lower():
                state["status"] = "PERMISSION_DENIED"
                state["last_error"] = (
                    f"Access Denied for Windows Event Channel '{channel}'. "
                    "Reading the Security log requires elevated Administrator privileges ('Run as administrator')."
                )
                logger.warning(
                    f"[Permission Notice] Access to Windows Event Channel '{channel}' denied. "
                    "Run collector as Administrator to ingest security audit logs."
                )
            elif "not found" in err_msg.lower() or "does not exist" in err_msg.lower():
                state["status"] = "SOURCE_UNAVAILABLE"
                state["last_error"] = f"Event channel '{channel}' does not exist on this Windows host."
                logger.info(f"Event channel '{channel}' not found on host.")
            else:
                state["status"] = "ERROR"
                state["last_error"] = err_msg or f"wevtutil exited with code {process.returncode}"
                logger.warning(f"wevtutil error on channel {channel}: {state['last_error']}")
            return []

        xml_output = process.stdout
        if not xml_output or not xml_output.strip():
            state["status"] = "HEALTHY_EMPTY"
            state["last_error"] = None
            return []

        # Parse XML output and normalize
        parsed_events = self.parse_wevtutil_xml(xml_output, channel)
        state["status"] = "LIVE"
        state["last_error"] = None
        state["events_collected"] += len(parsed_events)
        return parsed_events

    def parse_wevtutil_xml(self, xml_string: str, channel: str) -> List[Dict[str, Any]]:
        """
        Parses multi-event XML output from wevtutil into structured events.
        Handles wevtutil's concatenated XML roots by wrapping in an envelope.
        """
        if not xml_string or not xml_string.strip():
            return []

        # Strip XML declaration if present
        clean_xml = xml_string.strip()
        if clean_xml.startswith("<?xml"):
            idx = clean_xml.find("?>")
            if idx != -1:
                clean_xml = clean_xml[idx+2:].strip()

        # Wrap in root element only if not already wrapped
        if not clean_xml.startswith("<Events"):
            wrapped_xml = f"<Events xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">{clean_xml}</Events>"
        else:
            wrapped_xml = clean_xml

        try:
            root = ET.fromstring(wrapped_xml)
        except ET.ParseError as pe:
            logger.warning(f"XML parse error on {channel} events: {pe}. Attempting individual chunk parsing.")
            return self._parse_fallback_chunks(xml_string, channel)

        events: List[Dict[str, Any]] = []
        state = self.channel_states.get(channel, {})
        last_id = state.get("last_record_id", 0)
        highest_id = last_id

        # Search for Event nodes anywhere in the tree (handles namespaces and nesting)
        event_nodes = [
            elem for elem in root.iter()
            if elem.tag.endswith("Event") and not elem.tag.endswith("Events")
        ]

        for event_node in event_nodes:
            parsed = self._extract_event_data(event_node, channel)
            if not parsed:
                continue

            record_id = parsed.get("record_id", 0)
            # Avoid re-processing if record_id <= last_id (when bookmarking is active)
            if last_id > 0 and record_id > 0 and record_id <= last_id:
                continue

            if record_id > highest_id:
                highest_id = record_id

            # Determine severity and category based on Windows Event ID & Level
            event_id_num = parsed.get("event_id_code")
            level_num = parsed.get("level", 4)
            severity = self._map_severity(level_num, event_id_num)
            threat_type = self._map_threat_type(event_id_num, channel)

            # Map to system or application source
            source_tag = "system" if channel.lower() in ["system", "security"] else "application"

            normalized = self.normalizer.normalize(
                source_type="windows_event_log",
                collector_name="WindowsEventLogCollector",
                raw_message=parsed.get("raw_xml", ""),
                collection_status="COLLECTED",
                event_id=f"WIN-EVT-{channel[:3].upper()}-{record_id or event_id_num}-{highest_id}",
                timestamp=parsed.get("time_created"),
                source=source_tag,
                event_type=f"Windows {channel} Event {event_id_num}: {threat_type}",
                severity=severity,
                source_ip=parsed.get("source_ip", "127.0.0.1"),
                destination_ip="127.0.0.1",
                username=parsed.get("username"),
                details=parsed.get("description"),
                features={
                    "event_id": event_id_num,
                    "record_id": record_id,
                    "channel": channel,
                    "level": level_num,
                    "provider": parsed.get("provider", "Unknown"),
                    "is_security_audit": channel.lower() == "security"
                },
                custom_metadata={
                    "channel": channel,
                    "provider_name": parsed.get("provider"),
                    "windows_event_id": event_id_num,
                    "record_id": record_id
                }
            )

            if normalized:
                events.append(normalized)

        if highest_id > last_id:
            state["last_record_id"] = highest_id

        return events

    def _extract_event_data(self, event_elem: ET.Element, channel: str) -> Optional[Dict[str, Any]]:
        """
        Extracts structured fields from an individual <Event> XML node.
        """
        try:
            # Helper to find any child element by local tag name ignoring namespace
            def get_child_by_tag(parent: ET.Element, tag_name: str) -> Optional[ET.Element]:
                for child in parent:
                    local_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if local_tag == tag_name:
                        return child
                return None

            def get_text_by_tag(parent: ET.Element, tag_name: str) -> str:
                el = get_child_by_tag(parent, tag_name)
                return el.text if el is not None and el.text else ""

            # System header
            sys_node = get_child_by_tag(event_elem, "System")
            if sys_node is None:
                return None

            event_id_str = get_text_by_tag(sys_node, "EventID")
            event_id_code = int(event_id_str) if event_id_str.isdigit() else 0

            record_id_str = get_text_by_tag(sys_node, "EventRecordID")
            record_id = int(record_id_str) if record_id_str.isdigit() else 0

            level_str = get_text_by_tag(sys_node, "Level")
            level = int(level_str) if level_str.isdigit() else 4

            # Provider
            provider_node = get_child_by_tag(sys_node, "Provider")
            provider = provider_node.get("Name", "Microsoft-Windows") if provider_node is not None else "Microsoft-Windows"

            # TimeCreated
            time_node = get_child_by_tag(sys_node, "TimeCreated")
            time_created = time_node.get("SystemTime") if time_node is not None else datetime.now(timezone.utc).isoformat()

            # Computer
            computer = get_text_by_tag(sys_node, "Computer") or platform.node()

            # Security User SID
            sec_node = get_child_by_tag(sys_node, "Security")
            user_id = sec_node.get("UserID", "") if sec_node is not None else ""

            # EventData extraction
            event_data_dict = {}
            ed_node = get_child_by_tag(event_elem, "EventData")
            if ed_node is not None:
                for child in ed_node:
                    local_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if local_tag == "Data":
                        name = child.get("Name", "")
                        val = child.text or ""
                        if name:
                            event_data_dict[name] = val

            # Check for standard IP / Username fields in EventData
            source_ip = event_data_dict.get("IpAddress") or event_data_dict.get("WorkstationName") or "127.0.0.1"
            if source_ip in ["-", "::1", "127.0.0.1"]:
                source_ip = "127.0.0.1"
            username = event_data_dict.get("TargetUserName") or event_data_dict.get("SubjectUserName") or user_id

            # Build human-readable description
            description = (
                f"Windows [{channel}] Event {event_id_code} from {provider}. "
                f"Host: {computer}."
            )
            if username and username != "-":
                description += f" Account: {username}."
            if "LogonType" in event_data_dict:
                description += f" LogonType: {event_data_dict['LogonType']}."
            if "FailureReason" in event_data_dict or "SubStatus" in event_data_dict:
                description += f" Status: {event_data_dict.get('FailureReason', event_data_dict.get('SubStatus'))}."

            raw_xml = ET.tostring(event_elem, encoding="unicode")

            return {
                "event_id_code": event_id_code,
                "record_id": record_id,
                "level": level,
                "provider": provider,
                "time_created": time_created,
                "computer": computer,
                "username": username if username != "-" else None,
                "source_ip": source_ip,
                "event_data": event_data_dict,
                "description": description,
                "raw_xml": raw_xml
            }
        except Exception as e:
            logger.debug(f"Error extracting XML event data: {e}")
            return None

    def _parse_fallback_chunks(self, xml_string: str, channel: str) -> List[Dict[str, Any]]:
        """
        Fallback parser when XML contains malformed segments.
        Splits by </Event> tags and parses individually.
        """
        chunks = xml_string.split("</Event>")
        parsed_results = []
        for c in chunks:
            c = c.strip()
            if not c:
                continue
            if not c.startswith("<Event"):
                idx = c.find("<Event")
                if idx >= 0:
                    c = c[idx:]
                else:
                    continue
            full_c = c + "</Event>"
            try:
                elem = ET.fromstring(full_c)
                p = self._extract_event_data(elem, channel)
                if p:
                    parsed_results.append(p)
            except Exception:
                continue
        return parsed_results

    def _map_severity(self, level: int, event_id: int) -> str:
        """
        Maps Windows Event Level and Security Event IDs to project severity tiers.
        """
        # Critical Windows Security event IDs
        if event_id in [1102, 4719]:  # Audit log cleared / System audit policy changed
            return "CRITICAL"
        if event_id in [4625, 4672, 7045]:  # Failed logon / Admin privilege / Service install
            return "HIGH"
        if event_id in [4720, 4698, 4728]:  # User created / Scheduled task / Admin group member added
            return "MEDIUM"

        # Standard Level Mapping
        if level == 1:
            return "CRITICAL"
        elif level == 2:
            return "HIGH"
        elif level == 3:
            return "MEDIUM"
        elif level in [4, 5]:
            return "LOW"
        return "LOW"

    def _map_threat_type(self, event_id: int, channel: str) -> str:
        """
        Maps Windows Event ID to MITRE ATT&CK and Security classification.
        """
        if channel.lower() == "security":
            mapping = {
                4625: "Authentication Failure / Potential Brute Force (T1110)",
                4624: "Successful Logon Audit (T1078)",
                4672: "Special Privileges Assigned / Privilege Escalation (T1078)",
                4720: "User Account Creation (T1136)",
                4728: "Security Group Membership Modification (T1098)",
                4688: "New Process Creation (T1059)",
                4698: "Scheduled Task Creation (T1053.005)",
                1102: "Audit Log Cleared / Defense Evasion (T1070.001)",
                4719: "System Audit Policy Changed (T1562.002)"
            }
            return mapping.get(event_id, "Windows Security Audit")
        elif channel.lower() == "system":
            mapping = {
                7045: "New Service Installed / Persistence (T1543.003)",
                7036: "Service State Change",
                10016: "DCOM Authorization Failure",
                41: "Kernel-Power Unexpected Shutdown",
                6005: "Event Log Service Started",
                6006: "Event Log Service Stopped"
            }
            return mapping.get(event_id, "Windows System Event")
        else:
            mapping = {
                1000: "Application Error / Crash (T1499)",
                1001: "Windows Error Reporting",
                1002: "Application Hang"
            }
            return mapping.get(event_id, "Windows Application Event")
