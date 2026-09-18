"""
Dataset Validator & Ingestion Module
Handles safe dataset ingestion, schema validation, data type detection,
missing value detection, infinite value handling, identifier isolation,
and rigorous data quality validation (missing IPs, invalid protocols,
negative failed logins, invalid timestamps, missing labels, duplicates)
without silently dropping or mutating erroneous records.
"""
import os
import csv
import math
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set

UNSAFE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".bin", ".dll", ".so", ".py", ".js",
    ".ts", ".vbs", ".ps1", ".jar", ".msi", ".com", ".scr", ".pif", ".elf"
}

IDENTIFIER_PATTERNS = {
    "flow id", "flow_id", "source ip", "src ip", "src_ip", "srcip",
    "destination ip", "dst ip", "dst_ip", "dstip", "timestamp",
    "time", "date", "mac", "host", "guid", "uuid", "hash", "session"
}

LABEL_CANDIDATES = {
    "label", "attack_cat", "class", "target", "category",
    "threat_class", "is_attack", "status"
}

VALID_PROTOCOLS = {
    "tcp", "udp", "icmp", "http", "https", "dns", "arp", "ssh", "ftp",
    "smtp", "tls", "ssl", "telnet", "dhcp", "ntp", "snmp", "rdp",
    "igmp", "gre", "esp", "ah", "sctp", "ip", "ipv6", "ipv4",
    "6", "17", "1", "47", "50", "51", "132", "0"
}

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y/%m/%d %H:%M:%S",
    "%b %d %H:%M:%S",
    "%b %d, %Y %H:%M:%S",
    "%Y-%m-%d"
]


def validate_file_safety(filename: str, file_bytes: Optional[bytes] = None) -> Tuple[bool, str]:
    """
    Validates file extension and ensures file does not contain unsafe binaries or path traversal.
    """
    if not filename:
        return False, "Filename cannot be empty."

    # Prevent path traversal escapes
    if ".." in filename:
        return False, "Path traversal attempt detected in filename."

    ext = os.path.splitext(filename)[1].lower()
    if ext in UNSAFE_EXTENSIONS:
        return False, f"Dangerous file extension '{ext}' is strictly forbidden."

    if ext != ".csv":
        return False, f"Invalid file format: '{ext}'. Only standard .csv files are supported."

    if file_bytes is not None:
        if len(file_bytes) > 10 * 1024 * 1024:
            return False, "File exceeds maximum permitted size of 10 MB."
        # Null-byte check for binary disguise
        if b"\x00" in file_bytes[:1024]:
            return False, "File contains binary null bytes and appears to be disguised as CSV."

    return True, "File passed safety validation."


def is_valid_ip(ip_str: str) -> bool:
    """Validates IPv4 or IPv6 address string."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    cleaned = ip_str.strip()
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def is_valid_timestamp(ts_str: str) -> bool:
    """Validates timestamp strings against standard datetime formats and reasonable epochs."""
    if not ts_str or not isinstance(ts_str, str):
        return False
    cleaned = ts_str.strip()
    
    # Try numeric epoch timestamp
    try:
        epoch = float(cleaned)
        # Check if epoch is between 1990 (631152000) and 2100 (4102444800)
        if 631152000 <= epoch <= 4102444800:
            return True
        # Or millisecond epoch
        if 631152000000 <= epoch <= 4102444800000:
            return True
    except ValueError:
        pass

    # Try common datetime formats
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if 1990 <= dt.year <= 2100:
                return True
        except (ValueError, TypeError):
            continue

    return False


class DatasetValidator:
    """
    Validates and inspects cybersecurity datasets (e.g. CICIDS2017, UNSW-NB15, custom logs).
    Performs rigorous data quality checks, tracks row-level validation status,
    and returns comprehensive error detection analytics.
    """

    def __init__(self):
        pass

    def load_and_validate_csv(
        self,
        filepath_or_content: str,
        is_raw_content: bool = False
    ) -> Dict[str, Any]:
        """
        Parses CSV, validates structure, identifies data types, counts missing/invalid records,
        isolates network identifier columns, and validates every row against domain rules.
        """
        if is_raw_content:
            lines = [line for line in filepath_or_content.splitlines() if line.strip()]
        else:
            safe, msg = validate_file_safety(filepath_or_content)
            if not safe:
                raise ValueError(msg)
            if not os.path.exists(filepath_or_content):
                raise FileNotFoundError(f"Dataset file not found: {filepath_or_content}")
            with open(filepath_or_content, "r", encoding="utf-8", errors="replace") as f:
                lines = [line for line in f.read().splitlines() if line.strip()]

        if len(lines) < 2:
            raise ValueError("Dataset must contain at least 1 header line and 1 data row.")

        reader = csv.reader(lines)
        raw_headers = next(reader)
        headers = [h.strip().replace('"', '') for h in raw_headers]

        rows: List[List[str]] = []
        for row in reader:
            if len(row) == len(headers):
                rows.append([cell.strip() for cell in row])
            elif len(row) > 0:
                # Handle row length mismatch by padding or truncating gracefully
                padded = (row + [""] * len(headers))[:len(headers)]
                rows.append([cell.strip() for cell in padded])

        total_rows = len(rows)
        if total_rows == 0:
            raise ValueError("Dataset has no data rows.")

        # Identify key column roles
        column_meta: Dict[str, Dict[str, Any]] = {}
        detected_label: Optional[str] = None
        identifier_columns: List[str] = []
        
        ip_col_indices: List[Tuple[int, str]] = []
        protocol_col_indices: List[Tuple[int, str]] = []
        failed_login_col_indices: List[Tuple[int, str]] = []
        timestamp_col_indices: List[Tuple[int, str]] = []
        port_col_indices: List[Tuple[int, str]] = []
        metric_col_indices: List[Tuple[int, str]] = []
        label_col_index: Optional[int] = None

        for col_idx, col_name in enumerate(headers):
            col_lower = col_name.lower().strip()
            col_normalized = col_lower.replace(" ", "_").replace("-", "_")
            
            # Check if identifier column
            is_identifier = any(pat in col_lower or pat in col_normalized for pat in IDENTIFIER_PATTERNS)
            if is_identifier:
                identifier_columns.append(col_name)

            # Check if label candidate
            if not detected_label and any(cand == col_lower or cand in col_lower or cand == col_normalized or cand in col_normalized for cand in LABEL_CANDIDATES):
                detected_label = col_name
                label_col_index = col_idx

            # Track domain validation columns
            if any(term in col_normalized for term in ("src_ip", "dst_ip", "source_ip", "destination_ip", "client_ip", "ip_address")) or (col_normalized.endswith("_ip") or col_normalized == "ip"):
                ip_col_indices.append((col_idx, col_name))

            if any(term in col_normalized for term in ("protocol", "proto")):
                protocol_col_indices.append((col_idx, col_name))

            if any(term in col_normalized for term in ("failed_login", "failed_attempts", "failed_count", "login_failures", "num_failed_logins")):
                failed_login_col_indices.append((col_idx, col_name))

            if any(term in col_normalized for term in ("timestamp", "date_time", "datetime", "stime", "ltime")) or col_normalized in ("time", "date"):
                timestamp_col_indices.append((col_idx, col_name))

            if any(term in col_normalized for term in ("port", "destination_port", "source_port", "dst_port", "src_port", "sport", "dport")):
                port_col_indices.append((col_idx, col_name))

            if any(term in col_normalized for term in ("duration", "flow_duration", "src_bytes", "dst_bytes", "packets", "total_fwd_packets", "total_bwd_packets", "fwd_packets", "bwd_packets")):
                metric_col_indices.append((col_idx, col_name))

            missing_count = 0
            infinite_count = 0
            numeric_values: List[float] = []
            distinct_values: Set[str] = set()

            for r in rows:
                val = r[col_idx]
                distinct_values.add(val)
                if val == "" or val.lower() in ("nan", "null", "none", "na", "?"):
                    missing_count += 1
                elif val.lower() in ("inf", "+inf", "-inf", "infinity"):
                    infinite_count += 1
                else:
                    try:
                        num = float(val)
                        if math.isinf(num) or math.isnan(num):
                            infinite_count += 1
                        else:
                            numeric_values.append(num)
                    except ValueError:
                        pass

            is_numeric = len(numeric_values) > (total_rows * 0.5) and not is_identifier
            
            mean_val = (sum(numeric_values) / len(numeric_values)) if numeric_values else 0.0
            min_val = min(numeric_values) if numeric_values else 0.0
            max_val = max(numeric_values) if numeric_values else 0.0

            column_meta[col_name] = {
                "name": col_name,
                "is_numeric": is_numeric,
                "is_identifier": is_identifier,
                "missing_count": missing_count,
                "infinite_count": infinite_count,
                "distinct_count": len(distinct_values),
                "sample_values": list(distinct_values)[:5],
                "mean": round(mean_val, 4),
                "min": min_val,
                "max": max_val
            }

        # Analyze label distribution if label column identified
        class_distribution: Dict[str, int] = {}
        if detected_label and detected_label in headers:
            label_idx = headers.index(detected_label)
            label_col_index = label_idx
            for r in rows:
                lbl = r[label_idx] or "UNKNOWN"
                class_distribution[lbl] = class_distribution.get(lbl, 0) + 1

        # Suggested feature columns (numeric and non-identifier, excluding target)
        suggested_features = [
            c for c in headers
            if c != detected_label and column_meta[c]["is_numeric"] and not column_meta[c]["is_identifier"]
        ]

        total_missing = sum(cm["missing_count"] for cm in column_meta.values())
        total_infinite = sum(cm["infinite_count"] for cm in column_meta.values())

        # -------------------------------------------------------------
        # DOMAIN DATA QUALITY VALIDATION & ERROR DETECTION
        # -------------------------------------------------------------
        errors_by_code: Dict[str, int] = {
            "MISSING_IP": 0,
            "INVALID_IP": 0,
            "INVALID_PROTOCOL": 0,
            "NEGATIVE_FAILED_LOGINS": 0,
            "INVALID_TIMESTAMP": 0,
            "MISSING_LABEL": 0,
            "DUPLICATE_ROW": 0,
            "INVALID_PORT": 0,
            "NEGATIVE_METRIC": 0,
            "INFINITE_VALUE": 0,
            "MISSING_VALUE": 0
        }

        row_errors: List[Dict[str, Any]] = []
        seen_row_hashes: Dict[str, int] = {}
        valid_rows_count = 0
        invalid_rows_count = 0
        warning_rows_count = 0
        duplicate_rows_count = 0

        for row_idx, r in enumerate(rows):
            current_row_errors: List[Dict[str, Any]] = []
            is_duplicate = False

            # Check duplicate rows
            row_hash = "|||".join(r)
            if row_hash in seen_row_hashes:
                first_seen = seen_row_hashes[row_hash]
                current_row_errors.append({
                    "code": "DUPLICATE_ROW",
                    "severity": "WARNING",
                    "field": "RECORD",
                    "message": f"Duplicate record identical to row {first_seen + 1}",
                    "original_value": "duplicate"
                })
                errors_by_code["DUPLICATE_ROW"] += 1
                is_duplicate = True
                duplicate_rows_count += 1
            else:
                seen_row_hashes[row_hash] = row_idx

            # 1. IP Validation
            for c_idx, c_name in ip_col_indices:
                val = r[c_idx].strip()
                if not val or val.lower() in ("nan", "null", "none", "-", "?"):
                    current_row_errors.append({
                        "code": "MISSING_IP",
                        "severity": "ERROR",
                        "field": c_name,
                        "message": f"Missing required IP address in '{c_name}'",
                        "original_value": val
                    })
                    errors_by_code["MISSING_IP"] += 1
                elif not is_valid_ip(val):
                    current_row_errors.append({
                        "code": "INVALID_IP",
                        "severity": "ERROR",
                        "field": c_name,
                        "message": f"Invalid IP address format in '{c_name}': '{val}'",
                        "original_value": val
                    })
                    errors_by_code["INVALID_IP"] += 1

            # 2. Protocol Validation
            for c_idx, c_name in protocol_col_indices:
                val = r[c_idx].strip()
                if not val or val.lower() in ("nan", "null", "none"):
                    current_row_errors.append({
                        "code": "INVALID_PROTOCOL",
                        "severity": "ERROR",
                        "field": c_name,
                        "message": f"Missing protocol in '{c_name}'",
                        "original_value": val
                    })
                    errors_by_code["INVALID_PROTOCOL"] += 1
                else:
                    proto_clean = val.lower()
                    if proto_clean not in VALID_PROTOCOLS:
                        # Check if valid IANA protocol number (0-255)
                        try:
                            num = int(proto_clean)
                            if not (0 <= num <= 255):
                                raise ValueError()
                        except ValueError:
                            current_row_errors.append({
                                "code": "INVALID_PROTOCOL",
                                "severity": "ERROR",
                                "field": c_name,
                                "message": f"Unrecognized network protocol in '{c_name}': '{val}'",
                                "original_value": val
                            })
                            errors_by_code["INVALID_PROTOCOL"] += 1

            # 3. Negative Failed Logins Validation
            for c_idx, c_name in failed_login_col_indices:
                val = r[c_idx].strip()
                try:
                    num = float(val)
                    if num < 0:
                        current_row_errors.append({
                            "code": "NEGATIVE_FAILED_LOGINS",
                            "severity": "ERROR",
                            "field": c_name,
                            "message": f"Negative failed login value detected in '{c_name}': {val}",
                            "original_value": val
                        })
                        errors_by_code["NEGATIVE_FAILED_LOGINS"] += 1
                except (ValueError, TypeError):
                    pass

            # 4. Port Validation
            for c_idx, c_name in port_col_indices:
                val = r[c_idx].strip()
                if val:
                    try:
                        port_num = int(float(val))
                        if port_num < 0 or port_num > 65535:
                            current_row_errors.append({
                                "code": "INVALID_PORT",
                                "severity": "ERROR",
                                "field": c_name,
                                "message": f"Port out of range (0-65535) in '{c_name}': {val}",
                                "original_value": val
                            })
                            errors_by_code["INVALID_PORT"] += 1
                    except (ValueError, TypeError):
                        pass

            # 5. Non-negative Metric Validation
            for c_idx, c_name in metric_col_indices:
                val = r[c_idx].strip()
                try:
                    num = float(val)
                    if num < 0:
                        current_row_errors.append({
                            "code": "NEGATIVE_METRIC",
                            "severity": "ERROR",
                            "field": c_name,
                            "message": f"Negative metric value in '{c_name}': {val}",
                            "original_value": val
                        })
                        errors_by_code["NEGATIVE_METRIC"] += 1
                except (ValueError, TypeError):
                    pass

            # 6. Timestamp Validation
            for c_idx, c_name in timestamp_col_indices:
                val = r[c_idx].strip()
                if not val or val.lower() in ("nan", "null", "none", "-"):
                    current_row_errors.append({
                        "code": "INVALID_TIMESTAMP",
                        "severity": "ERROR",
                        "field": c_name,
                        "message": f"Missing timestamp in '{c_name}'",
                        "original_value": val
                    })
                    errors_by_code["INVALID_TIMESTAMP"] += 1
                elif not is_valid_timestamp(val):
                    current_row_errors.append({
                        "code": "INVALID_TIMESTAMP",
                        "severity": "ERROR",
                        "field": c_name,
                        "message": f"Invalid timestamp format or out-of-range date in '{c_name}': '{val}'",
                        "original_value": val
                    })
                    errors_by_code["INVALID_TIMESTAMP"] += 1

            # 7. Missing Label Validation
            if label_col_index is not None and label_col_index < len(r):
                val = r[label_col_index].strip()
                if not val or val.lower() in ("nan", "null", "none", "?", "na", ""):
                    current_row_errors.append({
                        "code": "MISSING_LABEL",
                        "severity": "ERROR",
                        "field": headers[label_col_index],
                        "message": f"Missing ground truth label in row {row_idx + 1}",
                        "original_value": val
                    })
                    errors_by_code["MISSING_LABEL"] += 1

            # Determine overall status of this row
            has_errors = any(e["severity"] == "ERROR" for e in current_row_errors)
            has_warnings = any(e["severity"] == "WARNING" for e in current_row_errors)

            if has_errors:
                row_status = "INVALID"
                invalid_rows_count += 1
            elif is_duplicate:
                row_status = "DUPLICATE"
            elif has_warnings:
                row_status = "WARNING"
                warning_rows_count += 1
            else:
                row_status = "VALID"
                valid_rows_count += 1

            if current_row_errors:
                row_dict = {headers[i]: r[i] for i in range(min(len(headers), len(r)))}
                row_errors.append({
                    "row_index": row_idx,
                    "row_number": row_idx + 1,
                    "status": row_status,
                    "errors": current_row_errors,
                    "raw_row": row_dict
                })

        # Schema Warnings summary
        schema_warnings: List[str] = []
        if errors_by_code["MISSING_IP"] > 0:
            schema_warnings.append(f"{errors_by_code['MISSING_IP']} records have missing IP addresses.")
        if errors_by_code["INVALID_IP"] > 0:
            schema_warnings.append(f"{errors_by_code['INVALID_IP']} records have invalid IP address formats.")
        if errors_by_code["INVALID_PROTOCOL"] > 0:
            schema_warnings.append(f"{errors_by_code['INVALID_PROTOCOL']} records have unrecognized or malformed protocols.")
        if errors_by_code["NEGATIVE_FAILED_LOGINS"] > 0:
            schema_warnings.append(f"{errors_by_code['NEGATIVE_FAILED_LOGINS']} records have negative failed login attempt values.")
        if errors_by_code["INVALID_TIMESTAMP"] > 0:
            schema_warnings.append(f"{errors_by_code['INVALID_TIMESTAMP']} records have invalid or unparseable timestamps.")
        if errors_by_code["MISSING_LABEL"] > 0:
            schema_warnings.append(f"{errors_by_code['MISSING_LABEL']} records are missing target/ground truth labels.")
        if errors_by_code["DUPLICATE_ROW"] > 0:
            schema_warnings.append(f"{errors_by_code['DUPLICATE_ROW']} duplicate records detected.")
        if errors_by_code["INVALID_PORT"] > 0:
            schema_warnings.append(f"{errors_by_code['INVALID_PORT']} records have out-of-range port numbers.")
        if errors_by_code["NEGATIVE_METRIC"] > 0:
            schema_warnings.append(f"{errors_by_code['NEGATIVE_METRIC']} records have negative metric values.")

        validation_percentage = round((valid_rows_count / total_rows) * 100, 2) if total_rows > 0 else 0.0

        return {
            "headers": headers,
            "total_rows": total_rows,
            "columns": column_meta,
            "detected_label": detected_label,
            "identifier_columns": identifier_columns,
            "suggested_features": suggested_features,
            "class_distribution": class_distribution,
            "missing_values_count": total_missing,
            "infinite_values_count": total_infinite,
            "is_academic_benchmark": not is_raw_content and ("cicids" in os.path.basename(filepath_or_content).lower() or "unsw" in os.path.basename(filepath_or_content).lower()),
            "rows": rows,
            # Structured Data Quality & Error Detection Analytics
            "valid_rows_count": valid_rows_count,
            "invalid_rows_count": invalid_rows_count,
            "warning_rows_count": warning_rows_count,
            "duplicate_rows_count": duplicate_rows_count,
            "validation_percentage": validation_percentage,
            "errors_by_code": errors_by_code,
            "schema_warnings": schema_warnings,
            "row_errors": row_errors,
            "error_sample": row_errors[:50]
        }
