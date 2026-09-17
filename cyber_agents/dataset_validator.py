"""
Dataset Validator & Ingestion Module
Handles safe dataset ingestion, schema validation, data type detection,
missing value detection, infinite value handling, and identifier isolation
to prevent data leakage in cybersecurity ML models.
"""
import os
import csv
import math
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


class DatasetValidator:
    """
    Validates and inspects cybersecurity datasets (e.g. CICIDS2017, UNSW-NB15, custom logs).
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
        and isolates network identifier columns from predictive features.
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

        # Analyze columns
        column_meta: Dict[str, Dict[str, Any]] = {}
        detected_label: Optional[str] = None
        identifier_columns: List[str] = []

        for col_idx, col_name in enumerate(headers):
            col_lower = col_name.lower().strip()
            
            # Check if identifier column
            is_identifier = any(pat in col_lower for pat in IDENTIFIER_PATTERNS)
            if is_identifier:
                identifier_columns.append(col_name)

            # Check if label candidate
            if not detected_label and any(cand == col_lower or cand in col_lower for cand in LABEL_CANDIDATES):
                detected_label = col_name

            missing_count = 0
            infinite_count = 0
            numeric_values: List[float] = []
            distinct_values: Set[str] = set()

            for r in rows:
                val = r[col_idx]
                distinct_values.add(val)
                if val == "" or val.lower() in ("nan", "null", "none", "na"):
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
            "rows": rows
        }
