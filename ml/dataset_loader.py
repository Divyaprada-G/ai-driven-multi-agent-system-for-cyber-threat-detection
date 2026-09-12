"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Dataset Loader & Inspection Utilities
"""

import os
import json
import numpy as np

def load_dataset(file_path: str):
    """
    Load dataset safely using pandas if available.
    """
    import pandas as pd

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file '{file_path}' not found.")

    # Read CSV
    df = pd.read_csv(file_path)
    # Strip whitespace from column headers
    df.columns = df.columns.str.strip()
    return df

def inspect_dataset_summary(df, label_column: str = None):
    """
    Extract real statistical summary, columns, data types, missing counts,
    and class distribution.
    """
    total_rows = len(df)
    total_cols = len(df.columns)
    
    missing_by_col = df.isnull().sum().to_dict()
    total_missing = sum(missing_by_col.values())
    
    # Detect infinite values
    import numpy as np
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    infinite_count = int(np.isinf(df[numeric_cols]).values.sum()) if numeric_cols else 0
    
    duplicate_rows = int(df.duplicated().sum())

    class_dist = {}
    if label_column and label_column in df.columns:
        class_dist = df[label_column].value_counts().to_dict()

    return {
        "rows": total_rows,
        "columns": total_cols,
        "total_missing": total_missing,
        "infinite_values": infinite_count,
        "duplicate_rows": duplicate_rows,
        "class_distribution": class_dist,
        "column_names": list(df.columns)
    }
