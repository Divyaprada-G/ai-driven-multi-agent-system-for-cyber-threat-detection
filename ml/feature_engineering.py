"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Feature Engineering & Identifier Isolation
"""

IDENTIFIER_NAMES = {
    'flow id', 'source ip', 'destination ip', 'srcip', 'dstip',
    'timestamp', 'time', 'date', 'id', 'guid', 'uuid', 'mac'
}

def identify_raw_identifiers(columns):
    """
    Detect columns that represent raw identifiers, IP addresses, or wall-clock timestamps.
    These must NOT be fed blindly into the ML feature matrix to prevent memorization/overfitting.
    """
    excluded = []
    for col in columns:
        col_lower = col.strip().lower()
        if any(ident in col_lower for ident in IDENTIFIER_NAMES):
            excluded.append(col)
    return excluded

def select_training_features(df, target_column: str, user_excluded: list = None):
    """
    Extract model-ready feature columns while strictly isolating raw identifiers
    and the ground-truth target column.
    """
    all_cols = list(df.columns)
    excluded = set(user_excluded or [])
    excluded.add(target_column)

    # Auto-detect additional raw identifiers
    auto_excluded = identify_raw_identifiers(all_cols)
    excluded.update(auto_excluded)

    feature_cols = [c for c in all_cols if c not in excluded]
    return feature_cols, list(excluded)
