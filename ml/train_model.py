"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Model Training Engine (Random Forest & Isolation Forest)
"""

import os
import sys
import json
import time
from datetime import datetime

def train_random_forest(
    dataset_path: str,
    label_column: str = "Label",
    selected_features: list = None,
    excluded_identifiers: list = None,
    test_size: float = 0.2,
    random_state: int = 42,
    n_estimators: int = 200,
    max_depth: int = None,
    min_samples_split: int = 2,
    min_samples_leaf: int = 1,
    class_weight: str = "balanced"
):
    """
    Train an authentic Random Forest Classifier on the specified dataset.
    """
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    from dataset_loader import load_dataset
    from feature_engineering import select_training_features
    from preprocessing import clean_and_split_data
    from evaluate import evaluate_classifier

    start_time = time.time()

    # 1. Load dataset
    df = load_dataset(dataset_path)

    if label_column not in df.columns:
        raise ValueError(f"Target column '{label_column}' not found in dataset columns.")

    # 2. Select features & isolate identifiers
    if not selected_features:
        feature_cols, auto_excluded = select_training_features(df, label_column, excluded_identifiers)
    else:
        feature_cols = [c for c in selected_features if c != label_column]
        auto_excluded = excluded_identifiers or []

    # 3. Leakage-free preprocessing and splitting
    X_train, X_test, y_train, y_test, preprocessor = clean_and_split_data(
        df,
        feature_cols,
        label_column,
        test_size=test_size,
        random_state=random_state
    )

    # 4. Instantiate & Train Random Forest
    cw = class_weight if class_weight != 'none' else None
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=min_samples_leaf,
        class_weight=cw,
        random_state=random_state,
        n_jobs=-1
    )

    rf.fit(X_train, y_train)

    # 5. Evaluate on held-out test data
    eval_metrics = evaluate_classifier(rf, X_test, y_test, preprocessor, feature_cols)
    eval_metrics["evaluatedAt"] = datetime.utcnow().isoformat()

    duration = time.time() - start_time
    model_id = f"RF-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    # 6. Save model artifacts
    artifact_dir = os.path.join(os.path.dirname(__file__), "artifacts", model_id)
    os.makedirs(artifact_dir, exist_ok=True)

    joblib.dump(rf, os.path.join(artifact_dir, "model.joblib"))
    joblib.dump(preprocessor, os.path.join(artifact_dir, "preprocessor.joblib"))

    metadata = {
        "modelId": model_id,
        "modelType": "RANDOM_FOREST",
        "modelVersion": "rf-cyber-v1.0",
        "datasetName": os.path.basename(dataset_path),
        "datasetIdentifier": os.path.basename(dataset_path),
        "datasetRowCount": len(df),
        "featureCount": len(feature_cols),
        "selectedFeatures": feature_cols,
        "excludedFeatures": auto_excluded,
        "labelColumn": label_column,
        "classLabels": list(preprocessor["label_encoder"].classes_),
        "trainRows": len(X_train),
        "testRows": len(X_test),
        "splitRatio": float(1.0 - test_size),
        "randomSeed": random_state,
        "hyperparameters": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_split": min_samples_split,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": class_weight,
            "random_state": random_state
        },
        "trainingTimestamp": datetime.utcnow().isoformat(),
        "trainingDurationSeconds": round(duration, 2),
        "evaluationMetrics": eval_metrics,
        "preprocessingVersion": "leakage-free-v1",
        "modelStatus": "TRAINED"
    }

    with open(os.path.join(artifact_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata

def train_isolation_forest(
    dataset_path: str,
    selected_features: list = None,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42
):
    """
    Train an authentic Isolation Forest Anomaly Detector.
    """
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    import joblib

    from dataset_loader import load_dataset
    from feature_engineering import identify_raw_identifiers

    start_time = time.time()
    df = load_dataset(dataset_path)

    # Exclude identifiers
    excluded = identify_raw_identifiers(df.columns)
    feature_cols = [c for c in df.columns if c not in excluded]
    if selected_features:
        feature_cols = [c for c in selected_features if c in feature_cols]

    X = df[feature_cols].copy()
    numeric_cols = X.select_dtypes(include=['number']).columns.tolist()

    imputer = SimpleImputer(strategy='median')
    scaler = StandardScaler()

    X_num = imputer.fit_transform(X[numeric_cols])
    X_scaled = scaler.fit_transform(X_num)

    iso_forest = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    iso_forest.fit(X_scaled)

    duration = time.time() - start_time
    model_id = f"IF-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    artifact_dir = os.path.join(os.path.dirname(__file__), "artifacts", model_id)
    os.makedirs(artifact_dir, exist_ok=True)

    joblib.dump(iso_forest, os.path.join(artifact_dir, "model.joblib"))
    joblib.dump({"imputer": imputer, "scaler": scaler, "numeric_cols": numeric_cols}, os.path.join(artifact_dir, "preprocessor.joblib"))

    metadata = {
        "modelId": model_id,
        "modelType": "ISOLATION_FOREST",
        "modelVersion": "if-cyber-anomaly-v1.0",
        "datasetName": os.path.basename(dataset_path),
        "datasetIdentifier": os.path.basename(dataset_path),
        "datasetRowCount": len(df),
        "featureCount": len(numeric_cols),
        "selectedFeatures": numeric_cols,
        "excludedFeatures": excluded,
        "labelColumn": "ANOMALY_DETECTION",
        "classLabels": ["BENIGN", "ANOMALY"],
        "trainRows": len(X),
        "testRows": 0,
        "splitRatio": 1.0,
        "randomSeed": random_state,
        "hyperparameters": {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state
        },
        "trainingTimestamp": datetime.utcnow().isoformat(),
        "trainingDurationSeconds": round(duration, 2),
        "evaluationMetrics": None,
        "preprocessingVersion": "leakage-free-v1",
        "modelStatus": "TRAINED"
    }

    with open(os.path.join(artifact_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python train_model.py <dataset_csv_path> [label_column]")
        sys.exit(1)
    csv_path = sys.argv[1]
    label_col = sys.argv[2] if len(sys.argv) > 2 else "Label"
    try:
        res = train_random_forest(csv_path, label_col)
        print(json.dumps(res, indent=2))
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
