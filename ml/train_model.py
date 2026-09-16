"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Model Training Engine (Random Forest & Isolation Forest)
"""

import os
import sys
import json
import time
from datetime import datetime

"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Model Training Engine (Random Forest & Isolation Forest)
Phase 1: Real Machine-Learning Inference Pipeline
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Any

# Ensure local ml directory is in python search path
ML_DIR = os.path.dirname(os.path.abspath(__file__))
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from dataset_loader import load_dataset
from feature_engineering import select_training_features, identify_raw_identifiers
from preprocessing import clean_and_split_data
from evaluate import evaluate_classifier

ARTIFACTS_DIR = os.path.join(ML_DIR, "artifacts")

def is_test_dataset(dataset_path: str, row_count: int) -> bool:
    """Identifies whether dataset is a small development/test dataset rather than full production dataset."""
    base = os.path.basename(dataset_path).lower()
    return "test" in base or "sample" in base or row_count < 1000

def train_random_forest(
    dataset_path: str,
    label_column: str = "Label",
    selected_features: list = None,
    excluded_identifiers: list = None,
    test_size: float = 0.25,
    random_state: int = 42,
    n_estimators: int = 100,
    max_depth: int = None,
    min_samples_split: int = 2,
    min_samples_leaf: int = 1,
    class_weight: str = "balanced",
    output_dir: str = None
) -> Dict[str, Any]:
    """
    Train an authentic Random Forest Classifier on a verified dataset.
    Validates dataset, handles preprocessing, trains scikit-learn model,
    evaluates on held-out test data, and persists real joblib artifacts and metadata.
    """
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    start_time = time.time()

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Dataset file '{dataset_path}' does not exist. "
            "Please provide a valid path to a CSV dataset or use 'data/test_dataset_cicids2017.csv' for test validation."
        )

    # 1. Load and validate dataset
    df = load_dataset(dataset_path)
    if len(df) < 5:
        raise ValueError(f"Dataset has only {len(df)} rows; minimum 5 rows required for training.")

    if label_column not in df.columns:
        raise ValueError(
            f"Target label column '{label_column}' not found in dataset columns: {list(df.columns)}"
        )

    row_count = len(df)
    test_data_flag = is_test_dataset(dataset_path, row_count)
    training_status = "TEST_DATA_TRAINED" if test_data_flag else "PRODUCTION_TRAINED"

    # 2. Select features & isolate identifiers
    if not selected_features:
        feature_cols, auto_excluded = select_training_features(df, label_column, excluded_identifiers)
    else:
        feature_cols = [c for c in selected_features if c != label_column]
        auto_excluded = excluded_identifiers or []

    if not feature_cols:
        raise ValueError("No valid features selected for training after excluding identifiers.")

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
    eval_metrics["evaluatedAt"] = datetime.utcnow().isoformat() + "Z"

    duration = time.time() - start_time
    timestamp_str = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    model_id = f"RF-{timestamp_str}"
    version = f"rf-cyber-{datetime.utcnow().strftime('%Y%m%d')}"

    # Target directories
    base_art_dir = output_dir or ARTIFACTS_DIR
    model_specific_dir = os.path.join(base_art_dir, model_id)
    os.makedirs(model_specific_dir, exist_ok=True)
    os.makedirs(base_art_dir, exist_ok=True)

    classes_list = [str(c) for c in preprocessor["label_encoder"].classes_]

    # Model metadata conforming to Section 3 requirements + existing frontend schema
    metadata = {
        # Standardized Versioning Fields
        "model_id": model_id,
        "model_version": version,
        "training_dataset": os.path.basename(dataset_path),
        "training_timestamp": datetime.utcnow().isoformat() + "Z",
        "feature_schema_version": "cicids2017-v1",
        "algorithm": "RandomForestClassifier",
        "training_metrics": {
            "accuracy": eval_metrics.get("accuracy"),
            "precision": eval_metrics.get("weightedPrecision"),
            "recall": eval_metrics.get("weightedRecall"),
            "f1_score": eval_metrics.get("weightedF1")
        },
        "model_type": "RANDOM_FOREST",
        "version": version,
        "dataset_name": os.path.basename(dataset_path),
        "feature_names": feature_cols,
        "target_column": label_column,
        "training_sample_count": len(X_train),
        "test_sample_count": len(X_test),
        "classes": classes_list,
        "accuracy": eval_metrics.get("accuracy"),
        "precision": eval_metrics.get("weightedPrecision"),
        "recall": eval_metrics.get("weightedRecall"),
        "f1_score": eval_metrics.get("weightedF1"),
        "confusion_matrix": eval_metrics.get("confusionMatrix"),
        "training_status": training_status,

        # Frontend Backward Compatibility Fields
        "modelId": model_id,
        "modelType": "RANDOM_FOREST",
        "modelVersion": version,
        "datasetName": os.path.basename(dataset_path),
        "datasetIdentifier": os.path.basename(dataset_path),
        "datasetRowCount": row_count,
        "featureCount": len(feature_cols),
        "selectedFeatures": feature_cols,
        "excludedFeatures": auto_excluded,
        "labelColumn": label_column,
        "classLabels": classes_list,
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
        "trainingTimestamp": datetime.utcnow().isoformat() + "Z",
        "trainingDurationSeconds": round(duration, 2),
        "evaluationMetrics": eval_metrics,
        "preprocessingVersion": "leakage-free-v1",
        "modelStatus": "TRAINED" if training_status == "PRODUCTION_TRAINED" else "TEST_DATA_TRAINED",
        "isTestData": test_data_flag,
        "notes": (
            "Authentic Random Forest trained on test dataset for verification."
            if test_data_flag
            else f"Production model trained on {os.path.basename(dataset_path)}."
        )
    }

    feature_schema = {
        "model_id": model_id,
        "model_type": "RANDOM_FOREST",
        "feature_names": feature_cols,
        "numeric_cols": preprocessor.get("numeric_cols", []),
        "categorical_cols": preprocessor.get("categorical_cols", []),
        "target_column": label_column,
        "classes": classes_list
    }

    # 6. Save model artifacts in model-specific directory
    joblib.dump(rf, os.path.join(model_specific_dir, "model.joblib"))
    joblib.dump(preprocessor, os.path.join(model_specific_dir, "preprocessor.joblib"))
    with open(os.path.join(model_specific_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)
    with open(os.path.join(model_specific_dir, "feature_schema.json"), "w") as f:
        json.dump(feature_schema, f, indent=2)

    # Also save standard top-level artifacts
    joblib.dump(rf, os.path.join(base_art_dir, "random_forest.joblib"))
    joblib.dump(preprocessor, os.path.join(base_art_dir, "random_forest_preprocessor.joblib"))
    with open(os.path.join(base_art_dir, "feature_schema.json"), "w") as f:
        json.dump(feature_schema, f, indent=2)
    with open(os.path.join(base_art_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return metadata

def train_isolation_forest(
    dataset_path: str,
    selected_features: list = None,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
    output_dir: str = None
) -> Dict[str, Any]:
    """
    Train an authentic Isolation Forest Anomaly Detector.
    Validates dataset, scales numeric features, fits IsolationForest,
    and saves real joblib artifacts and metadata.
    """
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    import joblib

    start_time = time.time()

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Dataset file '{dataset_path}' does not exist. "
            "Please provide a valid path to a CSV dataset or use 'data/test_dataset_cicids2017.csv' for test validation."
        )

    df = load_dataset(dataset_path)
    if len(df) < 5:
        raise ValueError(f"Dataset has only {len(df)} rows; minimum 5 rows required for anomaly training.")

    row_count = len(df)
    test_data_flag = is_test_dataset(dataset_path, row_count)
    training_status = "TEST_DATA_TRAINED" if test_data_flag else "PRODUCTION_TRAINED"

    # Exclude identifiers
    excluded = identify_raw_identifiers(df.columns)
    feature_cols = [c for c in df.columns if c not in excluded and c.lower() != "label"]
    if selected_features:
        feature_cols = [c for c in selected_features if c in feature_cols]

    X = df[feature_cols].copy()
    numeric_cols = X.select_dtypes(include=['number']).columns.tolist()
    if not numeric_cols:
        raise ValueError("No numeric features available for Isolation Forest training.")

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
    timestamp_str = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    model_id = f"IF-{timestamp_str}"
    version = f"if-cyber-{datetime.utcnow().strftime('%Y%m%d')}"

    base_art_dir = output_dir or ARTIFACTS_DIR
    model_specific_dir = os.path.join(base_art_dir, model_id)
    os.makedirs(model_specific_dir, exist_ok=True)
    os.makedirs(base_art_dir, exist_ok=True)

    metadata = {
        # Standardized Versioning Fields
        "model_id": model_id,
        "model_version": version,
        "training_dataset": os.path.basename(dataset_path),
        "training_timestamp": datetime.utcnow().isoformat() + "Z",
        "feature_schema_version": "cicids2017-v1",
        "algorithm": "IsolationForest",
        "training_metrics": {
            "contamination": contamination,
            "n_estimators": n_estimators,
            "sample_count": len(X)
        },
        "model_type": "ISOLATION_FOREST",
        "version": version,
        "dataset_name": os.path.basename(dataset_path),
        "feature_names": numeric_cols,
        "target_column": "ANOMALY_DETECTION",
        "training_sample_count": len(X),
        "test_sample_count": 0,
        "classes": ["BENIGN", "ANOMALY"],
        "accuracy": None,
        "precision": None,
        "recall": None,
        "f1_score": None,
        "confusion_matrix": None,
        "training_status": training_status,

        # Frontend Backward Compatibility Fields
        "modelId": model_id,
        "modelType": "ISOLATION_FOREST",
        "modelVersion": version,
        "datasetName": os.path.basename(dataset_path),
        "datasetIdentifier": os.path.basename(dataset_path),
        "datasetRowCount": row_count,
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
        "trainingTimestamp": datetime.utcnow().isoformat() + "Z",
        "trainingDurationSeconds": round(duration, 2),
        "evaluationMetrics": None,
        "preprocessingVersion": "leakage-free-v1",
        "modelStatus": "TRAINED" if training_status == "PRODUCTION_TRAINED" else "TEST_DATA_TRAINED",
        "isTestData": test_data_flag,
        "notes": (
            "Authentic Isolation Forest trained on test dataset for verification."
            if test_data_flag
            else f"Production anomaly model trained on {os.path.basename(dataset_path)}."
        )
    }

    preprocessor_data = {
        "imputer": imputer,
        "scaler": scaler,
        "numeric_cols": numeric_cols,
        "feature_names": numeric_cols
    }

    feature_schema = {
        "model_id": model_id,
        "model_type": "ISOLATION_FOREST",
        "feature_names": numeric_cols,
        "numeric_cols": numeric_cols,
        "categorical_cols": [],
        "target_column": "ANOMALY_DETECTION",
        "classes": ["BENIGN", "ANOMALY"]
    }

    joblib.dump(iso_forest, os.path.join(model_specific_dir, "model.joblib"))
    joblib.dump(preprocessor_data, os.path.join(model_specific_dir, "preprocessor.joblib"))
    with open(os.path.join(model_specific_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    joblib.dump(iso_forest, os.path.join(base_art_dir, "isolation_forest.joblib"))
    joblib.dump(preprocessor_data, os.path.join(base_art_dir, "isolation_forest_preprocessor.joblib"))

    return metadata

def main():
    parser = argparse.ArgumentParser(description="Train authentic Random Forest and Isolation Forest cyber threat detection models.")
    parser.add_argument("dataset_pos", nargs="?", default=None, help="Dataset CSV path (positional)")
    parser.add_argument("label_pos", nargs="?", default=None, help="Label column name (positional)")
    parser.add_argument("--dataset", "-d", type=str, default=None, help="Path to input CSV dataset")
    parser.add_argument("--label-column", "-l", type=str, default="Label", help="Target classification column name")
    parser.add_argument("--model-type", "-m", type=str, default="both", choices=["random_forest", "isolation_forest", "both"], help="Model type to train")
    parser.add_argument("--test-size", type=float, default=0.25, help="Train/test split ratio (default 0.25)")
    parser.add_argument("--n-estimators", type=int, default=100, help="Number of trees in ensemble")
    parser.add_argument("--contamination", type=float, default=0.05, help="Contamination rate for Isolation Forest")
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory for saved artifacts")

    args = parser.parse_args()

    dataset_path = args.dataset or args.dataset_pos
    label_col = args.label_pos or args.label_column

    if not dataset_path:
        print("ERROR: Dataset path must be specified.", file=sys.stderr)
        print("Usage: python ml/train_model.py --dataset <dataset_csv_path> [--label-column <Label>]", file=sys.stderr)
        sys.exit(1)

    print(f"[CyberML Training] Validating dataset at '{dataset_path}'...")
    if not os.path.exists(dataset_path):
        print(f"ERROR: Dataset file '{dataset_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    results = {}
    try:
        if args.model_type in ["random_forest", "both"]:
            print(f"[CyberML Training] Training Random Forest Classifier on {dataset_path} (Target: '{label_col}')...")
            rf_res = train_random_forest(
                dataset_path=dataset_path,
                label_column=label_col,
                test_size=args.test_size,
                n_estimators=args.n_estimators,
                output_dir=args.output_dir
            )
            results["randomForest"] = rf_res
            print(f"[CyberML Training] Random Forest trained successfully: Model ID={rf_res['model_id']}, Accuracy={rf_res.get('accuracy')}")

        if args.model_type in ["isolation_forest", "both"]:
            print(f"[CyberML Training] Training Isolation Forest Anomaly Detector on {dataset_path}...")
            if_res = train_isolation_forest(
                dataset_path=dataset_path,
                contamination=args.contamination,
                n_estimators=args.n_estimators,
                output_dir=args.output_dir
            )
            results["isolationForest"] = if_res
            print(f"[CyberML Training] Isolation Forest trained successfully: Model ID={if_res['model_id']}")

        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

