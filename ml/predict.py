"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Real Model Inference & Explainability Engine
"""

import os
import sys
import json
import numpy as np

def predict_sample(model_id: str, feature_values: dict, raw_identifier_meta: dict = None):
    """
    Run inference on unseen data using saved joblib model artifact & preprocessor.
    Validates required features, handles missing fields safely, and extracts confidence.
    """
    import joblib

    artifact_dir = os.path.join(os.path.dirname(__file__), "artifacts", model_id)
    if not os.path.exists(artifact_dir):
        raise FileNotFoundError(f"Model '{model_id}' artifact directory not found.")

    with open(os.path.join(artifact_dir, "metadata.json"), "r") as f:
        metadata = json.load(f)

    model = joblib.load(os.path.join(artifact_dir, "model.joblib"))
    preprocessor = joblib.load(os.path.join(artifact_dir, "preprocessor.joblib"))

    numeric_cols = preprocessor.get("numeric_cols", [])

    # Validate required columns
    missing_cols = [c for c in numeric_cols if c not in feature_values]
    if missing_cols:
        raise ValueError(f"Prediction cannot be performed because the following trained features are missing: {', '.join(missing_cols)}")

    # Extract numerical feature row
    row_values = []
    for col in numeric_cols:
        val = feature_values.get(col, 0)
        try:
            num = float(val)
        except (ValueError, TypeError):
            num = 0.0
        row_values.append(num)

    X_row = np.array([row_values])

    # Apply saved imputer & scaler
    imputer = preprocessor.get("imputer")
    scaler = preprocessor.get("scaler")
    if imputer:
        X_row = imputer.transform(X_row)
    if scaler:
        X_row = scaler.transform(X_row)

    model_type = metadata.get("modelType", "RANDOM_FOREST")
    predicted_class = "UNKNOWN"
    confidence = 0.0
    probabilities = {}
    anomaly_score = None

    if model_type == "RANDOM_FOREST":
        label_encoder = preprocessor.get("label_encoder")
        classes = list(label_encoder.classes_) if label_encoder else metadata.get("classLabels", [])

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_row)[0]
            max_idx = np.argmax(probs)
            confidence = float(probs[max_idx])
            predicted_class = str(classes[max_idx]) if max_idx < len(classes) else "UNKNOWN"
            for idx, cls_name in enumerate(classes):
                if idx < len(probs):
                    probabilities[str(cls_name)] = float(probs[idx])
        else:
            pred_idx = model.predict(X_row)[0]
            predicted_class = str(classes[pred_idx]) if pred_idx < len(classes) else "UNKNOWN"
            confidence = 1.0

    elif model_type == "ISOLATION_FOREST":
        raw_pred = model.predict(X_row)[0] # -1 for anomaly, 1 for normal
        score = model.score_samples(X_row)[0]
        # Invert score to 0..1 scale where 1 is highly anomalous
        anomaly_score = float(max(0.0, min(1.0, -score)))
        predicted_class = "ANOMALY" if raw_pred == -1 else "BENIGN"
        confidence = anomaly_score if raw_pred == -1 else (1.0 - anomaly_score)

    # Feature contribution impact
    feature_impacts = []
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        for idx, imp in enumerate(importances):
            col_name = numeric_cols[idx] if idx < len(numeric_cols) else f"feature_{idx}"
            impact_level = "HIGH" if imp > 0.15 else ("MEDIUM" if imp > 0.05 else "LOW")
            feature_impacts.append({
                "feature": col_name,
                "value": feature_values.get(col_name),
                "impact": impact_level
            })
        feature_impacts.sort(key=lambda x: 0 if x["impact"] == "HIGH" else (1 if x["impact"] == "MEDIUM" else 2))

    explanation = (
        f"Model classified this record as {predicted_class} based on learned statistical feature distributions. "
        f"Key distinguishing parameters: {', '.join([f['feature'] for f in feature_impacts[:3]])}."
    )

    evidence = {
        "modelId": model_id,
        "modelVersion": metadata.get("modelVersion"),
        "rawIdentifierMeta": raw_identifier_meta or {},
        "evaluatedFeaturesCount": len(numeric_cols),
        "timestamp": metadata.get("trainingTimestamp")
    }

    return {
        "modelId": model_id,
        "modelVersion": metadata.get("modelVersion"),
        "modelStatus": "TRAINED",
        "predictedClass": predicted_class,
        "predictionConfidence": round(confidence, 4),
        "confidenceDisclaimer": "This probability represents the model's predicted class probability and should not be interpreted as absolute certainty.",
        "classProbabilities": probabilities,
        "anomalyScore": anomaly_score,
        "importantContributingFeatures": feature_impacts[:5],
        "explanation": explanation,
        "evidence": evidence
    }
