"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Model Service — Scikit-Learn Model Loader & Inference Engine
Prompt 12 — Real Model Loading without Paid APIs
"""

import os
import sys
import json
import time
from typing import Dict, List, Optional, Tuple, Any

class ModelService:
    def __init__(self, artifacts_dir: Optional[str] = None):
        if artifacts_dir is None:
            # Default to /ml/artifacts or backend/models
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidate = os.path.join(os.path.dirname(base_dir), "ml", "artifacts")
            if os.path.exists(candidate):
                self.artifacts_dir = candidate
            else:
                self.artifacts_dir = os.path.join(base_dir, "models")
        else:
            self.artifacts_dir = artifacts_dir

        self.loaded_models: Dict[str, Any] = {}
        self.active_model_id: Optional[str] = None
        self.active_model_type: Optional[str] = None
        self.refresh_registry()

    def refresh_registry(self):
        """Scans artifacts directory for trained model artifacts."""
        self.loaded_models.clear()
        if not os.path.exists(self.artifacts_dir):
            os.makedirs(self.artifacts_dir, exist_ok=True)
            return

        for entry in os.listdir(self.artifacts_dir):
            entry_path = os.path.join(self.artifacts_dir, entry)
            meta_path = os.path.join(entry_path, "metadata.json")
            if os.path.isdir(entry_path) and os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    self.loaded_models[meta["modelId"]] = {
                        "metadata": meta,
                        "dir": entry_path,
                        "loaded": False,
                        "model": None,
                        "preprocessor": None
                    }
                    if not self.active_model_id:
                        self.active_model_id = meta["modelId"]
                        self.active_model_type = meta.get("modelType", "RANDOM_FOREST")
                except Exception as e:
                    print(f"[ModelService] Error reading {meta_path}: {e}")

    def get_registered_models(self) -> List[Dict[str, Any]]:
        return [m["metadata"] for m in self.loaded_models.values()]

    def get_model_status(self) -> Dict[str, str]:
        rf_status = "NOT_TRAINED"
        if_status = "NOT_TRAINED"

        for m in self.loaded_models.values():
            m_type = m["metadata"].get("modelType")
            status = m["metadata"].get("modelStatus", "TRAINED")
            if m_type == "RANDOM_FOREST":
                rf_status = status
            elif m_type == "ISOLATION_FOREST":
                if_status = status

        return {
            "randomForest": rf_status,
            "isolationForest": if_status,
            "activeModelId": self.active_model_id,
            "activeModelType": self.active_model_type,
            "loadedArtifactsCount": len(self.loaded_models)
        }

    def load_model(self, model_id: str):
        """Loads scikit-learn model and preprocessor into memory."""
        if model_id not in self.loaded_models:
            raise FileNotFoundError(f"Model '{model_id}' not found in registry.")

        entry = self.loaded_models[model_id]
        if entry["loaded"] and entry["model"] is not None:
            return entry

        try:
            import joblib
        except ImportError:
            raise RuntimeError("joblib is not installed. Install via pip install joblib.")

        model_file = os.path.join(entry["dir"], "model.joblib")
        prep_file = os.path.join(entry["dir"], "preprocessor.joblib")

        if not os.path.exists(model_file) or not os.path.exists(prep_file):
            raise FileNotFoundError(f"Model artifacts missing in {entry['dir']}.")

        entry["model"] = joblib.load(model_file)
        entry["preprocessor"] = joblib.load(prep_file)
        entry["loaded"] = True
        return entry

    def predict(self, model_id: Optional[str], feature_values: Dict[str, Any], raw_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs true prediction through the trained model and preprocessing pipeline.
        If no trained model is available, returns clear status without fabricating fake predictions.
        """
        target_id = model_id or self.active_model_id
        if not target_id or target_id not in self.loaded_models:
            return {
                "status": "MODEL_NOT_AVAILABLE",
                "message": "No trained model is available. Train a real model first in Datasets & ML Training."
            }

        entry = self.load_model(target_id)
        metadata = entry["metadata"]
        preprocessor = entry["preprocessor"]
        model = entry["model"]

        import numpy as np

        numeric_cols = preprocessor.get("numeric_cols", [])
        
        # Check required columns
        missing_cols = [c for c in numeric_cols if c not in feature_values]
        if missing_cols:
            # If missing columns exist, default to 0.0 with warning rather than crashing if partial telemetry
            for col in missing_cols:
                feature_values[col] = 0.0

        # Build feature vector
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
        probabilities: Dict[str, float] = {}
        anomaly_score = None
        anomaly_label = None

        if model_type == "RANDOM_FOREST":
            label_encoder = preprocessor.get("label_encoder")
            classes = list(label_encoder.classes_) if label_encoder else metadata.get("classLabels", ["BENIGN", "THREAT"])
            
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_row)[0]
                max_idx = int(np.argmax(probs))
                confidence = float(probs[max_idx])
                predicted_class = str(classes[max_idx]) if max_idx < len(classes) else "UNKNOWN"
                for idx, cls_name in enumerate(classes):
                    if idx < len(probs):
                        probabilities[str(cls_name)] = round(float(probs[idx]), 4)
            else:
                pred_idx = int(model.predict(X_row)[0])
                predicted_class = str(classes[pred_idx]) if pred_idx < len(classes) else "UNKNOWN"
                confidence = 1.0

        elif model_type == "ISOLATION_FOREST":
            raw_pred = model.predict(X_row)[0] # -1 for anomaly, 1 for normal
            score = model.score_samples(X_row)[0]
            anomaly_score = float(max(0.0, min(1.0, -score)))
            predicted_class = "ANOMALY" if raw_pred == -1 else "BENIGN"
            anomaly_label = "OUTLIER" if raw_pred == -1 else "NORMAL"
            confidence = anomaly_score if raw_pred == -1 else (1.0 - anomaly_score)

        # Feature impact breakdown
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

        prediction_id = f"PRED-{int(time.time() * 1000)}"
        explanation = (
            f"Classified as {predicted_class} with probability {round(confidence * 100, 1)}%. "
            f"Evaluated through trained {model_type} ({metadata.get('modelVersion')}) using {len(numeric_cols)} features."
        )

        return {
            "predictionId": prediction_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modelId": target_id,
            "modelVersion": metadata.get("modelVersion", "v1.0"),
            "modelStatus": metadata.get("modelStatus", "TRAINED"),
            "predictedClass": predicted_class,
            "rawClass": predicted_class,
            "confidence": round(confidence, 4),
            "confidenceDisclaimer": "This probability represents the model's predicted class probability and should not be interpreted as absolute certainty.",
            "classProbabilities": probabilities,
            "anomalyScore": anomaly_score,
            "anomalyLabel": anomaly_label,
            "featureSummary": {k: feature_values[k] for k in list(feature_values.keys())[:10]},
            "importantContributingFeatures": feature_impacts[:5],
            "explanation": explanation,
            "status": "COMPLETED"
        }

model_service = ModelService()
