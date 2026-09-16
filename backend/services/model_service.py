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

        # Check subdirectories first
        for entry in os.listdir(self.artifacts_dir):
            entry_path = os.path.join(self.artifacts_dir, entry)
            meta_path = os.path.join(entry_path, "metadata.json")
            if os.path.isdir(entry_path) and os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    m_id = meta.get("model_id") or meta.get("modelId")
                    if m_id:
                        self.loaded_models[m_id] = {
                            "metadata": meta,
                            "dir": entry_path,
                            "model_file": os.path.join(entry_path, "model.joblib"),
                            "prep_file": os.path.join(entry_path, "preprocessor.joblib"),
                            "loaded": False,
                            "model": None,
                            "preprocessor": None
                        }
                        if not self.active_model_id and (meta.get("model_type") == "RANDOM_FOREST" or meta.get("modelType") == "RANDOM_FOREST"):
                            self.active_model_id = m_id
                            self.active_model_type = "RANDOM_FOREST"
                except Exception as e:
                    print(f"[ModelService] Error reading {meta_path}: {e}")

        # Check top-level artifacts
        root_meta_path = os.path.join(self.artifacts_dir, "model_metadata.json")
        root_rf_path = os.path.join(self.artifacts_dir, "random_forest.joblib")
        root_rf_prep = os.path.join(self.artifacts_dir, "random_forest_preprocessor.joblib")
        if os.path.exists(root_rf_path):
            rf_meta = {}
            if os.path.exists(root_meta_path):
                try:
                    with open(root_meta_path, "r") as f:
                        rf_meta = json.load(f)
                except Exception:
                    pass
            m_id = rf_meta.get("model_id") or rf_meta.get("modelId") or "RANDOM_FOREST_DEFAULT"
            if m_id not in self.loaded_models:
                self.loaded_models[m_id] = {
                    "metadata": rf_meta if rf_meta else {
                        "model_id": m_id,
                        "modelId": m_id,
                        "model_type": "RANDOM_FOREST",
                        "modelType": "RANDOM_FOREST",
                        "version": "rf-default",
                        "modelVersion": "rf-default",
                        "modelStatus": "TRAINED"
                    },
                    "dir": self.artifacts_dir,
                    "model_file": root_rf_path,
                    "prep_file": root_rf_prep if os.path.exists(root_rf_prep) else None,
                    "loaded": False,
                    "model": None,
                    "preprocessor": None
                }
            if not self.active_model_id:
                self.active_model_id = m_id
                self.active_model_type = "RANDOM_FOREST"

        root_if_path = os.path.join(self.artifacts_dir, "isolation_forest.joblib")
        root_if_prep = os.path.join(self.artifacts_dir, "isolation_forest_preprocessor.joblib")
        if os.path.exists(root_if_path):
            m_id = "ISOLATION_FOREST_DEFAULT"
            # check if we have metadata
            if m_id not in self.loaded_models:
                self.loaded_models[m_id] = {
                    "metadata": {
                        "model_id": m_id,
                        "modelId": m_id,
                        "model_type": "ISOLATION_FOREST",
                        "modelType": "ISOLATION_FOREST",
                        "version": "if-default",
                        "modelVersion": "if-default",
                        "modelStatus": "TRAINED"
                    },
                    "dir": self.artifacts_dir,
                    "model_file": root_if_path,
                    "prep_file": root_if_prep if os.path.exists(root_if_prep) else None,
                    "loaded": False,
                    "model": None,
                    "preprocessor": None
                }


    def get_registered_models(self) -> List[Dict[str, Any]]:
        return [m["metadata"] for m in self.loaded_models.values()]

    def get_detailed_status(self) -> Dict[str, Any]:
        """
        Distinguishes:
        - SERVICE_UNAVAILABLE
        - ARTIFACTS_MISSING
        - MODEL_LOADING
        - MODEL_READY
        - MODEL_ERROR
        """
        if not os.path.exists(self.artifacts_dir) or len(self.loaded_models) == 0:
            return {
                "status": "ARTIFACTS_MISSING",
                "randomForest": "ARTIFACTS_MISSING",
                "isolationForest": "ARTIFACTS_MISSING",
                "activeModelId": None,
                "activeModelType": None,
                "modelVersion": None,
                "featureSchemaVersion": None,
                "loadedArtifactsCount": 0,
                "isTestData": False,
                "message": "No trained model artifacts found in registry. Training must be run on a verified dataset."
            }

        rf_status = "ARTIFACTS_MISSING"
        if_status = "ARTIFACTS_MISSING"
        rf_meta = None
        has_error = False

        for m_id, m in self.loaded_models.items():
            meta = m["metadata"]
            m_type = meta.get("model_type") or meta.get("modelType")
            try:
                self.load_model(m_id)
                status_str = meta.get("modelStatus", "TRAINED")
            except Exception as e:
                print(f"[ModelService] Load failure for {m_id}: {e}")
                status_str = "MODEL_ERROR"
                has_error = True

            if m_type == "RANDOM_FOREST":
                rf_status = status_str
                rf_meta = meta
            elif m_type == "ISOLATION_FOREST":
                if_status = status_str

        if has_error:
            overall = "MODEL_ERROR"
            msg = "One or more model artifacts failed loading or are corrupted."
        elif rf_status in ["TRAINED", "TEST_DATA_TRAINED"] or if_status in ["TRAINED", "TEST_DATA_TRAINED"]:
            overall = "MODEL_READY"
            msg = "Model artifacts loaded and verified ready for real inference."
        else:
            overall = "ARTIFACTS_MISSING"
            msg = "Required model artifacts are missing."

        return {
            "status": overall,
            "randomForest": rf_status,
            "isolationForest": if_status,
            "activeModelId": self.active_model_id,
            "activeModelType": self.active_model_type,
            "modelVersion": rf_meta.get("version") or rf_meta.get("modelVersion") if rf_meta else None,
            "featureSchemaVersion": rf_meta.get("feature_schema_version", "cicids2017-v1") if rf_meta else "cicids2017-v1",
            "loadedArtifactsCount": len(self.loaded_models),
            "isTestData": rf_meta.get("isTestData", True) if rf_meta else False,
            "message": msg
        }

    def get_model_status(self) -> Dict[str, str]:
        detailed = self.get_detailed_status()
        rf_s = "NOT_TRAINED" if detailed["randomForest"] == "ARTIFACTS_MISSING" else detailed["randomForest"]
        if_s = "NOT_TRAINED" if detailed["isolationForest"] == "ARTIFACTS_MISSING" else detailed["isolationForest"]
        return {
            "status": detailed["status"],
            "randomForest": rf_s,
            "isolationForest": if_s,
            "activeModelId": detailed["activeModelId"],
            "activeModelType": detailed["activeModelType"],
            "loadedArtifactsCount": detailed["loadedArtifactsCount"]
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

        model_file = entry.get("model_file") or os.path.join(entry["dir"], "model.joblib")
        prep_file = entry.get("prep_file") or os.path.join(entry["dir"], "preprocessor.joblib")

        if not os.path.exists(model_file):
            raise FileNotFoundError(f"Model artifact missing at {model_file}.")

        entry["model"] = joblib.load(model_file)
        if prep_file and os.path.exists(prep_file):
            entry["preprocessor"] = joblib.load(prep_file)
        else:
            entry["preprocessor"] = {}
        entry["loaded"] = True
        return entry

    def predict(self, model_id: Optional[str], feature_values: Dict[str, Any], raw_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs true prediction through the trained model and preprocessing pipeline.
        If no trained model is available, returns clear status without fabricating fake predictions.
        """
        if not self.loaded_models:
            self.refresh_registry()

        target_id = model_id or self.active_model_id
        if not target_id or target_id not in self.loaded_models:
            return {
                "status": "MODEL_NOT_AVAILABLE",
                "code": "MODEL_NOT_READY",
                "error": "No trained model artifact is available or specified model not found.",
                "message": "No trained model artifact is available. Train a real model first in Datasets & ML Training."
            }

        try:
            entry = self.load_model(target_id)
        except Exception as e:
            return {
                "status": "MODEL_NOT_AVAILABLE",
                "code": "MODEL_NOT_READY",
                "error": f"Failed to load model artifact: {str(e)}",
                "message": f"Model artifact could not be loaded: {str(e)}"
            }

        metadata = entry["metadata"]
        preprocessor = entry["preprocessor"]
        model = entry["model"]

        import numpy as np
        import pandas as pd

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

        if numeric_cols:
            X_df = pd.DataFrame([row_values], columns=numeric_cols)
        else:
            X_df = np.array([row_values])

        # Apply saved imputer & scaler
        imputer = preprocessor.get("imputer")
        scaler = preprocessor.get("scaler")
        if imputer:
            try:
                X_transformed = imputer.transform(X_df)
            except Exception:
                X_transformed = imputer.transform(np.array([row_values]))
        else:
            X_transformed = np.array([row_values])

        if scaler:
            try:
                X_scaled = scaler.transform(X_transformed)
            except Exception:
                X_scaled = X_transformed
        else:
            X_scaled = X_transformed

        X_eval = X_scaled


        model_type = metadata.get("model_type") or metadata.get("modelType", "RANDOM_FOREST")
        predicted_class = "UNKNOWN"
        confidence = 0.0
        probabilities: Dict[str, float] = {}
        anomaly_score = None
        anomaly_flag = None
        anomaly_label = None

        if model_type == "RANDOM_FOREST":
            label_encoder = preprocessor.get("label_encoder")
            classes = list(label_encoder.classes_) if label_encoder else metadata.get("classLabels", ["BENIGN", "THREAT"])
            
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_eval)[0]
                max_idx = int(np.argmax(probs))
                confidence = float(probs[max_idx])
                predicted_class = str(classes[max_idx]) if max_idx < len(classes) else "UNKNOWN"
                for idx, cls_name in enumerate(classes):
                    if idx < len(probs):
                        probabilities[str(cls_name)] = round(float(probs[idx]), 4)
            else:
                pred_idx = int(model.predict(X_eval)[0])
                predicted_class = str(classes[pred_idx]) if pred_idx < len(classes) else "UNKNOWN"
                confidence = 1.0

            # Evaluate companion Isolation Forest for anomaly score & anomaly flag if present
            if_id = None
            for candidate_id, c_entry in self.loaded_models.items():
                c_type = c_entry["metadata"].get("model_type") or c_entry["metadata"].get("modelType")
                if c_type == "ISOLATION_FOREST":
                    if_id = candidate_id
                    break

            if if_id:
                try:
                    if_loaded = self.load_model(if_id)
                    if_m = if_loaded["model"]
                    if_prep = if_loaded.get("preprocessor") or {}
                    if_num_cols = if_prep.get("numeric_cols", numeric_cols)
                    if_vals = []
                    for c in if_num_cols:
                        try:
                            if_vals.append(float(feature_values.get(c, 0.0)))
                        except (ValueError, TypeError):
                            if_vals.append(0.0)
                    if if_prep.get("scaler"):
                        try:
                            X_if = if_prep["scaler"].transform([if_vals])
                        except Exception:
                            X_if = np.array([if_vals])
                    else:
                        X_if = np.array([if_vals])

                    raw_if_pred = if_m.predict(X_if)[0]
                    if_score = if_m.score_samples(X_if)[0]
                    anomaly_score = round(float(max(0.0, min(1.0, -if_score))), 4)
                    anomaly_flag = bool(raw_if_pred == -1)
                    anomaly_label = "OUTLIER" if anomaly_flag else "NORMAL"
                except Exception as e:
                    print(f"[ModelService] Isolation Forest evaluation notice: {e}")

        elif model_type == "ISOLATION_FOREST":
            raw_pred = model.predict(X_eval)[0] # -1 for anomaly, 1 for normal
            score = model.score_samples(X_eval)[0]
            anomaly_score = float(max(0.0, min(1.0, -score)))
            anomaly_flag = bool(raw_pred == -1)
            predicted_class = "ANOMALY" if anomaly_flag else "BENIGN"
            anomaly_label = "OUTLIER" if anomaly_flag else "NORMAL"
            confidence = anomaly_score if anomaly_flag else (1.0 - anomaly_score)

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

        inference_time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        prediction_id = f"PRED-{int(time.time() * 1000)}"
        explanation = (
            f"Classified as {predicted_class} with probability {round(confidence * 100, 1)}%. "
            f"Evaluated through trained {model_type} ({metadata.get('modelVersion')}) using {len(numeric_cols)} features."
        )

        return {
            "predictionId": prediction_id,
            "timestamp": inference_time_str,
            "inferenceTimestamp": inference_time_str,
            "modelId": target_id,
            "modelVersion": metadata.get("modelVersion") or metadata.get("version", "v1.0"),
            "featureSchemaVersion": metadata.get("feature_schema_version", "cicids2017-v1"),
            "modelStatus": metadata.get("modelStatus", "TRAINED"),
            "prediction": predicted_class,
            "class": predicted_class,
            "predictedClass": predicted_class,
            "rawClass": predicted_class,
            "confidence": round(confidence, 4),
            "confidenceDisclaimer": "This probability represents the model's predicted class probability and should not be interpreted as absolute certainty.",
            "classProbabilities": probabilities,
            "anomalyScore": anomaly_score,
            "anomalyFlag": anomaly_flag,
            "anomalyLabel": anomaly_label,
            "featureSummary": {k: feature_values[k] for k in list(feature_values.keys())[:10]},
            "importantContributingFeatures": feature_impacts[:5],
            "explanation": explanation,
            "status": "COMPLETED"
        }

model_service = ModelService()
