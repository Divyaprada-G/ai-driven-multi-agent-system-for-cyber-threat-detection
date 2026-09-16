# AI-Driven Cyber Threat Detection: Machine Learning Pipeline Documentation

## 1. Architecture Overview

Phase 1 establishes an end-to-end, production-quality Machine Learning inference architecture replacing all heuristic rules with real trained scikit-learn models:

```
[ Browser / React SPA ]
         │ (HTTP / JSON)
         ▼
[ Node.js Express Gateway :3000 ]  <-- Serves Vite frontend + API proxy
         │ (Internal HTTP)
         ▼
[ Python FastAPI Service :8000 ]
         │
         ├── Model Registry & Service (backend/services/model_service.py)
         └── Artifact Store (ml/artifacts/)
                 ├── random_forest.joblib
                 ├── random_forest_preprocessor.joblib
                 ├── isolation_forest.joblib
                 ├── isolation_forest_preprocessor.joblib
                 └── feature_schema.json
```

---

## 2. Machine Learning Models & Artifacts

### 2.1 Supervised Multi-Class Threat Classifier: Random Forest
- **Algorithm**: `sklearn.ensemble.RandomForestClassifier`
- **Primary Use Case**: Multi-class flow threat classification (BENIGN, DDoS, PortScan, Infiltration, Web Attacks).
- **Features Handled**: Network flow telemetry metrics from benchmark datasets (CICIDS2017), including Flow Duration, Packet Counts, Byte/Packet Rates, Inter-Arrival Times (IAT), and TCP Flag distributions.
- **Explainability**: Dynamic extraction of Gini feature importances to indicate primary contributing telemetry signals.

### 2.2 Unsupervised Anomaly Detector: Isolation Forest
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Primary Use Case**: Zero-day and behavioral anomaly detection on telemetry (UNSW-NB15).
- **Outputs**: Binary outlier decision (-1 for anomaly, 1 for normal) mapped to normalized anomaly scores via `score_samples`.

### 2.3 Artifact Storage Layout
Trained artifacts are stored in `ml/artifacts/`:
- `random_forest.joblib`: Trained Random Forest model instance.
- `random_forest_preprocessor.joblib`: Imputer, StandardScaler, LabelEncoder, and numeric column list.
- `isolation_forest.joblib`: Trained Isolation Forest model instance.
- `isolation_forest_preprocessor.joblib`: Scaler, Imputer, and feature column list.
- `feature_schema.json`: Complete feature definitions, data types, and min/max ranges.
- `model_metadata.json`: Model version, training parameters, timestamps, and validation metrics.
- Subdirectories `ml/artifacts/<MODEL_ID>/`: Version-tagged model archives.

---

## 3. Preprocessing & Leakage-Free Pipeline

1. **Feature Alignment**: Incoming prediction requests provide a dictionary of telemetry features. The service maps these onto the model's fitted numeric column list, substituting median or baseline defaults for missing non-critical metrics.
2. **Missing Value Imputation**: `sklearn.impute.SimpleImputer(strategy='median')`.
3. **Feature Scaling**: `sklearn.preprocessing.StandardScaler()`.
4. **Data Leakage Guarantee**: Preprocessors are fit exclusively on training splits during training (`ml/train_model.py`) and saved as separate joblib objects to guarantee evaluation integrity.

---

## 4. API Endpoints

### 4.1 Health & Engine Readiness
**Endpoint**: `GET /api/ml/health`

Returns the operational status of the ML subsystem:
```json
{
  "status": "ready",
  "framework": "scikit-learn",
  "backendConfigured": true,
  "scikitLearnAvailable": true,
  "pandasAvailable": true,
  "joblibAvailable": true,
  "randomForest": {
    "available": true,
    "modelId": "RF-20260916-105303",
    "version": "rf-cyber-v1.0"
  },
  "isolationForest": {
    "available": true,
    "modelId": "IF-20260916-105303",
    "version": "if-anomaly-v1.0"
  },
  "message": "Real Scikit-Learn ML backend connected and ready."
}
```

### 4.2 Registered Models
**Endpoint**: `GET /api/ml/models`

Returns all active and historical trained model artifacts registered in the artifact store.

### 4.3 Real Model Inference
**Endpoint**: `POST /api/ml/predict`

**Request Body**:
```json
{
  "modelId": "RF-20260916-105303",
  "features": {
    "Flow Duration": 500,
    "Total Fwd Packets": 2,
    "Total Backward Packets": 1,
    "SYN Flag Count": 1,
    "Flow Bytes/s": 4200.5
  },
  "rawIdentifierMeta": {
    "sourceIp": "192.168.1.105",
    "destIp": "10.0.0.1",
    "destPort": 80
  }
}
```

**Response Body**:
```json
{
  "modelId": "RF-20260916-105303",
  "modelType": "RANDOM_FOREST",
  "modelVersion": "rf-cyber-v1.0",
  "predictedClass": "PortScan",
  "confidence": 0.59,
  "classProbabilities": {
    "BENIGN": 0.12,
    "DDoS": 0.29,
    "PortScan": 0.59
  },
  "anomalyScore": null,
  "importantContributingFeatures": [
    { "feature": "SYN Flag Count", "value": 1, "impact": "HIGH" },
    { "feature": "Flow Duration", "value": 500, "impact": "MEDIUM" }
  ],
  "latencyMs": 4.2
}
```

### 4.4 Batch Model Inference
**Endpoint**: `POST /api/ml/predict/batch`

Accepts an array of telemetry records (up to 500 per batch) and returns batch processing statistics and prediction vectors.

---

## 5. Academic Integrity & Error Handling

- **Zero Heuristics**: All hardcoded rule heuristics (such as `synFlags > 50` or `flowDuration < 5000`) have been eliminated. Predictions are exclusively computed by scikit-learn models.
- **Truthful Status**: If model artifacts are missing or unreadable, the system returns `503 Service Unavailable` with `status: "MODEL_NOT_AVAILABLE"` and `code: "MODEL_NOT_READY"`. The frontend displays `MODEL NOT READY` rather than fabricating simulated predictions.
- **Downstream Lineage**: Threat predictions from the real ML pipeline feed directly into the Multi-Agent correlation engine, the 7-factor quantitative risk scoring engine, and the incident response workflow.
