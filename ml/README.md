# AI-Driven Multi-Agent Cyber Threat Detection — Machine Learning Engine

This directory houses the Scikit-Learn Python machine learning subsystem for cybersecurity benchmark datasets (CICIDS2017, UNSW-NB15, KDD Cup 99, and custom CSV flow telemetry).

## System Architecture

```
ml/
├── train_model.py        # Random Forest & Isolation Forest training engine
├── predict.py            # Model inference with confidence & probability extraction
├── evaluate.py           # Authentic held-out test evaluation & confusion matrix
├── preprocessing.py      # Leakage-free train/test split & scaler fitting
├── dataset_loader.py     # CSV inspection, missing value & class balance analyzer
├── feature_engineering.py# Identifier isolation (Flow ID, IPs, MAC, Timestamps)
├── model_registry.py     # Joblib model artifact saving/loading
├── schemas.py            # Pydantic data schemas
├── requirements.txt      # Dependency specification
└── artifacts/            # Persisted models (<model_id>/model.joblib, metadata.json)
```

## Local Setup & Training Instructions

To execute real model training locally with Python 3.10+:

```bash
# 1. Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 2. Install required dependencies
pip install -r ml/requirements.txt

# 3. Train Random Forest on CICIDS2017 or custom dataset
python ml/train_model.py data/CICIDS2017.csv Label

# 4. The trained artifact will be saved in ml/artifacts/<MODEL_ID>/
# with model.joblib, preprocessor.joblib, and metadata.json.
```

## Academic Rigor Principles

1. **Strict Data Leakage Prevention**:
   - `train_test_split()` is executed **prior** to any data scaling or imputation.
   - All `SimpleImputer` and `StandardScaler` instances are `.fit()` on training samples only and `.transform()` out-of-sample on test sets.
2. **Identifier Isolation**:
   - Network flow identifiers (Source IP, Destination IP, Flow ID, Timestamps) are strictly isolated from the ML feature matrix and preserved purely for security evidence and agent correlation.
3. **No Fabricated Metrics**:
   - In environments without an active Python scikit-learn backend, the platform explicitly displays **"REAL ML TRAINING BACKEND NOT CONFIGURED"** and **"REAL MODEL TRAINING HAS NOT YET BEEN EXECUTED."**
