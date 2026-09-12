"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
ML Pipeline Pydantic / Typed Schemas
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class TrainingHyperparameters(BaseModel):
    n_estimators: int = Field(default=200, ge=10, le=1000)
    max_depth: Optional[int] = Field(default=None, ge=1, le=100)
    min_samples_split: int = Field(default=2, ge=2)
    min_samples_leaf: int = Field(default=1, ge=1)
    class_weight: str = Field(default="balanced")
    random_state: int = Field(default=42)

class IsolationForestHyperparameters(BaseModel):
    n_estimators: int = Field(default=100, ge=10, le=1000)
    contamination: float = Field(default=0.05, ge=0.001, le=0.5)
    random_state: int = Field(default=42)

class TrainRequest(BaseModel):
    dataset_path: str
    model_type: str = "RANDOM_FOREST"  # RANDOM_FOREST or ISOLATION_FOREST
    label_column: str = "Label"
    selected_features: Optional[List[str]] = None
    excluded_identifiers: Optional[List[str]] = None
    test_size: float = Field(default=0.2, ge=0.05, le=0.5)
    random_state: int = 42
    rf_params: Optional[TrainingHyperparameters] = None
    if_params: Optional[IsolationForestHyperparameters] = None

class PerClassMetrics(BaseModel):
    class_name: str
    precision: float
    recall: float
    f1_score: float
    support: int

class ConfusionMatrixSchema(BaseModel):
    labels: List[str]
    matrix: List[List[int]]

class EvaluationReport(BaseModel):
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    roc_auc: Optional[float] = None
    confusion_matrix: ConfusionMatrixSchema
    classification_report: List[PerClassMetrics]
    feature_importances: List[Dict[str, Any]]
    test_samples_count: int

class ModelMetadata(BaseModel):
    model_id: str
    model_type: str
    model_version: str
    dataset_name: str
    dataset_row_count: int
    feature_count: int
    selected_features: List[str]
    excluded_features: List[str]
    label_column: str
    class_labels: List[str]
    train_rows: int
    test_rows: int
    split_ratio: float
    random_seed: int
    hyperparameters: Dict[str, Any]
    training_timestamp: str
    training_duration_seconds: float
    evaluation_metrics: Optional[EvaluationReport] = None
    model_status: str = "TRAINED"

class PredictionRequest(BaseModel):
    model_id: str
    feature_values: Dict[str, Any]
    raw_identifier_meta: Optional[Dict[str, Any]] = None

class PredictionResponse(BaseModel):
    model_id: str
    model_version: str
    predicted_class: str
    confidence: float
    confidence_disclaimer: str
    class_probabilities: Optional[Dict[str, float]] = None
    anomaly_score: Optional[float] = None
    important_features: List[Dict[str, Any]]
    explanation: str
    evidence: Dict[str, Any]
