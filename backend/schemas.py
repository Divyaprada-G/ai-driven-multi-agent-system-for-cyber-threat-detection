"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Pydantic Schemas for Local Prediction API & Live Security Pipeline
Prompt 12 — 100% Free / Local / No Paid External API
"""

from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "Cyber Threat Detection ML Backend"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "1.0.0"
    offlineFirst: bool = True
    paidApisUsed: bool = False

class SystemStatusResponse(BaseModel):
    api: str = "ONLINE"
    mlEngine: str = "ONLINE"
    randomForest: str = "NOT_TRAINED"
    isolationForest: str = "NOT_TRAINED"
    eventPipeline: str = "STOPPED"
    datasetService: str = "READY"
    alertService: str = "READY"
    incidentService: str = "READY"
    activeModelId: Optional[str] = None
    activeModelType: Optional[str] = None
    loadedArtifactsCount: int = 0
    paidApiRequired: bool = False
    details: Dict[str, Any] = {}

class ModelMetadataResponse(BaseModel):
    modelId: str
    modelType: str
    modelVersion: str
    datasetName: str
    featureCount: int
    selectedFeatures: List[str]
    labelColumn: str
    classLabels: List[str]
    trainingTimestamp: str
    modelStatus: str
    evaluationMetrics: Optional[Dict[str, Any]] = None

class PredictionRequest(BaseModel):
    modelId: Optional[str] = None
    features: Dict[str, Any] = Field(..., description="Key-value pairs matching trained model schema")
    rawIdentifierMeta: Optional[Dict[str, Any]] = Field(default=None, description="Metadata excluded from ML features (IP, flowId, etc)")

class FeatureImpact(BaseModel):
    feature: str
    value: Any
    impact: str

class PredictionResponse(BaseModel):
    predictionId: str
    timestamp: str
    modelId: str
    modelVersion: str
    modelStatus: str
    predictedClass: str
    rawClass: Optional[str] = None
    confidence: float
    confidenceDisclaimer: str = "This probability represents the model's predicted class probability and should not be interpreted as absolute certainty."
    classProbabilities: Dict[str, float] = {}
    anomalyScore: Optional[float] = None
    anomalyLabel: Optional[str] = None
    featureSummary: Dict[str, Any] = {}
    importantContributingFeatures: List[FeatureImpact] = []
    explanation: str
    status: str = "COMPLETED"

class BatchPredictionRequest(BaseModel):
    modelId: Optional[str] = None
    records: List[Dict[str, Any]] = Field(..., description="List of feature records")
    batchSize: Optional[int] = 50

class BatchPredictionResponse(BaseModel):
    totalRequested: int
    processed: int
    successful: int
    failed: int
    processingTimeMs: float
    predictions: List[PredictionResponse] = []
    errors: List[Dict[str, Any]] = []

class SecurityEventPayload(BaseModel):
    eventId: Optional[str] = None
    timestamp: Optional[str] = None
    source: str = Field(..., description="'network', 'system', or 'application'")
    eventType: str = Field(..., description="Specific event indicator type")
    sourceIp: Optional[str] = "192.168.1.100"
    destinationIp: Optional[str] = "10.0.0.1"
    sourcePort: Optional[int] = 44321
    destinationPort: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    features: Dict[str, Any] = Field(default_factory=dict, description="Numerical & categorical features for agent & ML evaluation")
    isSimulated: bool = Field(default=True, description="Always marked true for test simulator events")
    details: Optional[str] = None

class SecurityEventResponse(BaseModel):
    eventId: str
    receivedAt: str
    status: str = "QUEUED" # QUEUED, PROCESSING, COMPLETED, FAILED
    agentId: str
    agentType: str
    findingId: Optional[str] = None
    correlationId: Optional[str] = None
    threatDetectionId: Optional[str] = None
    riskAssessmentId: Optional[str] = None
    alertId: Optional[str] = None
    incidentId: Optional[str] = None
    predictedClass: Optional[str] = None
    confidence: Optional[float] = None
    riskScore: Optional[float] = None
    severity: Optional[str] = None
    latencyMs: float = 0.0
    isSimulated: bool = True
    safeRecommendedAction: Optional[str] = None

class PipelineStatusResponse(BaseModel):
    status: str = "STOPPED" # RUNNING, STOPPED
    queueLength: int = 0
    eventsReceived: int = 0
    eventsProcessed: int = 0
    eventsFailed: int = 0
    threatsDetected: int = 0
    alertsGenerated: int = 0
    incidentsCreated: int = 0
    averageLatencyMs: float = 0.0
    minLatencyMs: float = 0.0
    maxLatencyMs: float = 0.0
    eventsPerSecond: float = 0.0
    lastEventProcessedAt: Optional[str] = None

class SimulatorControlRequest(BaseModel):
    eventRate: int = Field(default=2, description="Events per second: 1, 2, 5, or 10")
    mode: str = Field(default="mixed", description="'mixed', 'normal', 'suspicious', 'multistage'")

class IntegrationEventPlaceholder(BaseModel):
    status: str = "RESERVED"
    message: str = "Reserved for future n8n workflow integration. Not active in Prompt 12."
    receivedData: Dict[str, Any] = {}
