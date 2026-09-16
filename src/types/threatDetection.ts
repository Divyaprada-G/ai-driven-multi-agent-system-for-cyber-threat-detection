import { SeverityLevel, AgentType } from './index';

/**
 * Stage 7 Threat Classes
 * Academic classification hierarchy representing cyber threats.
 * Includes UNKNOWN for cases where evidence is insufficient.
 */
export type ThreatClass =
  | 'BENIGN'
  | 'SUSPICIOUS'
  | 'NETWORK_THREAT'
  | 'AUTHENTICATION_THREAT'
  | 'PRIVILEGE_ESCALATION'
  | 'WEB_THREAT'
  | 'API_THREAT'
  | 'MULTI_STAGE_THREAT'
  | 'ANOMALY'
  | 'UNKNOWN';

/**
 * Model Operational Status
 * Strictly adhered to for academic honesty:
 * - NOT_TRAINED: Code interface ready, but no training weights exist
 * - DEMO: Deterministic evidence-based demo mode active
 * - TRAINED: Trained weights loaded and active
 * - CONNECTED: Connected to external Python/ML inference backend
 */
export type ModelStatus = 'NOT_TRAINED' | 'DEMO' | 'TRAINED' | 'CONNECTED';

/**
 * Detection Model Types supported in Phase-I
 */
export type DetectionModelType =
  | 'RULE_BASED_DEMO'
  | 'RANDOM_FOREST'
  | 'ISOLATION_FOREST';

/**
 * 18-Dimensional Threat Feature Vector extracted from CorrelatedEvent
 * Raw numerical and categorical signals derived strictly from factual telemetry.
 */
export interface ThreatFeatureVector {
  // Volume & Structure
  findingCount: number;
  participatingAgentsCount: number;
  correlationConfidence: number; // 0.0 to 1.0
  correlationStrengthScore: number; // 1 = LOW, 2 = MEDIUM, 3 = HIGH
  eventDurationSeconds: number;

  // Pivot Entities
  uniqueSourceIpsCount: number;
  uniqueDestIpsCount: number;
  affectedHostsCount: number;
  affectedUsersCount: number;
  threatTypesCount: number;

  // Severity Distribution
  suspiciousEventsCount: number;
  highSeverityCount: number;
  criticalSeverityCount: number;

  // Agent Domain Involvement (binary 0 or 1)
  networkInvolvement: number;
  systemInvolvement: number;
  applicationInvolvement: number;

  // Sequence & Temporal Dispersion
  sequenceLength: number;
  timeSpanSeconds: number;
}

/**
 * Preprocessed & Normalized Feature Vector
 * All numerical values scaled between 0.0 and 1.0 with null/missing handling.
 */
export interface NormalizedFeatureVector extends ThreatFeatureVector {
  // Preprocessing metadata
  _preprocessedAt: string;
  _imputedFeatures: string[];
}

/**
 * Explainable AI Breakdown
 * Required for auditable, transparent security detection.
 */
export interface ThreatExplanation {
  whyAnalyzed: string;
  contributingFeatures: { feature: string; value: string | number; impact: 'HIGH' | 'MEDIUM' | 'LOW' }[];
  participatingAgents: AgentType[];
  supportingEvidence: string[];
  recommendedAction: string;
}

/**
 * Threat Detection Result
 * Consumed by analysts and prepared for future Risk Scoring.
 */
export interface ThreatDetectionResult {
  id: string;
  correlationId: string;
  timestamp: string;
  model: string;
  modelType: DetectionModelType;
  modelStatus: ModelStatus;
  classification: ThreatClass;
  threatDetected: boolean;
  confidence: number; // 0.0 to 1.0
  confidenceType: 'MODEL_DERIVED' | 'DEMO_DERIVED' | 'MODEL-DERIVED' | 'DEMO-DERIVED';
  anomalyScore: number; // 0.0 = nominal, 1.0 = highly anomalous
  anomalyScoreLabel: 'DEMO ANOMALY SCORE' | 'ISOLATION_FOREST_SCORE' | 'RANDOM_FOREST_PROBABILITY' | 'MODEL_DERIVED_SCORE';

  features: ThreatFeatureVector;
  normalizedFeatures?: NormalizedFeatureVector;
  evidence: string[];
  severity: SeverityLevel;
  explanation: ThreatExplanation;
  status: 'DETECTED' | 'REVIEWED' | 'ESCALATED' | 'DISMISSED';
  mitreTechniqueId?: string;
  recommendedAction: string;

  // Backward compatibility fields for legacy UI consumers
  threatType?: string;
  category?: string;
  predictedImpact?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CATASTROPHIC';
  baselineDeviation?: number;
}

/**
 * Model Evaluation Metrics
 * Only generated upon real evaluation on labeled datasets. Never fabricated.
 */
export interface ModelEvaluationMetrics {
  evaluated: boolean;
  datasetName?: string;
  sampleCount?: number;
  accuracy?: number; // 0.0 to 1.0
  precision?: number;
  recall?: number;
  f1Score?: number;
  confusionMatrix?: {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
  };
  evaluationDate?: string;
  message?: string;
}

/**
 * Training Dataset Information & Compatibility Schema
 * Designed for standard cybersecurity datasets (CICIDS2017, UNSW-NB15, KDD Cup 99)
 */
export interface TrainingDatasetMeta {
  datasetName: string;
  format: 'CSV' | 'JSON';
  standardType: 'CUSTOM' | 'CICIDS2017' | 'UNSW_NB15' | 'KDDCUP99';
  rowCount: number;
  columnCount: number;
  columns: string[];
  featureColumns: string[];
  targetColumn: string;
  classesFound: string[];
  classDistribution: Record<string, number>;
  missingValuesCount: number;
  uploadedAt: string;
}

/**
 * Model Information Configuration
 */
export interface ModelInfoDetails {
  modelName: string;
  modelType: DetectionModelType;
  modelStatus: ModelStatus;
  algorithm: string;
  version: string;
  featureCount: number;
  trainingStatus: string;
  lastTrainingTime: string | null;
  dataset: string | null;
  evaluationStatus: string;
  isRealModelConnected: boolean;
}
