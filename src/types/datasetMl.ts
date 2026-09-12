/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 11: Real Dataset Support, ML Model Training, Validation & Traceability
 */

export type DatasetStandardType = 'CICIDS2017' | 'UNSW_NB15' | 'KDDCUP99' | 'CUSTOM';

export type DatasetFormat = 'CSV' | 'PARQUET' | 'JSON';

export type ColumnDataType = 'numeric' | 'categorical' | 'identifier' | 'timestamp' | 'unknown';

export interface ColumnInspectionMeta {
  name: string;
  dataType: ColumnDataType;
  inferredType: string;
  missingCount: number;
  missingPercentage: number;
  uniqueValuesCount: number;
  isPotentialIdentifier: boolean;
  isPotentialTimestamp: boolean;
  isTargetCandidate: boolean;
  sampleValues: (string | number)[];
  min?: number;
  max?: number;
  mean?: number;
}

export interface DatasetSchema {
  datasetId: string;
  datasetName: string;
  fileName: string;
  standardType: DatasetStandardType;
  rowCount: number;
  columnCount: number;
  columns: ColumnInspectionMeta[];
  labelColumn: string | null;
  labelAutoDetected: boolean;
  classes: string[];
  classDistribution: Record<string, number>;
  numericFeatureCount: number;
  categoricalFeatureCount: number;
  identifierColumns: string[];
  timestampColumns: string[];
  missingValuesTotal: number;
  duplicateRowsCount: number;
  infiniteValuesCount: number;
  rawContentSample?: Record<string, any>[];
  uploadedAt: string;
  fileSizeBytes: number;
}

export interface PreprocessingConfig {
  selectedFeatures: string[];
  excludedIdentifiers: string[];
  handleMissingStrategy: 'mean' | 'median' | 'drop' | 'zero';
  handleDuplicates: boolean;
  handleInfinite: boolean;
  trainSplitRatio: number; // e.g. 0.8 for 80/20
  randomSeed: number; // default 42
  useStratification: boolean;
}

export interface DataLeakageCheckItem {
  id: string;
  name: string;
  passed: boolean;
  severity: 'PASSED' | 'WARNING' | 'VIOLATION';
  details: string;
}

export interface DataLeakageCheckResult {
  trainRows: number;
  testRows: number;
  splitRatio: number;
  randomSeed: number;
  stratifiedApplied: boolean;
  stratificationNote?: string;
  identifierExclusionsCount: number;
  leakageChecksPassed: boolean;
  checks: DataLeakageCheckItem[];
}

export type ModelTrainingStatus =
  | 'IDLE'
  | 'VALIDATING'
  | 'PREPROCESSING'
  | 'SPLITTING'
  | 'TRAINING'
  | 'EVALUATING'
  | 'SAVING'
  | 'COMPLETED'
  | 'FAILED';

export type ModelOperationalStatus =
  | 'NOT_CONFIGURED'
  | 'CONFIGURED'
  | 'TRAINING'
  | 'TRAINED'
  | 'FAILED'
  | 'DEMO_MODEL';

export interface RandomForestHyperparameters {
  n_estimators: number;
  max_depth: number | null;
  min_samples_split: number;
  min_samples_leaf: number;
  class_weight: 'balanced' | 'balanced_subsample' | 'none';
  random_state: number;
}

export interface IsolationForestHyperparameters {
  n_estimators: number;
  contamination: number | 'auto';
  max_samples: number | 'auto';
  random_state: number;
}

export interface ConfusionMatrixData {
  labels: string[];
  matrix: number[][]; // rows: true class, cols: predicted class
  totalSamples: number;
}

export interface PerClassMetric {
  className: string;
  precision: number;
  recall: number;
  f1Score: number;
  support: number;
}

export interface ModelEvaluationResult {
  accuracy: number;
  macroPrecision: number;
  macroRecall: number;
  macroF1: number;
  weightedPrecision: number;
  weightedRecall: number;
  weightedF1: number;
  rocAuc?: number | null;
  rocAucNote?: string;
  confusionMatrix: ConfusionMatrixData;
  classificationReport: PerClassMetric[];
  featureImportances: { feature: string; importance: number; rank: number }[];
  evaluatedOnTestRows: number;
  evaluatedAt: string;
}

export interface TrainedModelArtifact {
  modelId: string;
  modelType: 'RANDOM_FOREST' | 'ISOLATION_FOREST';
  modelVersion: string;
  datasetName: string;
  datasetIdentifier: string;
  datasetRowCount: number;
  featureCount: number;
  selectedFeatures: string[];
  excludedFeatures: string[];
  labelColumn: string;
  classLabels: string[];
  trainRows: number;
  testRows: number;
  splitRatio: number;
  randomSeed: number;
  hyperparameters: Record<string, any>;
  trainingTimestamp: string;
  trainingDurationSeconds: number;
  evaluationMetrics: ModelEvaluationResult | null;
  preprocessingVersion: string;
  modelStatus: ModelOperationalStatus;
  notes?: string;
}

export interface TestPredictionRequest {
  modelId: string;
  featureValues: Record<string, any>;
  rawIdentifierMeta?: {
    flowId?: string;
    sourceIp?: string;
    destIp?: string;
    sourcePort?: number;
    destPort?: number;
    protocol?: string;
    timestamp?: string;
    user?: string;
    host?: string;
  };
}

export interface TestPredictionResult {
  modelId: string;
  modelVersion: string;
  modelStatus: ModelOperationalStatus;
  predictedClass: string;
  normalizedClassification: string;
  classProbabilities?: Record<string, number>;
  predictionConfidence: number; // 0.0 to 1.0
  anomalyScore?: number; // for Isolation Forest
  confidenceDisclaimer: string;
  importantContributingFeatures: { feature: string; value: any; impact: 'HIGH' | 'MEDIUM' | 'LOW' }[];
  explanation: string;
  evidence: Record<string, any>;
  traceability: {
    datasetRecordId?: string;
    associatedAgent: 'NETWORK_AGENT' | 'SYSTEM_AGENT' | 'APPLICATION_AGENT';
    securityEventId: string;
    threatDetectionId: string;
    riskAssessmentId?: string;
    securityAlertId?: string;
    incidentId?: string;
  };
}

export interface MLBackendStatus {
  backendConfigured: boolean;
  pythonVersion: string | null;
  scikitLearnAvailable: boolean;
  pandasAvailable: boolean;
  joblibAvailable: boolean;
  statusLabel: 'CONFIGURED' | 'NOT_CONFIGURED' | 'ERROR';
  message: string;
  recommendedAction: string;
  localSetupInstructions: string[];
}
