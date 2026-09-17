/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Advanced Security Dashboard, Analytics, Audit & Traceability Types
 */

import { SeverityLevel, AgentType } from './index';
import { ThreatClass } from './threatDetection';
import { PriorityLevel, RiskStatus } from './riskScoring';
import { AlertLifecycleStatus, IncidentLifecycleStatus } from './alertIncident';

export type SecurityPostureRating =
  | 'LOW ACTIVITY'
  | 'MODERATE ACTIVITY'
  | 'ELEVATED ACTIVITY'
  | 'HIGH ACTIVITY';

export type TimeRangeFilter = '24H' | '7D' | '30D' | 'ALL' | 'CUSTOM';

export type AuditActionType =
  | 'ALERT_CREATED'
  | 'ALERT_ACKNOWLEDGED'
  | 'ALERT_STATUS_UPDATED'
  | 'INCIDENT_CREATED'
  | 'INCIDENT_ACKNOWLEDGED'
  | 'INCIDENT_STATUS_UPDATED'
  | 'INVESTIGATION_NOTE_ADDED'
  | 'RESPONSE_ACTION_DENIED'
  | 'RESPONSE_ACTION_AUTHORIZED'
  | 'STATUS_CHANGED'
  | 'FALSE_POSITIVE_MARKED'
  | 'INCIDENT_RESOLVED'
  | 'ANALYST_NOTE_ADDED'
  | 'DEMO_SCENARIO_STARTED'
  | 'DEMO_SCENARIO_RESET'
  | 'SIMULATION_EXECUTED'
  | 'CONFIG_UPDATED'
  | 'TRAINING_STARTED'
  | 'TRAINING_COMPLETED'
  | 'TRAINING_FAILED'
  | 'MODEL_SAVED'
  | 'MODEL_LOADED'
  | 'PREDICTION_EXECUTED';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: AuditActionType;
  entityType: 'ALERT' | 'INCIDENT' | 'RISK' | 'THREAT' | 'SYSTEM' | 'DEMO' | 'CONFIG' | 'MODEL' | 'DATASET';
  entityId: string;
  actor: string;
  details: string;
  previousValue?: string;
  newValue?: string;
  metadata?: Record<string, unknown>;
}

export type TimelineEventType =
  | 'LOG_RECEIVED'
  | 'AGENT_FINDING'
  | 'CORRELATION_CREATED'
  | 'THREAT_DETECTED'
  | 'RISK_ASSESSED'
  | 'ALERT_GENERATED'
  | 'INCIDENT_CREATED'
  | 'ALERT_ACKNOWLEDGED'
  | 'INVESTIGATION_STARTED'
  | 'INCIDENT_RESOLVED';

export interface UnifiedTimelineItem {
  id: string;
  timestamp: string;
  eventType: TimelineEventType;
  title: string;
  description: string;
  severity: SeverityLevel;
  riskScore?: number;
  priority?: PriorityLevel;
  source?: string;
  participatingAgents?: AgentType[];
  relatedId?: string;
  relatedType?: 'LOG' | 'FINDING' | 'CORRELATION' | 'THREAT' | 'RISK' | 'ALERT' | 'INCIDENT';
}

export interface TraceabilityStep {
  stage:
    | 'Original Event'
    | 'Agent Finding'
    | 'Correlated Event'
    | 'Threat Detection'
    | 'Risk Assessment'
    | 'Alert'
    | 'Incident';
  id: string;
  label: string;
  status?: string;
  timestamp?: string;
  details?: string;
  agent?: AgentType | string;
  severity?: SeverityLevel;
  score?: number;
}

export interface TraceabilityChain {
  id: string;
  title: string;
  classification: ThreatClass | string;
  overallSeverity: SeverityLevel;
  overallRiskScore: number;
  steps: TraceabilityStep[];
}

export interface GlobalFilterCriteria {
  searchTerm?: string;
  timeRange: TimeRangeFilter;
  customStartDate?: string;
  customEndDate?: string;
  severity?: 'ALL' | SeverityLevel;
  riskLevel?: 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  priority?: 'ALL' | PriorityLevel;
  threatClassification?: 'ALL' | ThreatClass | string;
  agent?: 'ALL' | AgentType;
  alertStatus?: 'ALL' | AlertLifecycleStatus;
  incidentStatus?: 'ALL' | IncidentLifecycleStatus;
}

export interface GlobalSearchResultItem {
  id: string;
  type: 'EVENT' | 'THREAT' | 'RISK' | 'ALERT' | 'INCIDENT' | 'CORRELATION';
  title: string;
  subtitle: string;
  timestamp: string;
  severity?: SeverityLevel;
  riskScore?: number;
  priority?: PriorityLevel;
  status?: string;
  classification?: string;
  source?: string;
  correlationId?: string;
}

export type ComponentHealthStatus =
  | 'ACTIVE'
  | 'READY'
  | 'DEMO'
  | 'SIMULATED'
  | 'NOT CONFIGURED'
  | 'UNKNOWN';

export interface ComponentHealthInfo {
  id: string;
  name: string;
  layer: 'INPUT' | 'PROCESSING' | 'AGENT' | 'INTELLIGENCE' | 'RESPONSE' | 'PRESENTATION';
  status: ComponentHealthStatus;
  verificationMethod: string;
  lastChecked: string;
  details: string;
  isSimulated: boolean;
}

export interface DataSourceStatusInfo {
  id: string;
  name: string;
  type: 'DATASET' | 'LIVE_FEED' | 'DEMO_GENERATOR';
  status: 'CONNECTED' | 'LOADED' | 'DEMO' | 'NOT CONFIGURED';
  recordCount: number;
  loadedAt?: string;
  format?: string;
  description: string;
}

export interface MLModelStatusInfo {
  id: string;
  name: string;
  modelType: string;
  status: 'MODEL LOADED' | 'DEMO MODEL' | 'NOT TRAINED' | 'NOT CONFIGURED';
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1Score?: number;
  evaluationAvailable: boolean;
  algorithm: string;
  trainingDataset?: string;
}

export interface PipelineStageInfo {
  id: string;
  stepNumber: number;
  name: string;
  status: ComponentHealthStatus;
  description: string;
  input: string;
  output: string;
  processedCount: number;
}

export interface SystemHealthReport {
  overallStatus: 'OPERATIONAL' | 'DEGRADED' | 'DEMO_ACTIVE';
  mode: 'DEMO / SIMULATED' | 'EVALUATION_DATASET' | 'PRODUCTION_ACTIVE';
  components: ComponentHealthInfo[];
  dataSources: DataSourceStatusInfo[];
  mlModels: MLModelStatusInfo[];
  pipelineStages: PipelineStageInfo[];
  uptimeSeconds: number;
  lastAuditTime: string;
}

export interface DemoScenarioDefinition {
  id: string;
  scenarioNumber: number;
  name: string;
  category: string;
  description: string;
  expectedFlow: string[];
  threatClassification: ThreatClass;
  severity: SeverityLevel;
  expectedRiskScore: number;
  priority: PriorityLevel;
  participatingAgents: AgentType[];
  deterministicEntities: {
    sourceIp: string;
    targetHost: string;
    user: string;
    endpoint: string;
  };
}
