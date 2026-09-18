/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Document Types, Enums & Interfaces
 */

export type SeverityLevel = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
export type IncidentPriority = 'P1' | 'P2' | 'P3' | 'P4';
export type IncidentStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED';
export type DetectionEngine = 'RULE_BASED' | 'RANDOM_FOREST' | 'ISOLATION_FOREST' | 'ENSEMBLE';
export type AgentLogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export interface InvestigationNote {
  id: string;
  author: string;
  note: string;
  timestamp: string;
}

export interface IncidentHistoryItem {
  id: string;
  incidentId: string;
  field: string;
  oldValue: string;
  newValue: string;
  actor: string;
  reason?: string;
  timestamp: string;
}

/**
 * 1. Security Event Document Schema
 */
export interface MongoSecurityEvent {
  _id?: any;
  id: string;
  source: string;
  eventType: string;
  severity: SeverityLevel;
  rawPayload: string;
  normalizedFields: Record<string, any>;
  sourceIp?: string;
  destinationIp?: string;
  host?: string;
  username?: string;
  contentHash: string;
  batchId?: string;
  isTestEvent?: boolean;
  timestamp: Date;
  createdAt: Date;
}

/**
 * 2. Correlated Incident Document Schema
 */
export interface MongoIncident {
  _id?: any;
  incidentId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  priority: IncidentPriority;
  status: IncidentStatus;
  riskScore: number;
  primaryIp?: string;
  affectedHost?: string;
  mitreTechniques: string[];
  correlatedEvents: string[];
  investigationNotes: InvestigationNote[];
  containmentStatus?: string;
  assignee?: string;
  resolutionSummary?: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * 3. Threat Detection Document Schema
 */
export interface MongoThreatDetection {
  _id?: any;
  detectionId: string;
  eventId?: string;
  threatType: string;
  threatCategory: string;
  severity: SeverityLevel;
  confidence: number;
  detectionEngine: DetectionEngine;
  features: Record<string, any>;
  explanation: string;
  mitreTechnique?: string;
  mitreTactic?: string;
  timestamp: Date;
  createdAt: Date;
}

/**
 * 4. Alert Record Document Schema
 */
export interface MongoAlert {
  _id?: any;
  alertId: string;
  incidentId?: string;
  title: string;
  description: string;
  alertType: string;
  threatCategory?: string;
  agentName?: string;
  detectionMethod?: string;
  recommendedAction?: string;
  incidentStatus?: string;
  severity: SeverityLevel;
  riskScore: number;
  priority: IncidentPriority;
  status: AlertStatus;
  mitreTechniques: string[];
  evidence: any[];
  actor?: string;
  timestamp: Date;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * 5. Agent Execution Log Document Schema
 */
export interface MongoAgentLog {
  _id?: any;
  logId: string;
  agentId: string;
  action: string;
  level: AgentLogLevel;
  message: string;
  executionTimeMs: number;
  eventsProcessedCount: number;
  metadata?: Record<string, any>;
  timestamp: Date;
  createdAt: Date;
}

/**
 * 6. Model Metadata Document Schema
 */
export interface MongoModelMetadata {
  _id?: any;
  modelId: string;
  modelName: string;
  algorithm: string;
  version: string;
  status: 'ACTIVE' | 'TRAINING' | 'DEPRECATED';
  datasetUsed: string;
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1Score?: number;
    rocAuc?: number;
    trainingSamples?: number;
    testSamples?: number;
  };
  hyperparameters?: Record<string, any>;
  featureNames: string[];
  trainedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Filter & Pagination Options
 */
export interface MongoPaginationOptions {
  limit?: number;
  offset?: number;
  page?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface MongoPaginatedResult<T> {
  data: T[];
  incidents?: T[];
  alerts?: T[];
  events?: T[];
  total: number;
  limit: number;
  offset: number;
  page: number;
  totalPages: number;
  hasMore: boolean;
}

export interface MongoHealthStatus {
  status: 'CONNECTED' | 'DISCONNECTED' | 'ERROR' | 'UNCONFIGURED';
  connected: boolean;
  database?: string;
  host?: string;
  details?: string;
  collections?: {
    securityEvents: number;
    incidents: number;
    threatDetections: number;
    alerts: number;
    agentLogs: number;
    modelMetadata: number;
  };
}

export interface MongoDashboardStats {
  status: string;
  totalEvents: number;
  threatsDetected: number;
  criticalThreats: number;
  highThreats: number;
  mediumThreats: number;
  lowThreats: number;
  activeIncidents: number;
  resolvedIncidents: number;
  totalAlerts: number;
  openAlerts: number;
  agentLogsCount: number;
  activeModelsCount: number;
  timestamp: string;
  source: 'MONGODB' | 'JSON_STORE_FALLBACK';
}

export interface MongoAuditLog {
  _id?: any;
  id: string;
  timestamp: Date;
  action: string;
  actor: string;
  entityType: 'INCIDENT' | 'ALERT' | 'RESPONSE_ACTION' | 'SYSTEM' | 'NOTIFICATION';
  entityId: string;
  details: string;
  previousStatus?: string;
  newStatus?: string;
  reason?: string;
  createdAt: Date;
}

export interface MongoNotificationDispatch {
  _id?: any;
  id: string;
  channel: 'EMAIL' | 'WEBHOOK' | 'N8N';
  alertId: string;
  incidentId?: string;
  destination: string;
  status: 'PENDING' | 'DISPATCHED' | 'SENT' | 'FAILED' | 'RETRYING' | 'NOT_CONFIGURED';
  attemptCount: number;
  maxAttempts: number;
  lastError?: string;
  responseStatus?: number;
  payloadSummary: string;
  createdAt: Date;
  updatedAt: Date;
  dispatchedAt?: Date;
}

/**
 * -------------------------------------------------------------
 * UPGRADE 6: PRODUCTION-READY PERSISTENCE DOCUMENT SCHEMAS
 * -------------------------------------------------------------
 */

/**
 * 7. Raw Event Document Schema
 * Unique index: { event_id: 1 }
 */
export interface MongoRawEvent {
  _id?: any;
  event_id: string;
  source: string;
  source_type: string;
  hostname: string;
  raw_payload: string;
  content_hash: string;
  is_simulated: boolean;
  received_at: string;
  processed_at?: string;
  stored_at: string;
}

/**
 * 8. Normalized Event Document Schema
 * Unique index: { event_id: 1 }
 */
export interface MongoNormalizedEvent {
  _id?: any;
  event_id: string;
  source_type: string;
  hostname: string;
  local_ip?: string;
  remote_ip?: string;
  local_port?: number;
  remote_port?: number;
  protocol?: string;
  connection_state?: string;
  process_name?: string;
  collector_name?: string;
  collection_status?: string;
  is_simulated: boolean;
  received_at: string;
  processed_at: string;
  stored_at: string;
}

/**
 * 9. Validation Result Document Schema
 * Unique index: { event_id: 1 }
 */
export interface MongoValidationResult {
  _id?: any;
  event_id: string;
  is_valid: boolean;
  validation_status: string;
  errors: string[];
  warnings: string[];
  schema_version: string;
  received_at: string;
  processed_at: string;
  stored_at: string;
}

/**
 * 10. Agent Processing Result Document Schema
 * Unique compound index: { event_id: 1, agent_name: 1 }
 */
export interface MongoAgentProcessingResult {
  _id?: any;
  event_id: string;
  agent_name: string;
  agent_type: string;
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  findings: any[];
  evidence: string[];
  execution_time_ms: number;
  error?: string;
  received_at: string;
  processed_at: string;
  stored_at: string;
}

/**
 * 11. Multi-Agent Correlation Document Schema
 * Unique index: { correlation_id: 1 }
 */
export interface MongoCorrelationRecord {
  _id?: any;
  correlation_id: string;
  event_ids: string[];
  attack_chain_detected: boolean;
  cluster_size: number;
  rules_matched: string[];
  confidence: number;
  threat_chain?: string;
  agents_involved: string[];
  received_at?: string;
  processed_at?: string;
  stored_at: string;
}

/**
 * 12. Threat Detection Document Schema (Upgrade 6)
 * Unique index: { detection_id: 1 }
 */
export interface MongoThreatDetectionRecord {
  _id?: any;
  detection_id: string;
  event_id: string;
  correlation_id?: string;
  threat_type: string;
  threat_category: string;
  severity: string;
  confidence: number;
  detection_engine: string;
  evidence: string[];
  explanation?: string;
  received_at: string;
  processed_at: string;
  stored_at: string;
}

/**
 * 13. Risk Score Assessment Document Schema
 * Unique index: { event_id: 1 }
 */
export interface MongoRiskScoreRecord {
  _id?: any;
  event_id: string;
  risk_score: number;
  risk_band: 'Low' | 'Medium' | 'High' | 'Critical';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  factors: Record<string, any>;
  explanation: string;
  received_at: string;
  processed_at: string;
  stored_at: string;
}

/**
 * 14. Standardized Security Alert Schema (Upgrade 6)
 * Unique index: { alert_id: 1 }
 * Includes all required fields:
 * - alert_id
 * - event_id
 * - detection_source
 * - threat_type
 * - severity
 * - risk_score
 * - evidence
 * - created_at
 * - workflow_status
 * - notification_status
 */
export interface MongoAlertRecord {
  _id?: any;
  alert_id: string;
  event_id: string;
  detection_source: string;
  threat_type: string;
  severity: SeverityLevel | string;
  risk_score: number;
  evidence: string[];
  created_at: string;
  workflow_status: 'PENDING' | 'PERSISTED' | 'NOTIFIED' | 'COMPLETED' | 'FAILED' | 'DEGRADED';
  notification_status: 'NOT_CONFIGURED' | 'PENDING' | 'SENT' | 'FAILED' | 'RETRYING' | 'SIMULATED';
  incident_id?: string;
  title?: string;
  description?: string;
  category?: string;
  recommended_actions?: string[];
  recommended_action?: string;
  received_at?: string;
  processed_at?: string;
  stored_at: string;
}

/**
 * 15. Standardized Incident Record (Upgrade 6)
 * Unique index: { incident_id: 1 }
 */
export interface MongoIncidentRecord {
  _id?: any;
  incident_id: string;
  title: string;
  description: string;
  severity: string;
  priority: string;
  risk_score: number;
  status: string;
  alert_ids: string[];
  associated_event_ids: string[];
  affected_entities: string[];
  containment_status: string;
  assigned_to?: string;
  mitre_technique?: string;
  mitre_techniques?: string[];
  created_at: string;
  updated_at: string;
  received_at?: string;
  processed_at?: string;
  stored_at: string;
}

/**
 * 16. Audit Log Document Schema (Upgrade 6)
 * Unique index: { id: 1 }
 */
export interface MongoAuditLogRecord {
  _id?: any;
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  entity_type: string;
  entity_id: string;
  details: string;
  metadata?: Record<string, any>;
  stored_at: string;
}

/**
 * Persistence Operation Result
 */
export interface PersistenceWriteResult<T = any> {
  success: boolean;
  status: 'PERSISTED' | 'DATABASE_UNAVAILABLE' | 'DUPLICATE_SKIPPED' | 'WRITE_FAILED';
  isDuplicate: boolean;
  doc?: T;
  error?: string;
  stored_at?: string;
}

/**
 * Persistence Telemetry Batch Summary
 */
export interface FullTelemetryPersistenceSummary {
  eventId: string;
  success: boolean;
  status: 'PERSISTED' | 'DATABASE_UNAVAILABLE' | 'WRITE_FAILED';
  collectionsWritten: string[];
  isDuplicate: boolean;
  error?: string;
  storedAt: string;
}

/**
 * Live Database & Workflow Metrics
 */
export interface DatabaseWorkflowMetrics {
  mongoStatus: 'CONNECTED' | 'DISCONNECTED' | 'DATABASE_UNAVAILABLE' | 'UNCONFIGURED';
  lastSuccessfulWrite: string | null;
  persistenceFailures: number;
  lastPersistenceError: string | null;
  alertWorkflowStatus: 'IDLE' | 'PROCESSING' | 'HEALTHY' | 'DEGRADED' | 'FAILED';
  n8nStatus: 'NOT_CONFIGURED' | 'PENDING' | 'SENT' | 'FAILED' | 'RETRYING';
  notificationStatus: 'NOT_CONFIGURED' | 'SENT' | 'FAILED' | 'RETRYING' | 'SIMULATED';
  failedWorkflowCount: number;
  totalWorkflows: number;
  successfulWorkflows: number;
}

