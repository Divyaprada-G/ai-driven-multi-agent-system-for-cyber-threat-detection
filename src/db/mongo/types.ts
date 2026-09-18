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
  status: 'PENDING' | 'DISPATCHED' | 'FAILED' | 'RETRYING';
  attemptCount: number;
  maxAttempts: number;
  lastError?: string;
  responseStatus?: number;
  payloadSummary: string;
  createdAt: Date;
  updatedAt: Date;
  dispatchedAt?: Date;
}
