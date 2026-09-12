/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Core Data Models and Domain Interfaces
 */

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type LogType = 'NETWORK' | 'SYSTEM' | 'APPLICATION';

export type AgentType = 'NETWORK_AGENT' | 'SYSTEM_AGENT' | 'APPLICATION_AGENT';

export type AgentStatus = 'READY' | 'ACTIVE' | 'PROCESSING' | 'DEGRADED' | 'OFFLINE';

export type NotificationStatus = 'PENDING' | 'SENT' | 'FAILED' | 'DISPATCHED_N8N';

export type LogFileFormat = 'JSON' | 'JSONL' | 'CSV' | 'SYSLOG' | 'PLAINTEXT' | 'KEY_VALUE';

export type ValidationStatus = 'VALID' | 'INVALID';

export type NavPageId =
  | 'dashboard'
  | 'live-pipeline'
  | 'log-explorer'
  | 'network-agent'
  | 'system-agent'
  | 'application-agent'
  | 'event-correlation'
  | 'threat-detection'
  | 'risk-analysis'
  | 'incidents'
  | 'alerts'
  | 'datasets-ml'
  | 'reports'
  | 'settings';

export * from './correlation';

export interface LogValidationResult {
  status: ValidationStatus;
  errors: string[];
  warnings: string[];
}

/**
 * Standardized fields produced by logNormalizer
 */
export interface NormalizedFields {
  // Network attributes
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  packetSize?: number;
  flags?: string[];
  flowDuration?: number;

  // System/Host attributes
  hostName?: string;
  processId?: number;
  processName?: string;
  userName?: string;
  commandLine?: string;
  parentProcess?: string;
  integrityLevel?: string;

  // Application/Web attributes
  applicationName?: string;
  httpMethod?: string;
  endpoint?: string;
  statusCode?: number;
  userAgent?: string;
  payloadSnippet?: string;

  // Extensible attribute map
  [key: string]: unknown;
}

/**
 * Base Unified Log Event Model (Stage 2 Unified Representation)
 */
export interface LogEvent {
  id: string;
  timestamp: string;
  ingestionTimestamp?: string;
  source: string;
  logType: LogType;
  message: string;
  rawData?: string;
  format?: LogFileFormat;
  normalizedFields?: NormalizedFields;
  validation?: LogValidationResult;
  isDuplicate?: boolean;
  duplicateCount?: number;
  fingerprint?: string;
  metadata?: Record<string, unknown>;
}

export type UnifiedLogEvent = LogEvent;

/**
 * Network Log Event Specialization
 */
export interface NetworkEvent extends LogEvent {
  logType: 'NETWORK';
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS';
  packetSize?: number;
  flags?: string[];
  flowDuration?: number;
}

/**
 * System/Host Log Event Specialization
 */
export interface SystemEvent extends LogEvent {
  logType: 'SYSTEM';
  hostName: string;
  processId: number;
  processName: string;
  userName: string;
  commandLine?: string;
  parentProcess?: string;
  integrityLevel?: string;
}

/**
 * Application/Web Log Event Specialization
 */
export interface ApplicationEvent extends LogEvent {
  logType: 'APPLICATION';
  applicationName: string;
  httpMethod?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  endpoint?: string;
  statusCode?: number;
  userAgent?: string;
  payloadSnippet?: string;
}

/**
 * Common Multi-Agent Output Contract
 * Shared compatible structure so all specialized agents (Network, System, Application)
 * can be seamlessly consumed by the correlation engine.
 */
export interface CommonAgentResult {
  id?: string;
  agentId: AgentType;
  eventId: string;
  timestamp: string;
  source?: string;
  threatDetected: boolean;
  threatType: string;
  severity: SeverityLevel;
  confidence: number; // 0.00 to 1.00
  evidence: string[];
  indicators: string[];
  detection: string;
  classification?: 'BENIGN' | 'SUSPICIOUS' | 'THREAT';
  recommendedAction?: string;
  observedActivity?: string;
  detectedPattern?: string;
  securityFinding?: string;
  status?: string;
  rawEvent?: LogEvent;
}

/**
 * Specialized Agent Evaluation Result
 */
export interface AgentResult {
  agentId: AgentType;
  eventId: string;
  timestamp: string;
  detection: string;
  confidence: number; // 0.00 to 1.00
  severity: SeverityLevel;
  indicators: string[];
  rawEvidence?: string;
}

/**
 * Agent Status Information
 */
export interface AgentStatusInfo {
  agentId: AgentType;
  name: string;
  status: AgentStatus;
  eventsProcessed: number;
  threatsDetected: number;
  lastActivity: string;
  detectionConfidence: number; // percentage, e.g., 94.8
  description: string;
  activeRulesCount: number;
  uptime: string;
}

// Re-export threat detection types, risk scoring types, correlation types, alert/incident types, and dataset ML types
export * from './threatDetection';
export * from './correlation';
export * from './riskScoring';
export * from './alertIncident';
export * from './datasetMl';

/**
 * High-Level Dashboard SOC Metrics
 */
export interface DashboardMetrics {
  totalEvents: number;
  suspiciousEvents: number;
  activeThreats: number;
  criticalIncidents: number;
  networkEvents: number;
  systemEvents: number;
  applicationEvents: number;
  lastUpdated: string;
}

/**
 * Ingested Log File Record for Log Explorer
 */
export interface LogFileRecord {
  id: string;
  filename: string;
  logType: LogType;
  fileSize: string;
  uploadTime: string;
  processingStatus: 'PARSING' | 'COMPLETED' | 'FAILED' | 'QUEUED';
  numberOfEvents: number;
  validCount?: number;
  invalidCount?: number;
  duplicateCount?: number;
  detectedFormat?: LogFileFormat;
  parsedPreview?: string[];
  parsingDurationMs?: number;
  errors?: string[];
}

/**
 * Result of ingesting a batch or file
 */
export interface IngestionBatchResult {
  fileId: string;
  filename: string;
  fileSize: string;
  detectedFormat: LogFileFormat;
  detectedLogType: LogType;
  totalParsed: number;
  validCount: number;
  invalidCount: number;
  duplicateCount: number;
  durationMs: number;
  events: LogEvent[];
  errors: string[];
}

/**
 * Aggregate telemetry repository statistics
 */
export interface RepositoryStats {
  totalEvents: number;
  validEvents: number;
  invalidEvents: number;
  duplicateEvents: number;
  networkEvents: number;
  systemEvents: number;
  applicationEvents: number;
  uniqueSources: number;
  firstEventTime: string | null;
  lastEventTime: string | null;
  ingestedFilesCount: number;
  isRealDataActive: boolean;
}

/**
 * Log explorer query and filter criteria
 */
export interface LogFilterCriteria {
  searchTerm?: string;
  logType?: 'ALL' | LogType;
  validationStatus?: 'ALL' | ValidationStatus | 'DUPLICATE';
  source?: string;
  timeRange?: 'ALL' | '15M' | '1H' | '24H' | '7D';
  deduplicate?: boolean;
}

/**
 * Chart Data Types
 */
export interface TimeSeriesPoint {
  time: string;
  networkEvents: number;
  systemEvents: number;
  applicationEvents: number;
  threats: number;
}

export interface SeverityDistributionPoint {
  severity: SeverityLevel;
  count: number;
  color: string;
}

export interface SourceDistributionPoint {
  source: string;
  count: number;
  threats: number;
}

export interface AgentActivityPoint {
  time: string;
  networkAgent: number;
  systemAgent: number;
  applicationAgent: number;
}

export interface ThreatCategoryPoint {
  category: string;
  count: number;
  riskAvg: number;
}

export * from './network';
export * from './system';
export * from './application';
