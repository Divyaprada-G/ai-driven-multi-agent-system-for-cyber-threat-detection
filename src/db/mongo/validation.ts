/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Validation and Sensitive Information Sanitization Utilities
 */
import crypto from 'crypto';
import {
  SeverityLevel,
  IncidentPriority,
  IncidentStatus,
  AlertStatus,
  DetectionEngine,
  AgentLogLevel,
  MongoSecurityEvent,
  MongoIncident,
  MongoThreatDetection,
  MongoAlert,
  MongoAgentLog,
  MongoModelMetadata
} from './types';

const ALLOWED_SEVERITIES: Set<SeverityLevel> = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const ALLOWED_PRIORITIES: Set<IncidentPriority> = new Set(['P1', 'P2', 'P3', 'P4']);
const ALLOWED_INCIDENT_STATUSES: Set<IncidentStatus> = new Set([
  'NEW',
  'ACKNOWLEDGED',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE'
]);
const ALLOWED_ALERT_STATUSES: Set<AlertStatus> = new Set([
  'NEW',
  'ACKNOWLEDGED',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE',
  'SUPPRESSED'
]);
const ALLOWED_ENGINES: Set<DetectionEngine> = new Set([
  'RULE_BASED',
  'RANDOM_FOREST',
  'ISOLATION_FOREST',
  'ENSEMBLE'
]);
const ALLOWED_LOG_LEVELS: Set<AgentLogLevel> = new Set(['DEBUG', 'INFO', 'WARN', 'ERROR']);

// Sensitive field keys to redact from logs and raw payloads
const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /auth(?:orization)?/i,
  /bearer/i,
  /private[_-]?key/i,
  /credit[_-]?card/i,
  /cvv/i,
  /ssn/i
];

/**
 * Computes a deterministic SHA-256 content hash for an event payload to detect duplicates.
 */
export function computeEventContentHash(source: string, eventType: string, rawPayload: string, sourceIp?: string): string {
  const normalized = `${source.trim().toLowerCase()}|${eventType.trim().toLowerCase()}|${rawPayload.trim()}|${(sourceIp || '').trim()}`;
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Recursively sanitizes objects to prevent MongoDB query injection ($ and . in keys)
 * and redacts sensitive credentials/tokens from being stored in plaintext.
 */
export function sanitizeSensitiveData(obj: any, depth = 0): any {
  if (depth > 10 || obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    // Redact password occurrences in standard formats: password=XYZ or "password": "XYZ"
    return obj
      .replace(/((?:password|passwd|token|secret|authorization)\s*[:=]\s*["']?)([^"',;\s&]+)(["']?)/gi, '$1[REDACTED]$3')
      .replace(/(bearer\s+)([A-Za-z0-9\-._~+/]+=*)/gi, '$1[REDACTED]');
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeSensitiveData(item, depth + 1));
  }

  if (typeof obj === 'object') {
    const clean: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      // Strip dangerous characters from keys that could cause BSON injection
      const safeKey = key.replace(/^\$/, '_$').replace(/\./g, '_');

      const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));
      if (isSensitive) {
        clean[safeKey] = '[REDACTED]';
      } else {
        clean[safeKey] = sanitizeSensitiveData(value, depth + 1);
      }
    }
    return clean;
  }

  return obj;
}

/**
 * 1. Validate Security Event Input
 */
export function validateSecurityEventInput(input: any): Omit<MongoSecurityEvent, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Security event must be a valid non-empty object.');
  }

  const source = String(input.source || '').trim();
  const eventType = String(input.eventType || input.event_type || '').trim();
  const rawPayload = typeof input.rawPayload === 'string' ? input.rawPayload : JSON.stringify(input.rawPayload || input.raw || '');

  if (!source) {
    throw new Error("Missing required event field: 'source' is required.");
  }
  if (!eventType) {
    throw new Error("Missing required event field: 'eventType' is required.");
  }
  if (!rawPayload) {
    throw new Error("Missing required event field: 'rawPayload' is required.");
  }

  let severity: SeverityLevel = 'MEDIUM';
  if (input.severity && ALLOWED_SEVERITIES.has(String(input.severity).toUpperCase() as SeverityLevel)) {
    severity = String(input.severity).toUpperCase() as SeverityLevel;
  }

  const id = String(input.id || `EVT-${crypto.randomUUID()}`);
  const sourceIp = input.sourceIp || input.src_ip || input.source_ip || undefined;
  const destinationIp = input.destinationIp || input.dst_ip || input.destination_ip || undefined;
  const host = input.host || input.hostname || undefined;
  const username = input.username || input.user || undefined;
  const batchId = input.batchId || undefined;
  const isTestEvent = Boolean(input.isTestEvent);

  const timestamp = input.timestamp ? new Date(input.timestamp) : (input.eventTimestamp ? new Date(input.eventTimestamp) : new Date());
  if (isNaN(timestamp.getTime())) {
    throw new Error('Invalid event timestamp provided.');
  }

  const sanitizedPayload = sanitizeSensitiveData(rawPayload);
  const sanitizedNormalized = sanitizeSensitiveData(input.normalizedFields || input.normalized || {});
  const contentHash = input.contentHash || computeEventContentHash(source, eventType, sanitizedPayload, sourceIp);

  return {
    id,
    source,
    eventType,
    severity,
    rawPayload: sanitizedPayload,
    normalizedFields: sanitizedNormalized,
    sourceIp: sourceIp ? String(sourceIp) : undefined,
    destinationIp: destinationIp ? String(destinationIp) : undefined,
    host: host ? String(host) : undefined,
    username: username ? String(username) : undefined,
    contentHash,
    batchId,
    isTestEvent,
    timestamp,
    createdAt: new Date()
  };
}

/**
 * 2. Validate Incident Input
 */
export function validateIncidentInput(input: any): Omit<MongoIncident, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Incident must be a valid non-empty object.');
  }

  const title = String(input.title || '').trim();
  const description = String(input.description || '').trim();

  if (!title) {
    throw new Error("Missing required incident field: 'title' is required.");
  }

  const incidentId = String(input.incidentId || input.id || `INC-${Date.now()}`);
  let severity: SeverityLevel = 'HIGH';
  if (input.severity && ALLOWED_SEVERITIES.has(String(input.severity).toUpperCase() as SeverityLevel)) {
    severity = String(input.severity).toUpperCase() as SeverityLevel;
  }

  let priority: IncidentPriority = 'P2';
  if (input.priority && ALLOWED_PRIORITIES.has(String(input.priority).toUpperCase() as IncidentPriority)) {
    priority = String(input.priority).toUpperCase() as IncidentPriority;
  }

  let status: IncidentStatus = 'NEW';
  if (input.status && ALLOWED_INCIDENT_STATUSES.has(String(input.status).toUpperCase() as IncidentStatus)) {
    status = String(input.status).toUpperCase() as IncidentStatus;
  }

  const riskScore = Math.max(0, Math.min(100, Number(input.riskScore ?? 50)));

  const mitreTechniques = Array.isArray(input.mitreTechniques) ? input.mitreTechniques.map(String) : [];
  const correlatedEvents = Array.isArray(input.correlatedEvents) ? input.correlatedEvents.map(String) : [];

  let investigationNotes: any[] = [];
  if (Array.isArray(input.investigationNotes)) {
    investigationNotes = input.investigationNotes.map((note: any) => ({
      id: String(note.id || `note-${crypto.randomUUID()}`),
      author: String(note.author || 'SOC Analyst'),
      note: sanitizeSensitiveData(String(note.note || '')),
      timestamp: note.timestamp || new Date().toISOString()
    }));
  }

  return {
    incidentId,
    title: sanitizeSensitiveData(title),
    description: sanitizeSensitiveData(description),
    severity,
    priority,
    status,
    riskScore,
    primaryIp: input.primaryIp ? String(input.primaryIp) : undefined,
    affectedHost: input.affectedHost ? String(input.affectedHost) : undefined,
    mitreTechniques,
    correlatedEvents,
    investigationNotes,
    containmentStatus: input.containmentStatus ? String(input.containmentStatus) : 'UNCONTAINED',
    assignee: input.assignee ? String(input.assignee) : undefined,
    resolutionSummary: input.resolutionSummary ? String(input.resolutionSummary) : undefined,
    createdAt: input.createdAt ? new Date(input.createdAt) : new Date(),
    updatedAt: new Date()
  };
}

/**
 * 3. Validate Threat Detection Input
 */
export function validateThreatDetectionInput(input: any): Omit<MongoThreatDetection, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Threat detection must be a valid non-empty object.');
  }

  const threatType = String(input.threatType || input.threat_type || '').trim();
  if (!threatType) {
    throw new Error("Missing required detection field: 'threatType' is required.");
  }

  const detectionId = String(input.detectionId || input.id || `DET-${crypto.randomUUID()}`);
  let severity: SeverityLevel = 'MEDIUM';
  if (input.severity && ALLOWED_SEVERITIES.has(String(input.severity).toUpperCase() as SeverityLevel)) {
    severity = String(input.severity).toUpperCase() as SeverityLevel;
  }

  let detectionEngine: DetectionEngine = 'RULE_BASED';
  if (input.detectionEngine && ALLOWED_ENGINES.has(String(input.detectionEngine).toUpperCase() as DetectionEngine)) {
    detectionEngine = String(input.detectionEngine).toUpperCase() as DetectionEngine;
  }

  const confidence = Math.max(0, Math.min(1, Number(input.confidence ?? 0.8)));
  const features = sanitizeSensitiveData(input.features || {});
  const explanation = sanitizeSensitiveData(String(input.explanation || 'Threat pattern detected'));

  return {
    detectionId,
    eventId: input.eventId ? String(input.eventId) : undefined,
    threatType,
    threatCategory: String(input.threatCategory || 'CYBER_ATTACK'),
    severity,
    confidence,
    detectionEngine,
    features,
    explanation,
    mitreTechnique: input.mitreTechnique ? String(input.mitreTechnique) : undefined,
    mitreTactic: input.mitreTactic ? String(input.mitreTactic) : undefined,
    timestamp: input.timestamp ? new Date(input.timestamp) : new Date(),
    createdAt: new Date()
  };
}

/**
 * 4. Validate Alert Record Input
 */
export function validateAlertInput(input: any): Omit<MongoAlert, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Alert must be a valid non-empty object.');
  }

  const title = String(input.title || '').trim();
  if (!title) {
    throw new Error("Missing required alert field: 'title' is required.");
  }

  const alertId = String(input.alertId || input.id || `ALT-${Date.now()}`);
  let severity: SeverityLevel = 'MEDIUM';
  if (input.severity && ALLOWED_SEVERITIES.has(String(input.severity).toUpperCase() as SeverityLevel)) {
    severity = String(input.severity).toUpperCase() as SeverityLevel;
  }

  let priority: IncidentPriority = 'P3';
  if (input.priority && ALLOWED_PRIORITIES.has(String(input.priority).toUpperCase() as IncidentPriority)) {
    priority = String(input.priority).toUpperCase() as IncidentPriority;
  }

  let status: AlertStatus = 'NEW';
  if (input.status && ALLOWED_ALERT_STATUSES.has(String(input.status).toUpperCase() as AlertStatus)) {
    status = String(input.status).toUpperCase() as AlertStatus;
  }

  const riskScore = Math.max(0, Math.min(100, Number(input.riskScore ?? 50)));

  return {
    alertId,
    incidentId: input.incidentId ? String(input.incidentId) : undefined,
    title: sanitizeSensitiveData(title),
    description: sanitizeSensitiveData(String(input.description || '')),
    alertType: String(input.alertType || input.alert_type || 'SECURITY_ALERT'),
    severity,
    riskScore,
    priority,
    status,
    mitreTechniques: Array.isArray(input.mitreTechniques) ? input.mitreTechniques.map(String) : [],
    evidence: Array.isArray(input.evidence) ? sanitizeSensitiveData(input.evidence) : [],
    actor: input.actor ? String(input.actor) : undefined,
    timestamp: input.timestamp ? new Date(input.timestamp) : new Date(),
    createdAt: input.createdAt ? new Date(input.createdAt) : new Date(),
    updatedAt: new Date()
  };
}

/**
 * 5. Validate Agent Execution Log Input
 */
export function validateAgentLogInput(input: any): Omit<MongoAgentLog, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Agent log must be a valid non-empty object.');
  }

  const agentId = String(input.agentId || input.agent || '').trim();
  const action = String(input.action || '').trim();
  if (!agentId) {
    throw new Error("Missing required agent log field: 'agentId' is required.");
  }
  if (!action) {
    throw new Error("Missing required agent log field: 'action' is required.");
  }

  let level: AgentLogLevel = 'INFO';
  if (input.level && ALLOWED_LOG_LEVELS.has(String(input.level).toUpperCase() as AgentLogLevel)) {
    level = String(input.level).toUpperCase() as AgentLogLevel;
  }

  return {
    logId: String(input.logId || `LOG-${crypto.randomUUID()}`),
    agentId,
    action,
    level,
    message: sanitizeSensitiveData(String(input.message || '')),
    executionTimeMs: Math.max(0, Number(input.executionTimeMs || 0)),
    eventsProcessedCount: Math.max(0, Number(input.eventsProcessedCount || 0)),
    metadata: sanitizeSensitiveData(input.metadata || {}),
    timestamp: input.timestamp ? new Date(input.timestamp) : new Date(),
    createdAt: new Date()
  };
}

/**
 * 6. Validate Model Metadata Input
 */
export function validateModelMetadataInput(input: any): Omit<MongoModelMetadata, '_id'> {
  if (!input || typeof input !== 'object') {
    throw new Error('Model metadata must be a valid non-empty object.');
  }

  const modelId = String(input.modelId || input.id || '').trim();
  const algorithm = String(input.algorithm || input.modelType || '').trim();
  if (!modelId) {
    throw new Error("Missing required model field: 'modelId' is required.");
  }
  if (!algorithm) {
    throw new Error("Missing required model field: 'algorithm' is required.");
  }

  return {
    modelId,
    modelName: String(input.modelName || modelId),
    algorithm,
    version: String(input.version || input.modelVersion || '1.0.0'),
    status: (input.status === 'TRAINING' || input.status === 'DEPRECATED') ? input.status : 'ACTIVE',
    datasetUsed: String(input.datasetUsed || input.datasetName || 'CICIDS2017'),
    metrics: input.metrics || input.evaluationMetrics || {},
    hyperparameters: input.hyperparameters || {},
    featureNames: Array.isArray(input.featureNames) ? input.featureNames.map(String) : (Array.isArray(input.selectedFeatures) ? input.selectedFeatures.map(String) : []),
    trainedAt: input.trainedAt ? new Date(input.trainedAt) : (input.trainingTimestamp ? new Date(input.trainingTimestamp) : new Date()),
    createdAt: new Date(),
    updatedAt: new Date()
  };
}
