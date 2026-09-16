import { pgTable, text, timestamp, integer, doublePrecision, boolean, jsonb, index, uniqueIndex } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

/**
 * 1. Users / Analysts
 */
export const users = pgTable('users', {
  id: text('id').primaryKey(), // UUID or Firebase Auth UID
  uid: text('uid').unique(),
  email: text('email').notNull(),
  name: text('name'),
  role: text('role').default('SOC_ANALYST'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

/**
 * 2. Raw Ingested & Normalized Security Events
 * Satisfies Task 3: UUID, ingestion_timestamp, event_timestamp, source, event_type, raw_payload, normalized_fields, content_hash
 */
export const rawEvents = pgTable('raw_events', {
  id: text('id').primaryKey(), // UUID
  contentHash: text('content_hash').notNull().unique(), // Deterministic SHA-256 for deduplication
  ingestionTimestamp: timestamp('ingestion_timestamp', { withTimezone: true }).defaultNow().notNull(),
  eventTimestamp: timestamp('event_timestamp', { withTimezone: true }).defaultNow().notNull(),
  source: text('source').notNull(),
  eventType: text('event_type').notNull(),
  rawPayload: text('raw_payload').notNull(),
  normalizedFields: jsonb('normalized_fields').notNull(),
  sourceIp: text('source_ip'),
  destinationIp: text('destination_ip'),
  host: text('host'),
  username: text('username'),
  severity: text('severity').default('LOW'),
  batchId: text('batch_id'),
  isTestEvent: boolean('is_test_event').default(false).notNull(),
}, (table) => [
  uniqueIndex('raw_events_content_hash_idx').on(table.contentHash),
  index('raw_events_event_timestamp_idx').on(table.eventTimestamp),
  index('raw_events_source_ip_idx').on(table.sourceIp),
  index('raw_events_dest_ip_idx').on(table.destinationIp),
]);

/**
 * 3. Security Findings (Agent Findings)
 * Satisfies Task 5: finding_id, event_id, agent_type, threat_type, evidence, confidence, MITRE technique, timestamp
 */
export const securityFindings = pgTable('security_findings', {
  id: text('id').primaryKey(), // UUID
  eventId: text('event_id').notNull().references(() => rawEvents.id, { onDelete: 'cascade' }),
  agentType: text('agent_type').notNull(), // 'NETWORK_AGENT' | 'SYSTEM_AGENT' | 'APPLICATION_AGENT'
  threatType: text('threat_type').notNull(),
  severity: text('severity').notNull(),
  confidence: doublePrecision('confidence').notNull(),
  evidence: jsonb('evidence').notNull().$type<string[]>(),
  indicators: jsonb('indicators').notNull().$type<string[]>(),
  mitreTechnique: text('mitre_technique'),
  mitreTactic: text('mitre_tactic'),
  timestamp: timestamp('timestamp', { withTimezone: true }).defaultNow().notNull(),
  metadata: jsonb('metadata'),
}, (table) => [
  index('security_findings_event_id_idx').on(table.eventId),
  index('security_findings_agent_type_idx').on(table.agentType),
  index('security_findings_threat_type_idx').on(table.threatType),
]);

/**
 * 4. Model Registry / Reference Information
 * Satisfies Task 2 & Task 4
 */
export const modelRegistry = pgTable('model_registry', {
  id: text('id').primaryKey(), // e.g. RF-20260916-105303
  modelType: text('model_type').notNull(), // 'RANDOM_FOREST' | 'ISOLATION_FOREST'
  modelVersion: text('model_version').notNull(),
  featureSchemaVersion: text('feature_schema_version').default('cicids2017-v1').notNull(),
  algorithm: text('algorithm').notNull(),
  trainingDataset: text('training_dataset'),
  trainingTimestamp: timestamp('training_timestamp', { withTimezone: true }),
  trainingMetrics: jsonb('training_metrics'),
  featureNames: jsonb('feature_names').$type<string[]>(),
  classes: jsonb('classes').$type<string[]>(),
  status: text('status').default('READY').notNull(),
  isTestData: boolean('is_test_data').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

/**
 * 5. ML Detections
 * Satisfies Task 4: event_id, model_id, model_version, prediction, class, class_probability/confidence, anomaly_score, anomaly_flag, inference_timestamp, feature_schema_version
 */
export const detections = pgTable('detections', {
  id: text('id').primaryKey(), // UUID
  eventId: text('event_id').notNull().references(() => rawEvents.id, { onDelete: 'cascade' }),
  modelId: text('model_id').notNull(),
  modelVersion: text('model_version').notNull(),
  featureSchemaVersion: text('feature_schema_version').default('cicids2017-v1').notNull(),
  prediction: text('prediction').notNull(),
  predictedClass: text('predicted_class').notNull(),
  confidence: doublePrecision('confidence').notNull(),
  classProbabilities: jsonb('class_probabilities').notNull(),
  anomalyScore: doublePrecision('anomaly_score'),
  anomalyFlag: boolean('anomaly_flag'),
  anomalyLabel: text('anomaly_label'),
  featureSummary: jsonb('feature_summary'),
  importantContributingFeatures: jsonb('important_contributing_features'),
  inferenceTimestamp: timestamp('inference_timestamp', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('detections_event_id_idx').on(table.eventId),
  index('detections_model_id_idx').on(table.modelId),
  index('detections_predicted_class_idx').on(table.predictedClass),
]);

/**
 * 6. Correlations
 * Satisfies Task 6: correlation_id, related_event_ids, related_finding_ids, correlation_rule, entities, time_window, attack_stage, mitre_techniques, correlation_score
 */
export const correlations = pgTable('correlations', {
  id: text('id').primaryKey(), // UUID
  relatedEventIds: jsonb('related_event_ids').notNull().$type<string[]>(),
  relatedFindingIds: jsonb('related_finding_ids').notNull().$type<string[]>(),
  correlationRule: text('correlation_rule').notNull(),
  ruleCategory: text('rule_category'),
  entities: jsonb('entities').notNull(),
  timeWindowStart: timestamp('time_window_start', { withTimezone: true }),
  timeWindowEnd: timestamp('time_window_end', { withTimezone: true }),
  attackStage: text('attack_stage'),
  mitreTechniques: jsonb('mitre_techniques').$type<string[]>(),
  correlationScore: doublePrecision('correlation_score').notNull(),
  correlationStrength: text('correlation_strength').notNull(), // 'LOW' | 'MEDIUM' | 'HIGH'
  summary: text('summary').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('correlations_score_idx').on(table.correlationScore),
  index('correlations_created_at_idx').on(table.createdAt),
]);

/**
 * 7. Risk Assessments
 * Satisfies Task 7: risk_score, risk_band, factor_values, factor_weights, calculation_timestamp
 */
export const riskAssessments = pgTable('risk_assessments', {
  id: text('id').primaryKey(), // UUID
  correlationId: text('correlation_id').references(() => correlations.id, { onDelete: 'set null' }),
  eventId: text('event_id').references(() => rawEvents.id, { onDelete: 'set null' }),
  riskScore: doublePrecision('risk_score').notNull(), // 0.0 - 100.0
  riskBand: text('risk_band').notNull(), // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  priority: text('priority').notNull(), // 'P1' | 'P2' | 'P3' | 'P4'
  factorValues: jsonb('factor_values').notNull(), // normalized 7 factors
  factorWeights: jsonb('factor_weights').notNull(), // weights 0.30, 0.20, etc.
  contributions: jsonb('contributions').notNull(),
  calculationTimestamp: timestamp('calculation_timestamp', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('risk_assessments_score_idx').on(table.riskScore),
  index('risk_assessments_band_idx').on(table.riskBand),
]);

/**
 * 8. Alerts
 * Satisfies Task 8: NEW, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
 */
export const alerts = pgTable('alerts', {
  id: text('id').primaryKey(), // UUID or ALT-XXXX
  alertId: text('alert_id').notNull().unique(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  alertType: text('alert_type').notNull(),
  severity: text('severity').notNull(), // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  status: text('status').notNull().default('NEW'), // 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED'
  riskScore: doublePrecision('risk_score').notNull(),
  priority: text('priority').notNull(),
  riskAssessmentId: text('risk_assessment_id').references(() => riskAssessments.id, { onDelete: 'set null' }),
  correlationId: text('correlation_id').references(() => correlations.id, { onDelete: 'set null' }),
  sourceIp: text('source_ip'),
  destinationIp: text('destination_ip'),
  affectedHost: text('affected_host'),
  affectedUser: text('affected_user'),
  mitreTechniques: jsonb('mitre_techniques').$type<string[]>(),
  evidence: jsonb('evidence').$type<string[]>(),
  notificationStatus: text('notification_status').default('PENDING'),
  burstCount: integer('burst_count').default(1).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  uniqueIndex('alerts_alert_id_idx').on(table.alertId),
  index('alerts_status_idx').on(table.status),
  index('alerts_severity_idx').on(table.severity),
  index('alerts_created_at_idx').on(table.createdAt),
]);

/**
 * 9. Incidents
 * Satisfies Task 9: assignment, priority, investigation_notes, containment, resolution, false_positive
 */
export const incidents = pgTable('incidents', {
  id: text('id').primaryKey(), // UUID or INC-XXXX
  incidentId: text('incident_id').notNull().unique(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  severity: text('severity').notNull(),
  priority: text('priority').notNull(),
  status: text('status').notNull().default('NEW'), // 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE'
  riskScore: doublePrecision('risk_score').notNull(),
  assignee: text('assignee'),
  primaryIp: text('primary_ip'),
  affectedHost: text('affected_host'),
  alertIds: jsonb('alert_ids').notNull().$type<string[]>(),
  correlationIds: jsonb('correlation_ids').notNull().$type<string[]>(),
  mitreTechniques: jsonb('mitre_techniques').$type<string[]>(),
  investigationNotes: jsonb('investigation_notes').default([]).notNull(),
  timeline: jsonb('timeline').default([]).notNull(),
  containmentStatus: text('containment_status'),
  containedAt: timestamp('contained_at', { withTimezone: true }),
  resolvedAt: timestamp('resolved_at', { withTimezone: true }),
  resolutionSummary: text('resolution_summary'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  uniqueIndex('incidents_incident_id_idx').on(table.incidentId),
  index('incidents_status_idx').on(table.status),
  index('incidents_priority_idx').on(table.priority),
  index('incidents_created_at_idx').on(table.createdAt),
]);

/**
 * 10. Incident State History / Transitions
 * Satisfies Task 8 & Task 9: Every state transition must create an incident-history/audit record
 */
export const incidentHistory = pgTable('incident_history', {
  id: text('id').primaryKey(), // UUID
  incidentId: text('incident_id').notNull().references(() => incidents.incidentId, { onDelete: 'cascade' }),
  previousStatus: text('previous_status'),
  newStatus: text('new_status').notNull(),
  action: text('action').notNull(),
  actor: text('actor').notNull(),
  reason: text('reason'),
  details: text('details').notNull(),
  timestamp: timestamp('timestamp', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('incident_history_incident_id_idx').on(table.incidentId),
  index('incident_history_timestamp_idx').on(table.timestamp),
]);

/**
 * 11. Audit Logs
 * Satisfies Task 11: GET /api/audit
 */
export const auditLogs = pgTable('audit_logs', {
  id: text('id').primaryKey(), // UUID
  timestamp: timestamp('timestamp', { withTimezone: true }).defaultNow().notNull(),
  action: text('action').notNull(),
  entityType: text('entity_type').notNull(), // 'ALERT' | 'INCIDENT' | 'EVENT' | 'DETECTION' | 'CONFIG'
  entityId: text('entity_id').notNull(),
  actor: text('actor').notNull(),
  details: text('details').notNull(),
  previousValue: text('previous_value'),
  newValue: text('new_value'),
  metadata: jsonb('metadata'),
}, (table) => [
  index('audit_logs_timestamp_idx').on(table.timestamp),
  index('audit_logs_entity_type_idx').on(table.entityType),
  index('audit_logs_entity_id_idx').on(table.entityId),
]);

/**
 * 12. Reports Metadata
 * Satisfies Task 10: report_id, report_type, incident/correlation references, generation_timestamp, generated_by, report_status
 */
export const reports = pgTable('reports', {
  id: text('id').primaryKey(), // UUID or REP-XXXX
  reportId: text('report_id').notNull().unique(),
  reportType: text('report_type').notNull(), // 'EXECUTIVE_SUMMARY' | 'INCIDENT_DOSSIER' | 'THREAT_INTEL' | 'COMPLIANCE'
  title: text('title').notNull(),
  timeRange: text('time_range').notNull(),
  generatedBy: text('generated_by').notNull(),
  status: text('status').default('COMPLETED').notNull(),
  incidentReferences: jsonb('incident_references').$type<string[]>(),
  correlationReferences: jsonb('correlation_references').$type<string[]>(),
  summaryFigures: jsonb('summary_figures'),
  generatedAt: timestamp('generated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  uniqueIndex('reports_report_id_idx').on(table.reportId),
  index('reports_generated_at_idx').on(table.generatedAt),
]);

// -------------------------------------------------------------
// Drizzle Relations
// -------------------------------------------------------------
export const rawEventsRelations = relations(rawEvents, ({ many }) => ({
  findings: many(securityFindings),
  detections: many(detections),
}));

export const securityFindingsRelations = relations(securityFindings, ({ one }) => ({
  event: one(rawEvents, {
    fields: [securityFindings.eventId],
    references: [rawEvents.id],
  }),
}));

export const detectionsRelations = relations(detections, ({ one }) => ({
  event: one(rawEvents, {
    fields: [detections.eventId],
    references: [rawEvents.id],
  }),
}));

export const alertsRelations = relations(alerts, ({ one }) => ({
  riskAssessment: one(riskAssessments, {
    fields: [alerts.riskAssessmentId],
    references: [riskAssessments.id],
  }),
  correlation: one(correlations, {
    fields: [alerts.correlationId],
    references: [correlations.id],
  }),
}));

export const incidentsRelations = relations(incidents, ({ many }) => ({
  history: many(incidentHistory),
}));

export const incidentHistoryRelations = relations(incidentHistory, ({ one }) => ({
  incident: one(incidents, {
    fields: [incidentHistory.incidentId],
    references: [incidents.incidentId],
  }),
}));
