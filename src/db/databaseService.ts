import { db, isDbConfigured } from './index.ts';
import {
  rawEvents,
  securityFindings,
  modelRegistry,
  detections,
  correlations,
  riskAssessments,
  alerts,
  incidents,
  incidentHistory,
  auditLogs,
  reports,
  users
} from './schema.ts';
import { eq, desc, inArray, sql } from 'drizzle-orm';
import crypto from 'crypto';

/**
 * Deterministic Content Hash (SHA-256) for deduplication
 */
export function generateContentHash(event: {
  source: string;
  eventType: string;
  rawPayload?: string;
  sourceIp?: string;
  destinationIp?: string;
  timestamp?: string;
}): string {
  const normStr = `${event.source || ''}|${event.eventType || ''}|${event.sourceIp || ''}|${event.destinationIp || ''}|${event.timestamp || ''}|${event.rawPayload || ''}`;
  return crypto.createHash('sha256').update(normStr).digest('hex');
}

export class DatabaseService {
  /**
   * Health Check: Distinguishes DATABASE_CONNECTED vs DATABASE_UNAVAILABLE
   */
  async checkConnection(): Promise<{ status: string; connected: boolean; details?: string }> {
    if (!isDbConfigured()) {
      return { status: 'DATABASE_UNAVAILABLE', connected: false, details: 'SQL environment variables missing.' };
    }
    try {
      await db.execute(sql`SELECT 1 as ping`);
      return { status: 'DATABASE_CONNECTED', connected: true };
    } catch (err: any) {
      console.error('[DatabaseService] Connection check failure:', err);
      return { status: 'DATABASE_UNAVAILABLE', connected: false, details: err.message || 'Failed connecting to database' };
    }
  }

  // ==========================================
  // 1. RAW EVENTS & DEDUPLICATION (Task 3)
  // ==========================================
  async insertRawEvent(eventData: {
    id?: string;
    source: string;
    eventType: string;
    rawPayload: string;
    normalizedFields: Record<string, any>;
    eventTimestamp?: Date | string;
    sourceIp?: string;
    destinationIp?: string;
    host?: string;
    username?: string;
    severity?: string;
    batchId?: string;
    isTestEvent?: boolean;
  }) {
    const id = eventData.id || `EVT-${crypto.randomUUID()}`;
    const contentHash = generateContentHash({
      source: eventData.source,
      eventType: eventData.eventType,
      rawPayload: eventData.rawPayload,
      sourceIp: eventData.sourceIp,
      destinationIp: eventData.destinationIp,
      timestamp: eventData.eventTimestamp ? new Date(eventData.eventTimestamp).toISOString() : undefined
    });

    const eventDate = eventData.eventTimestamp ? new Date(eventData.eventTimestamp) : new Date();

    try {
      const inserted = await db
        .insert(rawEvents)
        .values({
          id,
          contentHash,
          eventTimestamp: eventDate,
          source: eventData.source,
          eventType: eventData.eventType,
          rawPayload: eventData.rawPayload,
          normalizedFields: eventData.normalizedFields,
          sourceIp: eventData.sourceIp,
          destinationIp: eventData.destinationIp,
          host: eventData.host,
          username: eventData.username,
          severity: eventData.severity || 'LOW',
          batchId: eventData.batchId,
          isTestEvent: Boolean(eventData.isTestEvent),
        })
        .onConflictDoNothing({ target: rawEvents.contentHash })
        .returning();

      if (inserted.length > 0) {
        return { event: inserted[0], isDuplicate: false };
      }

      // If already existed, fetch existing record
      const existing = await db.select().from(rawEvents).where(eq(rawEvents.contentHash, contentHash)).limit(1);
      return { event: existing[0], isDuplicate: true };
    } catch (err: any) {
      console.error('[DatabaseService] Insert raw event failed:', err);
      throw new Error('Database operation failed: insertRawEvent', { cause: err });
    }
  }

  async getEvents(limit = 100, offset = 0) {
    try {
      return await db
        .select()
        .from(rawEvents)
        .orderBy(desc(rawEvents.eventTimestamp))
        .limit(limit)
        .offset(offset);
    } catch (err: any) {
      console.error('[DatabaseService] getEvents failed:', err);
      throw new Error('Database operation failed: getEvents', { cause: err });
    }
  }

  async getEventById(id: string) {
    try {
      const rows = await db.select().from(rawEvents).where(eq(rawEvents.id, id)).limit(1);
      return rows[0] || null;
    } catch (err: any) {
      console.error('[DatabaseService] getEventById failed:', err);
      throw new Error('Database operation failed: getEventById', { cause: err });
    }
  }

  // ==========================================
  // 2. SECURITY FINDINGS (Task 5)
  // ==========================================
  async insertFinding(finding: {
    id?: string;
    eventId: string;
    agentType: string;
    threatType: string;
    severity: string;
    confidence: number;
    evidence: string[];
    indicators: string[];
    mitreTechnique?: string;
    mitreTactic?: string;
    timestamp?: Date | string;
    metadata?: Record<string, any>;
  }) {
    const id = finding.id || `FIND-${crypto.randomUUID()}`;
    const ts = finding.timestamp ? new Date(finding.timestamp) : new Date();

    try {
      const inserted = await db
        .insert(securityFindings)
        .values({
          id,
          eventId: finding.eventId,
          agentType: finding.agentType,
          threatType: finding.threatType,
          severity: finding.severity,
          confidence: finding.confidence,
          evidence: finding.evidence || [],
          indicators: finding.indicators || [],
          mitreTechnique: finding.mitreTechnique,
          mitreTactic: finding.mitreTactic,
          timestamp: ts,
          metadata: finding.metadata,
        })
        .returning();
      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertFinding failed:', err);
      throw new Error('Database operation failed: insertFinding', { cause: err });
    }
  }

  async getFindingsByEventId(eventId: string) {
    try {
      return await db.select().from(securityFindings).where(eq(securityFindings.eventId, eventId));
    } catch (err: any) {
      console.error('[DatabaseService] getFindingsByEventId failed:', err);
      throw new Error('Database operation failed: getFindingsByEventId', { cause: err });
    }
  }

  // ==========================================
  // 3. ML DETECTIONS (Task 4)
  // ==========================================
  async insertDetection(det: {
    id?: string;
    eventId: string;
    modelId: string;
    modelVersion: string;
    featureSchemaVersion?: string;
    prediction: string;
    predictedClass: string;
    confidence: number;
    classProbabilities: Record<string, number>;
    anomalyScore?: number | null;
    anomalyFlag?: boolean | null;
    anomalyLabel?: string | null;
    featureSummary?: Record<string, any>;
    importantContributingFeatures?: any[];
    inferenceTimestamp?: Date | string;
  }) {
    const id = det.id || `DET-${crypto.randomUUID()}`;
    const infTs = det.inferenceTimestamp ? new Date(det.inferenceTimestamp) : new Date();

    try {
      const inserted = await db
        .insert(detections)
        .values({
          id,
          eventId: det.eventId,
          modelId: det.modelId,
          modelVersion: det.modelVersion,
          featureSchemaVersion: det.featureSchemaVersion || 'cicids2017-v1',
          prediction: det.prediction,
          predictedClass: det.predictedClass,
          confidence: det.confidence,
          classProbabilities: det.classProbabilities,
          anomalyScore: det.anomalyScore ?? null,
          anomalyFlag: det.anomalyFlag ?? null,
          anomalyLabel: det.anomalyLabel ?? null,
          featureSummary: det.featureSummary,
          importantContributingFeatures: det.importantContributingFeatures,
          inferenceTimestamp: infTs,
        })
        .returning();
      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertDetection failed:', err);
      throw new Error('Database operation failed: insertDetection', { cause: err });
    }
  }

  async getDetections(limit = 100, offset = 0) {
    try {
      return await db
        .select()
        .from(detections)
        .orderBy(desc(detections.inferenceTimestamp))
        .limit(limit)
        .offset(offset);
    } catch (err: any) {
      console.error('[DatabaseService] getDetections failed:', err);
      throw new Error('Database operation failed: getDetections', { cause: err });
    }
  }

  // ==========================================
  // 4. CORRELATIONS & RISK (Tasks 6 & 7)
  // ==========================================
  async insertCorrelation(corr: {
    id?: string;
    relatedEventIds: string[];
    relatedFindingIds: string[];
    correlationRule: string;
    ruleCategory?: string;
    entities: Record<string, any>;
    timeWindowStart?: Date | string;
    timeWindowEnd?: Date | string;
    attackStage?: string;
    mitreTechniques?: string[];
    correlationScore: number;
    correlationStrength: string;
    summary: string;
  }) {
    const id = corr.id || `CORR-${crypto.randomUUID()}`;
    try {
      const inserted = await db
        .insert(correlations)
        .values({
          id,
          relatedEventIds: corr.relatedEventIds,
          relatedFindingIds: corr.relatedFindingIds,
          correlationRule: corr.correlationRule,
          ruleCategory: corr.ruleCategory,
          entities: corr.entities,
          timeWindowStart: corr.timeWindowStart ? new Date(corr.timeWindowStart) : null,
          timeWindowEnd: corr.timeWindowEnd ? new Date(corr.timeWindowEnd) : null,
          attackStage: corr.attackStage,
          mitreTechniques: corr.mitreTechniques,
          correlationScore: corr.correlationScore,
          correlationStrength: corr.correlationStrength,
          summary: corr.summary,
        })
        .returning();
      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertCorrelation failed:', err);
      throw new Error('Database operation failed: insertCorrelation', { cause: err });
    }
  }

  async insertRiskAssessment(risk: {
    id?: string;
    correlationId?: string;
    eventId?: string;
    riskScore: number;
    riskBand: string;
    priority: string;
    factorValues: Record<string, any>;
    factorWeights: Record<string, any>;
    contributions: Record<string, any>;
    calculationTimestamp?: Date | string;
  }) {
    const id = risk.id || `RISK-${crypto.randomUUID()}`;
    const calcTs = risk.calculationTimestamp ? new Date(risk.calculationTimestamp) : new Date();
    try {
      const inserted = await db
        .insert(riskAssessments)
        .values({
          id,
          correlationId: risk.correlationId || null,
          eventId: risk.eventId || null,
          riskScore: risk.riskScore,
          riskBand: risk.riskBand,
          priority: risk.priority,
          factorValues: risk.factorValues,
          factorWeights: risk.factorWeights,
          contributions: risk.contributions,
          calculationTimestamp: calcTs,
        })
        .returning();
      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertRiskAssessment failed:', err);
      throw new Error('Database operation failed: insertRiskAssessment', { cause: err });
    }
  }

  // ==========================================
  // 5. ALERTS & LIFECYCLE (Task 8)
  // ==========================================
  async insertAlert(alertData: {
    id?: string;
    alertId?: string;
    title: string;
    description: string;
    alertType: string;
    severity: string;
    status?: string;
    riskScore: number;
    priority: string;
    riskAssessmentId?: string;
    correlationId?: string;
    sourceIp?: string;
    destinationIp?: string;
    affectedHost?: string;
    affectedUser?: string;
    mitreTechniques?: string[];
    evidence?: string[];
    notificationStatus?: string;
    burstCount?: number;
  }) {
    const id = alertData.id || alertData.alertId || `ALT-${Date.now().toString().slice(-6)}`;
    const alertId = alertData.alertId || id;
    try {
      const inserted = await db
        .insert(alerts)
        .values({
          id,
          alertId,
          title: alertData.title,
          description: alertData.description,
          alertType: alertData.alertType,
          severity: alertData.severity,
          status: alertData.status || 'NEW',
          riskScore: alertData.riskScore,
          priority: alertData.priority,
          riskAssessmentId: alertData.riskAssessmentId || null,
          correlationId: alertData.correlationId || null,
          sourceIp: alertData.sourceIp,
          destinationIp: alertData.destinationIp,
          affectedHost: alertData.affectedHost,
          affectedUser: alertData.affectedUser,
          mitreTechniques: alertData.mitreTechniques,
          evidence: alertData.evidence,
          notificationStatus: alertData.notificationStatus || 'PENDING',
          burstCount: alertData.burstCount || 1,
        })
        .onConflictDoUpdate({
          target: alerts.alertId,
          set: {
            burstCount: sql`${alerts.burstCount} + 1`,
            updatedAt: new Date(),
          },
        })
        .returning();

      // Automatically record audit log for alert creation
      await this.insertAuditLog({
        action: 'ALERT_CREATED',
        entityType: 'ALERT',
        entityId: alertId,
        actor: 'SYSTEM',
        details: `Alert ${alertId} created: ${alertData.title} (${alertData.severity})`,
        newValue: alertData.status || 'NEW'
      });

      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertAlert failed:', err);
      throw new Error('Database operation failed: insertAlert', { cause: err });
    }
  }

  async getAlerts(limit = 100, offset = 0) {
    try {
      return await db
        .select()
        .from(alerts)
        .orderBy(desc(alerts.createdAt))
        .limit(limit)
        .offset(offset);
    } catch (err: any) {
      console.error('[DatabaseService] getAlerts failed:', err);
      throw new Error('Database operation failed: getAlerts', { cause: err });
    }
  }

  async getAlertById(alertId: string) {
    try {
      const rows = await db.select().from(alerts).where(eq(alerts.alertId, alertId)).limit(1);
      return rows[0] || null;
    } catch (err: any) {
      console.error('[DatabaseService] getAlertById failed:', err);
      throw new Error('Database operation failed: getAlertById', { cause: err });
    }
  }

  async updateAlertStatus(alertId: string, newStatus: string, actor = 'ANALYST', reason?: string) {
    try {
      const existing = await this.getAlertById(alertId);
      if (!existing) {
        return null;
      }
      const previousStatus = existing.status;

      const updated = await db
        .update(alerts)
        .set({
          status: newStatus,
          updatedAt: new Date(),
        })
        .where(eq(alerts.alertId, alertId))
        .returning();

      // Record audit log
      await this.insertAuditLog({
        action: newStatus === 'FALSE_POSITIVE' ? 'FALSE_POSITIVE_MARKED' : 'STATUS_CHANGED',
        entityType: 'ALERT',
        entityId: alertId,
        actor,
        details: `Alert ${alertId} status transitioned from ${previousStatus} to ${newStatus}${reason ? ` (${reason})` : ''}`,
        previousValue: previousStatus,
        newValue: newStatus,
      });

      return updated[0];
    } catch (err: any) {
      console.error('[DatabaseService] updateAlertStatus failed:', err);
      throw new Error('Database operation failed: updateAlertStatus', { cause: err });
    }
  }

  // ==========================================
  // 6. INCIDENTS & HISTORY (Task 9)
  // ==========================================
  async insertIncident(incData: {
    id?: string;
    incidentId?: string;
    title: string;
    description: string;
    severity: string;
    priority: string;
    status?: string;
    riskScore: number;
    assignee?: string;
    primaryIp?: string;
    affectedHost?: string;
    alertIds: string[];
    correlationIds: string[];
    mitreTechniques?: string[];
    investigationNotes?: any[];
    timeline?: any[];
  }) {
    const id = incData.id || incData.incidentId || `INC-${Date.now().toString().slice(-6)}`;
    const incidentId = incData.incidentId || id;

    try {
      const inserted = await db
        .insert(incidents)
        .values({
          id,
          incidentId,
          title: incData.title,
          description: incData.description,
          severity: incData.severity,
          priority: incData.priority,
          status: incData.status || 'NEW',
          riskScore: incData.riskScore,
          assignee: incData.assignee || 'Unassigned',
          primaryIp: incData.primaryIp,
          affectedHost: incData.affectedHost,
          alertIds: incData.alertIds || [],
          correlationIds: incData.correlationIds || [],
          mitreTechniques: incData.mitreTechniques || [],
          investigationNotes: incData.investigationNotes || [],
          timeline: incData.timeline || [],
        })
        .onConflictDoUpdate({
          target: incidents.incidentId,
          set: {
            title: incData.title,
            riskScore: incData.riskScore,
            updatedAt: new Date(),
          },
        })
        .returning();

      // State transition / history record
      await this.insertIncidentHistory({
        incidentId,
        previousStatus: null,
        newStatus: incData.status || 'NEW',
        action: 'INCIDENT_CREATED',
        actor: 'SYSTEM',
        details: `Incident ${incidentId} created: ${incData.title}`,
      });

      // Audit log
      await this.insertAuditLog({
        action: 'INCIDENT_CREATED',
        entityType: 'INCIDENT',
        entityId: incidentId,
        actor: 'SYSTEM',
        details: `Incident ${incidentId} created`,
        newValue: incData.status || 'NEW',
      });

      return inserted[0];
    } catch (err: any) {
      console.error('[DatabaseService] insertIncident failed:', err);
      throw new Error('Database operation failed: insertIncident', { cause: err });
    }
  }

  async getIncidents(limit = 100, offset = 0) {
    try {
      return await db
        .select()
        .from(incidents)
        .orderBy(desc(incidents.createdAt))
        .limit(limit)
        .offset(offset);
    } catch (err: any) {
      console.error('[DatabaseService] getIncidents failed:', err);
      throw new Error('Database operation failed: getIncidents', { cause: err });
    }
  }

  async getIncidentById(incidentId: string) {
    try {
      const rows = await db.select().from(incidents).where(eq(incidents.incidentId, incidentId)).limit(1);
      return rows[0] || null;
    } catch (err: any) {
      console.error('[DatabaseService] getIncidentById failed:', err);
      throw new Error('Database operation failed: getIncidentById', { cause: err });
    }
  }

  async updateIncident(
    incidentId: string,
    updates: {
      status?: string;
      assignee?: string;
      priority?: string;
      containmentStatus?: string;
      resolutionSummary?: string;
      newNote?: { author: string; note: string };
      actor?: string;
      reason?: string;
    }
  ) {
    const actor = updates.actor || 'ANALYST';
    try {
      const existing = await this.getIncidentById(incidentId);
      if (!existing) return null;

      const patchData: Record<string, any> = { updatedAt: new Date() };

      if (updates.status && updates.status !== existing.status) {
        patchData.status = updates.status;
        if (updates.status === 'CONTAINED') {
          patchData.containedAt = new Date();
          patchData.containmentStatus = 'CONTAINED';
        }
        if (updates.status === 'RESOLVED') {
          patchData.resolvedAt = new Date();
        }

        // Record state transition history (Task 8 & 9)
        await this.insertIncidentHistory({
          incidentId,
          previousStatus: existing.status,
          newStatus: updates.status,
          action: 'STATUS_CHANGED',
          actor,
          reason: updates.reason,
          details: `Status changed from ${existing.status} to ${updates.status}${updates.reason ? ` (${updates.reason})` : ''}`,
        });

        await this.insertAuditLog({
          action: updates.status === 'RESOLVED' ? 'INCIDENT_RESOLVED' : updates.status === 'FALSE_POSITIVE' ? 'FALSE_POSITIVE_MARKED' : 'STATUS_CHANGED',
          entityType: 'INCIDENT',
          entityId: incidentId,
          actor,
          details: `Incident ${incidentId} transitioned to ${updates.status}`,
          previousValue: existing.status,
          newValue: updates.status,
        });
      }

      if (updates.assignee !== undefined) {
        patchData.assignee = updates.assignee;
      }
      if (updates.priority !== undefined) {
        patchData.priority = updates.priority;
      }
      if (updates.containmentStatus !== undefined) {
        patchData.containmentStatus = updates.containmentStatus;
      }
      if (updates.resolutionSummary !== undefined) {
        patchData.resolutionSummary = updates.resolutionSummary;
      }

      if (updates.newNote) {
        const notes = Array.isArray(existing.investigationNotes) ? [...existing.investigationNotes] : [];
        const noteEntry = {
          id: `note-${Date.now()}`,
          timestamp: new Date().toISOString(),
          author: updates.newNote.author,
          note: updates.newNote.note,
        };
        notes.push(noteEntry);
        patchData.investigationNotes = notes;

        await this.insertAuditLog({
          action: 'ANALYST_NOTE_ADDED',
          entityType: 'INCIDENT',
          entityId: incidentId,
          actor: updates.newNote.author,
          details: `Note added to ${incidentId}: "${updates.newNote.note.slice(0, 50)}..."`,
        });
      }

      const updated = await db
        .update(incidents)
        .set(patchData)
        .where(eq(incidents.incidentId, incidentId))
        .returning();

      return updated[0];
    } catch (err: any) {
      console.error('[DatabaseService] updateIncident failed:', err);
      throw new Error('Database operation failed: updateIncident', { cause: err });
    }
  }

  async insertIncidentHistory(entry: {
    incidentId: string;
    previousStatus: string | null;
    newStatus: string;
    action: string;
    actor: string;
    reason?: string;
    details: string;
  }) {
    const id = `HIST-${crypto.randomUUID()}`;
    try {
      return await db
        .insert(incidentHistory)
        .values({
          id,
          incidentId: entry.incidentId,
          previousStatus: entry.previousStatus,
          newStatus: entry.newStatus,
          action: entry.action,
          actor: entry.actor,
          reason: entry.reason,
          details: entry.details,
        })
        .returning();
    } catch (err: any) {
      console.error('[DatabaseService] insertIncidentHistory failed:', err);
      throw new Error('Database operation failed: insertIncidentHistory', { cause: err });
    }
  }

  async getIncidentHistory(incidentId: string) {
    try {
      return await db
        .select()
        .from(incidentHistory)
        .where(eq(incidentHistory.incidentId, incidentId))
        .orderBy(desc(incidentHistory.timestamp));
    } catch (err: any) {
      console.error('[DatabaseService] getIncidentHistory failed:', err);
      throw new Error('Database operation failed: getIncidentHistory', { cause: err });
    }
  }

  // ==========================================
  // 7. AUDIT LOGS (Task 11)
  // ==========================================
  async insertAuditLog(log: {
    action: string;
    entityType: string;
    entityId: string;
    actor: string;
    details: string;
    previousValue?: string;
    newValue?: string;
    metadata?: Record<string, any>;
  }) {
    const id = `AUD-${crypto.randomUUID()}`;
    try {
      return await db
        .insert(auditLogs)
        .values({
          id,
          action: log.action,
          entityType: log.entityType,
          entityId: log.entityId,
          actor: log.actor,
          details: log.details,
          previousValue: log.previousValue,
          newValue: log.newValue,
          metadata: log.metadata,
        })
        .returning();
    } catch (err: any) {
      console.error('[DatabaseService] insertAuditLog failed:', err);
      // Audit log failures shouldn't completely crash operational flow
      return null;
    }
  }

  async getAuditLogs(limit = 100, offset = 0) {
    try {
      return await db
        .select()
        .from(auditLogs)
        .orderBy(desc(auditLogs.timestamp))
        .limit(limit)
        .offset(offset);
    } catch (err: any) {
      console.error('[DatabaseService] getAuditLogs failed:', err);
      throw new Error('Database operation failed: getAuditLogs', { cause: err });
    }
  }

  // ==========================================
  // 8. REPORTS METADATA (Task 10)
  // ==========================================
  async insertReport(rep: {
    reportId?: string;
    reportType: string;
    title: string;
    timeRange: string;
    generatedBy: string;
    status?: string;
    incidentReferences?: string[];
    correlationReferences?: string[];
    summaryFigures?: Record<string, any>;
  }) {
    const reportId = rep.reportId || `REP-${Date.now().toString().slice(-6)}`;
    const id = `REP-UUID-${crypto.randomUUID()}`;

    try {
      return await db
        .insert(reports)
        .values({
          id,
          reportId,
          reportType: rep.reportType,
          title: rep.title,
          timeRange: rep.timeRange,
          generatedBy: rep.generatedBy,
          status: rep.status || 'COMPLETED',
          incidentReferences: rep.incidentReferences,
          correlationReferences: rep.correlationReferences,
          summaryFigures: rep.summaryFigures,
        })
        .returning();
    } catch (err: any) {
      console.error('[DatabaseService] insertReport failed:', err);
      throw new Error('Database operation failed: insertReport', { cause: err });
    }
  }

  async getReports(limit = 50) {
    try {
      return await db
        .select()
        .from(reports)
        .orderBy(desc(reports.generatedAt))
        .limit(limit);
    } catch (err: any) {
      console.error('[DatabaseService] getReports failed:', err);
      throw new Error('Database operation failed: getReports', { cause: err });
    }
  }

  // ==========================================
  // 9. MODEL REGISTRY PERSISTENCE (Task 2 & 4)
  // ==========================================
  async upsertModelRegistry(model: {
    id: string;
    modelType: string;
    modelVersion: string;
    featureSchemaVersion?: string;
    algorithm: string;
    trainingDataset?: string;
    trainingTimestamp?: Date | string;
    trainingMetrics?: Record<string, any>;
    featureNames?: string[];
    classes?: string[];
    status?: string;
    isTestData?: boolean;
  }) {
    try {
      return await db
        .insert(modelRegistry)
        .values({
          id: model.id,
          modelType: model.modelType,
          modelVersion: model.modelVersion,
          featureSchemaVersion: model.featureSchemaVersion || 'cicids2017-v1',
          algorithm: model.algorithm,
          trainingDataset: model.trainingDataset,
          trainingTimestamp: model.trainingTimestamp ? new Date(model.trainingTimestamp) : null,
          trainingMetrics: model.trainingMetrics,
          featureNames: model.featureNames,
          classes: model.classes,
          status: model.status || 'READY',
          isTestData: Boolean(model.isTestData),
        })
        .onConflictDoUpdate({
          target: modelRegistry.id,
          set: {
            modelVersion: model.modelVersion,
            trainingMetrics: model.trainingMetrics,
            status: model.status || 'READY',
          },
        })
        .returning();
    } catch (err: any) {
      console.error('[DatabaseService] upsertModelRegistry failed:', err);
      throw new Error('Database operation failed: upsertModelRegistry', { cause: err });
    }
  }

  async getRegisteredModels() {
    try {
      return await db.select().from(modelRegistry).orderBy(desc(modelRegistry.createdAt));
    } catch (err: any) {
      console.error('[DatabaseService] getRegisteredModels failed:', err);
      throw new Error('Database operation failed: getRegisteredModels', { cause: err });
    }
  }
}

export const databaseService = new DatabaseService();
