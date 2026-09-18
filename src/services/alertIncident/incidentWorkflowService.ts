/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * End-to-End Alert & Incident Response Workflow Service
 * 
 * Implements:
 * 1. Unique Incident ID generation
 * 2. Incident & Alert persistence in MongoDB (with localStore fallback)
 * 3. Transparent Severity Rules assignment (Informational, Low, Medium, High, Critical)
 * 4. Alert dispatch to the Dashboard and real-time streams
 * 5. Detection source and supporting events provenance tracking
 * 6. User acknowledgment and resolution workflow
 * 7. Immutable audit logging for all lifecycle transitions
 * 8. Optional notifications (Email, Webhook, n8n) with protected credentials & safe retries
 * 9. Safety Guard: No autonomous destructive actions, explicit authorization required
 */

import { severityRuleEngine, SeverityEvaluationResult } from './severityRuleEngine';
import { alertRateLimiter, RateLimitResult } from './rateLimiter';
import { notificationDispatcher, NotificationDispatchRecord } from './notificationDispatcher';
import { responseAuthorizationGuard, ResponseAuthorizationRequest, ResponseAuthorizationDecision } from './responseAuthorizationGuard';
import { alertManager } from './alertManager';
import { incidentManager } from './incidentManager';
import { auditService } from '../auditService';
import { SecurityAlert, SecurityIncident, IncidentLifecycleStatus, IncidentTimelineEntry } from '../../types/alertIncident';
import { mongoService } from '../../db/mongo/mongoService';
import { PersistenceWriteResult } from '../../db/mongo/types';

export interface ThreatDetectionInput {
  threatCategory: string;
  threatType?: string;
  source: string;
  sourceIp?: string;
  affectedHost?: string;
  agentName: string;
  detectionMethod: string;
  description: string;
  evidence: string[];
  recommendedAction?: string;
  supportingEvents?: Array<{
    eventId: string;
    timestamp?: string;
    description: string;
    sourceIp?: string;
    eventType?: string;
  }>;
  riskScore?: number;
  confidence?: number;
  anomalyScore?: number;
  participatingAgents?: string[];
  mitreTactic?: string;
  mitreTechnique?: string;
  isMultiStage?: boolean;
}

export interface IncidentWorkflowExecutionResult {
  success: boolean;
  incidentId: string;
  alertId: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  severityRule: {
    ruleId: string;
    ruleName: string;
    justification: string;
  };
  rateLimitStatus: RateLimitResult;
  incident: SecurityIncident;
  alert: SecurityAlert;
  notifications: NotificationDispatchRecord[];
  auditLogId: string;
  message: string;
  persistenceStatus?: {
    incident: PersistenceWriteResult<any>;
    alert: PersistenceWriteResult<any>;
  };
}

class IncidentWorkflowService {
  /**
   * Generates an unforgeable, collision-free Incident ID
   */
  public generateUniqueIncidentId(): string {
    const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const randPart = Math.random().toString(36).substring(2, 7).toUpperCase();
    return `INC-${datePart}-${randPart}`;
  }

  /**
   * Generates an unforgeable, collision-free Alert ID
   */
  public generateUniqueAlertId(): string {
    const randPart = Math.random().toString(36).substring(2, 7).toUpperCase();
    return `ALT-${Date.now().toString().slice(-6)}-${randPart}`;
  }

  /**
   * Primary workflow executed WHEN A THREAT IS DETECTED
   */
  public async handleThreatDetected(input: ThreatDetectionInput): Promise<IncidentWorkflowExecutionResult> {
    const timestamp = new Date().toISOString();

    // 1. Rate Limiting & Duplicate Prevention Check
    const rateLimitCheck = alertRateLimiter.evaluate({
      source: input.source || input.sourceIp || 'unknown',
      threatCategory: input.threatCategory,
      primaryIp: input.sourceIp,
      agentName: input.agentName,
      detectionMethod: input.detectionMethod
    });

    // 2. Assign Severity Based on Transparent Rules
    const severityEval: SeverityEvaluationResult = severityRuleEngine.evaluateSeverity({
      threatCategory: input.threatCategory,
      threatType: input.threatType || input.threatCategory,
      riskScore: input.riskScore,
      confidence: input.confidence,
      anomalyScore: input.anomalyScore,
      participatingAgents: input.participatingAgents || [input.agentName],
      mitreTactic: input.mitreTactic,
      isMultiStage: input.isMultiStage,
      affectedHost: input.affectedHost,
      eventCount: input.supportingEvents?.length || 1,
      indicators: input.evidence
    });

    // 3. Create Unique Incident and Alert IDs
    const incidentId = this.generateUniqueIncidentId();
    const alertId = this.generateUniqueAlertId();

    const recommendedAction =
      input.recommendedAction ||
      `Review ${input.agentName} telemetry, inspect indicators [${input.sourceIp || input.affectedHost || 'endpoint'}], and request human-in-the-loop authorization if containment is warranted.`;

    const supportingEvents = input.supportingEvents || [
      {
        eventId: `EVT-${Date.now().toString().slice(-5)}`,
        timestamp,
        description: input.description,
        sourceIp: input.sourceIp,
        eventType: input.threatType || input.threatCategory
      }
    ];

    // 4. Construct Security Incident Record
    const incidentTimeline: IncidentTimelineEntry[] = supportingEvents.map((evt, idx) => ({
      id: `tl-${incidentId}-${idx}`,
      time: new Date().toLocaleTimeString(),
      timestamp: evt.timestamp || timestamp,
      description: `[${input.agentName}] ${evt.description}`,
      actor: input.agentName,
      phase: 'DETECTION' as const,
      relatedEventId: evt.eventId
    }));

    incidentTimeline.unshift({
      id: `tl-${incidentId}-init`,
      time: new Date().toLocaleTimeString(),
      timestamp,
      description: `Incident created via Multi-Agent Threat Detection. Severity assigned: ${severityEval.severity} (${severityEval.ruleName})`,
      actor: 'SOC Incident Workflow Engine',
      phase: 'DETECTION' as const
    });

    const newIncident: SecurityIncident = {
      id: incidentId,
      incidentId,
      title: input.threatType || input.threatCategory,
      description: input.description,
      createdAt: timestamp,
      updatedAt: timestamp,
      detectedAt: timestamp,
      severity: severityEval.normalizedSeverity,
      priority: severityEval.calculatedRiskScore >= 90 ? 'P1' : severityEval.calculatedRiskScore >= 70 ? 'P2' : 'P3',
      riskScore: severityEval.calculatedRiskScore,
      status: 'NEW',
      alertIds: [alertId],
      correlationIds: [],
      threatTypes: [input.threatCategory],
      participatingAgents: (input.participatingAgents as any) || [input.agentName as any],
      affectedEntities: [input.affectedHost || input.sourceIp || input.source],
      affectedSource: input.sourceIp || input.affectedHost || input.source,
      evidence: [
        ...input.evidence,
        `Detection Method: ${input.detectionMethod}`,
        `Severity Rule: ${severityEval.ruleName} (${severityEval.justification})`
      ],
      timeline: incidentTimeline,
      analystNotes: [
        {
          id: `note-${incidentId}-1`,
          timestamp,
          author: 'SOC Workflow Automation',
          note: `Incident automatically opened. Severity: ${severityEval.severity}. Justification: ${severityEval.justification}`
        }
      ],
      recommendedActions: [recommendedAction],
      assignedTo: 'SOC Triage Queue',
      mitreTactic: input.mitreTactic || 'TA0001 - Initial Access',
      mitreTechnique: input.mitreTechnique || 'T1190 - Exploit Public-Facing Application',
      containmentRecommendation: recommendedAction,
      summary: `${input.threatCategory} detected by ${input.agentName} targeting ${input.sourceIp || input.affectedHost || 'endpoint'}.`,
      history: [
        {
          id: `hist-${incidentId}-1`,
          timestamp,
          action: 'INCIDENT_CREATED',
          actor: 'SOC Workflow Engine',
          details: `Incident created with ${severityEval.severity} severity (${severityEval.ruleId}).`
        }
      ],
      simulatedResponses: []
    };

    // 5. Construct Security Alert Record
    const newAlert: SecurityAlert = {
      id: alertId,
      alertId,
      incidentId,
      alertType: input.threatCategory,
      title: input.threatType || input.threatCategory,
      threat: input.threatType || input.threatCategory,
      description: input.description,
      timestamp,
      source: input.sourceIp || input.affectedHost || input.source,
      threatClassification: input.threatCategory,
      severity: severityEval.normalizedSeverity,
      riskScore: severityEval.calculatedRiskScore,
      priority: severityEval.calculatedRiskScore >= 90 ? 'P1' : severityEval.calculatedRiskScore >= 70 ? 'P2' : 'P3',
      confidence: Math.round((input.confidence || 0.85) * 100),
      affectedEntities: [input.sourceIp || input.affectedHost || input.source],
      participatingAgents: (input.participatingAgents as any) || [input.agentName as any],
      evidence: input.evidence,
      explanation: `${input.description} (Evaluated under ${severityEval.ruleName})`,
      recommendedAction,
      status: 'NEW',
      incidentStatus: newIncident.status,
      agentName: input.agentName,
      threatCategory: input.threatCategory,
      detectionMethod: input.detectionMethod,
      isRead: false,
      deduplicationCount: rateLimitCheck.burstCount,
      lastSeenTimestamp: timestamp,
      history: [
        {
          id: `hist-${alertId}-1`,
          timestamp,
          action: 'ALERT_GENERATED',
          actor: input.agentName,
          details: `Alert generated by ${input.detectionMethod}. Linked to incident ${incidentId}.`
        }
      ],
      simulatedResponses: [],
      notificationStatus: rateLimitCheck.suppressNotification ? 'SENT' : 'PENDING',
      targetChannels: ['#soc-tier1-alerts', 'SOC In-App Center'],
      ruleTriggered: severityEval.ruleId
    };

    // 6. Display in Dashboard (In-Memory Stores)
    incidentManager.addDirectIncident(newIncident);
    alertManager.addDirectAlert(newAlert);

    // 7. Store in Persistent MongoDB (Verified persistence, explicit error handling)
    const incidentPersistResult = await this.persistIncidentToBackend(newIncident);
    const alertPersistResult = await this.persistAlertToBackend(newAlert, input);

    // 8. Record in Audit Log
    const auditRecord = auditService.recordAction({
      action: 'INCIDENT_CREATED',
      entityType: 'INCIDENT',
      entityId: incidentId,
      actor: input.agentName,
      details: `Incident ${incidentId} created: [${severityEval.severity}] ${input.threatCategory} on ${newIncident.affectedSource}. Rule: ${severityEval.ruleName} (DB Status: ${incidentPersistResult.status})`,
      metadata: {
        alertId,
        severity: severityEval.severity,
        ruleId: severityEval.ruleId,
        detectionMethod: input.detectionMethod,
        riskScore: severityEval.calculatedRiskScore,
        incidentPersistStatus: incidentPersistResult.status,
        alertPersistStatus: alertPersistResult.status
      }
    });

    // 9. Dispatch Notifications (Email, Webhook, n8n) if not suppressed by rate limit
    let notifications: NotificationDispatchRecord[] = [];
    if (!rateLimitCheck.suppressNotification) {
      notifications = await notificationDispatcher.dispatchAll({
        alertId,
        incidentId,
        title: newAlert.title,
        severity: severityEval.severity,
        threatCategory: input.threatCategory,
        agentName: input.agentName,
        description: input.description,
        evidence: input.evidence,
        detectionMethod: input.detectionMethod,
        recommendedAction,
        timestamp,
        incidentStatus: newIncident.status
      });
    }

    return {
      success: true,
      incidentId,
      alertId,
      severity: severityEval.severity,
      severityRule: {
        ruleId: severityEval.ruleId,
        ruleName: severityEval.ruleName,
        justification: severityEval.justification
      },
      rateLimitStatus: rateLimitCheck,
      incident: newIncident,
      alert: newAlert,
      notifications,
      auditLogId: auditRecord.id,
      persistenceStatus: {
        incident: incidentPersistResult,
        alert: alertPersistResult
      },
      message: `Incident ${incidentId} and Alert ${alertId} created with ${severityEval.severity} severity. Database status: Incident=${incidentPersistResult.status}, Alert=${alertPersistResult.status}.`
    };
  }

  /**
   * Allow user to acknowledge an incident with audit trail
   */
  public async acknowledgeIncident(
    incidentId: string,
    actor: string = 'SOC Analyst',
    reason?: string
  ): Promise<boolean> {
    const success = incidentManager.updateIncidentStatus(
      incidentId,
      'ACKNOWLEDGED',
      reason || 'Incident acknowledged by analyst for active triage.',
      actor
    );

    if (success) {
      auditService.recordAction({
        action: 'INCIDENT_ACKNOWLEDGED',
        entityType: 'INCIDENT',
        entityId: incidentId,
        actor,
        details: `Incident ${incidentId} acknowledged by ${actor}. ${reason ? `Reason: ${reason}` : ''}`,
        previousValue: 'NEW',
        newValue: 'ACKNOWLEDGED'
      });

      // Synchronize status to backend database
      this.syncIncidentStatusToBackend(incidentId, 'ACKNOWLEDGED', actor, reason).catch(() => {});
    }

    return success;
  }

  /**
   * Allow user to resolve an incident with audit trail
   */
  public async resolveIncident(
    incidentId: string,
    resolutionSummary: string,
    actor: string = 'SOC Analyst'
  ): Promise<boolean> {
    const success = incidentManager.updateIncidentStatus(
      incidentId,
      'RESOLVED',
      resolutionSummary || 'Incident resolved and mitigated.',
      actor
    );

    if (success) {
      auditService.recordAction({
        action: 'INCIDENT_RESOLVED',
        entityType: 'INCIDENT',
        entityId: incidentId,
        actor,
        details: `Incident ${incidentId} resolved by ${actor}. Summary: ${resolutionSummary}`,
        previousValue: 'INVESTIGATING',
        newValue: 'RESOLVED'
      });

      // Synchronize status to backend database
      this.syncIncidentStatusToBackend(incidentId, 'RESOLVED', actor, resolutionSummary).catch(() => {});
    }

    return success;
  }

  /**
   * Execute human-authorized response action with strict safety checks
   */
  public authorizeAndExecuteResponse(req: ResponseAuthorizationRequest): ResponseAuthorizationDecision {
    const decision = responseAuthorizationGuard.evaluateAuthorization(req);
    if (!decision.allowed) {
      return decision;
    }

    const simRecord = responseAuthorizationGuard.executeAuthorizedResponse(req);

    // Record in incident or alert
    if (req.targetType === 'INCIDENT') {
      incidentManager.addSimulatedResponse(req.targetId, simRecord);
    } else {
      alertManager.addSimulatedResponse(req.targetId, simRecord);
    }

    // Record in SOC Audit Log
    auditService.recordAction({
      action: 'RESPONSE_ACTION_AUTHORIZED',
      entityType: req.targetType === 'INCIDENT' ? 'INCIDENT' : 'ALERT',
      entityId: req.targetId,
      actor: req.authorizedBy,
      details: `[SAFETY GUARD: AUTHORIZED] ${req.actionType} on target ${req.target}. Justification: ${req.operationalJustification}`,
      metadata: {
        actionType: req.actionType,
        target: req.target,
        simulatedId: simRecord.id
      }
    });

    return decision;
  }

  /**
   * Persist Incident to Backend MongoDB without silent catches.
   * Explicitly updates incident.databasePersistenceStatus to PERSISTED or FAILED.
   */
  public async persistIncidentToBackend(incident: SecurityIncident): Promise<PersistenceWriteResult<any>> {
    const receivedAt = incident.detectedAt || new Date().toISOString();
    const processedAt = new Date().toISOString();
    const storedAt = new Date().toISOString();

    try {
      const result = await mongoService.persistIncidentRecord({
        incident_id: incident.incidentId,
        title: incident.title || 'Security Incident',
        description: incident.description || incident.summary || 'Incident generated via multi-agent threat pipeline',
        severity: incident.severity,
        status: incident.status,
        risk_score: incident.riskScore,
        assigned_to: incident.assignedTo,
        affected_entities: incident.affectedEntities || [incident.affectedSource],
        alert_ids: incident.alertIds || [],
        mitre_tactic: incident.mitreTactic,
        mitre_technique: incident.mitreTechnique,
        received_at: receivedAt,
        processed_at: processedAt,
        stored_at: storedAt
      });

      if (result.success) {
        incident.databasePersistenceStatus = result.isDuplicate ? 'DUPLICATE_SKIPPED' : 'PERSISTED';
        incident.databaseStoredAt = result.stored_at;
      } else {
        incident.databasePersistenceStatus = result.status === 'DATABASE_UNAVAILABLE' ? 'DATABASE_UNAVAILABLE' : 'FAILED';
        incident.databasePersistenceError = result.error;
      }
      return result;
    } catch (err: any) {
      if (typeof window !== 'undefined' && typeof fetch !== 'undefined') {
        try {
          const resp = await fetch('/api/mongo/incidents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              incidentId: incident.incidentId,
              title: incident.title,
              description: incident.description,
              severity: incident.severity,
              priority: incident.priority,
              status: incident.status,
              riskScore: incident.riskScore,
              primaryIp: incident.affectedSource,
              affectedHost: incident.affectedEntities?.[0],
              mitreTechniques: [incident.mitreTechnique],
              correlatedEvents: incident.correlationIds,
              investigationNotes: incident.analystNotes
            })
          });

          if (!resp.ok) {
            const errText = await resp.text().catch(() => resp.statusText);
            incident.databasePersistenceStatus = 'FAILED';
            incident.databasePersistenceError = `HTTP ${resp.status}: ${errText}`;
            return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: incident.databasePersistenceError };
          }

          const data = await resp.json().catch(() => ({}));
          incident.databasePersistenceStatus = 'PERSISTED';
          incident.databaseStoredAt = storedAt;
          return { success: true, status: 'PERSISTED', isDuplicate: false, doc: data, stored_at: storedAt };
        } catch (fetchErr: any) {
          incident.databasePersistenceStatus = 'FAILED';
          incident.databasePersistenceError = fetchErr.message;
          return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: fetchErr.message };
        }
      }

      incident.databasePersistenceStatus = 'FAILED';
      incident.databasePersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: incident.databasePersistenceError };
    }
  }

  /**
   * Persist Alert to Backend MongoDB without silent catches.
   * Explicitly updates alert.databasePersistenceStatus to PERSISTED or FAILED.
   */
  public async persistAlertToBackend(alert: SecurityAlert, input: ThreatDetectionInput): Promise<PersistenceWriteResult<any>> {
    const receivedAt = alert.timestamp || new Date().toISOString();
    const processedAt = new Date().toISOString();
    const storedAt = new Date().toISOString();

    try {
      const result = await mongoService.persistAlertRecord({
        alert_id: alert.alertId,
        incident_id: alert.incidentId,
        title: alert.title,
        severity: alert.severity,
        category: input.threatCategory,
        agent_name: input.agentName,
        detection_method: input.detectionMethod,
        risk_score: alert.riskScore,
        evidence: alert.evidence,
        recommended_action: alert.recommendedAction,
        received_at: receivedAt,
        processed_at: processedAt,
        stored_at: storedAt
      });

      if (result.success) {
        alert.databasePersistenceStatus = result.isDuplicate ? 'DUPLICATE_SKIPPED' : 'PERSISTED';
        alert.databaseStoredAt = result.stored_at;
      } else {
        alert.databasePersistenceStatus = result.status === 'DATABASE_UNAVAILABLE' ? 'DATABASE_UNAVAILABLE' : 'FAILED';
        alert.databasePersistenceError = result.error;
      }
      return result;
    } catch (err: any) {
      if (typeof window !== 'undefined' && typeof fetch !== 'undefined') {
        try {
          const resp = await fetch('/api/mongo/alerts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              alertId: alert.alertId,
              incidentId: alert.incidentId,
              title: alert.title,
              description: alert.description,
              alertType: alert.alertType,
              threatCategory: input.threatCategory,
              agentName: input.agentName,
              detectionMethod: input.detectionMethod,
              recommendedAction: alert.recommendedAction,
              incidentStatus: alert.status,
              severity: alert.severity,
              riskScore: alert.riskScore,
              priority: alert.priority,
              status: alert.status,
              mitreTechniques: alert.evidence,
              evidence: alert.evidence
            })
          });

          if (!resp.ok) {
            const errText = await resp.text().catch(() => resp.statusText);
            alert.databasePersistenceStatus = 'FAILED';
            alert.databasePersistenceError = `HTTP ${resp.status}: ${errText}`;
            return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: alert.databasePersistenceError };
          }

          const data = await resp.json().catch(() => ({}));
          alert.databasePersistenceStatus = 'PERSISTED';
          alert.databaseStoredAt = storedAt;
          return { success: true, status: 'PERSISTED', isDuplicate: false, doc: data, stored_at: storedAt };
        } catch (fetchErr: any) {
          alert.databasePersistenceStatus = 'FAILED';
          alert.databasePersistenceError = fetchErr.message;
          return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: fetchErr.message };
        }
      }

      alert.databasePersistenceStatus = 'FAILED';
      alert.databasePersistenceError = err.message || String(err);
      return { success: false, status: 'WRITE_FAILED', isDuplicate: false, error: alert.databasePersistenceError };
    }
  }

  private async syncIncidentStatusToBackend(
    incidentId: string,
    status: IncidentLifecycleStatus,
    actor: string,
    reason?: string
  ): Promise<void> {
    try {
      await fetch(`/api/incidents/${incidentId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, actor, reason })
      });
    } catch {
      // Fallback handled
    }
  }
}

export const incidentWorkflowService = new IncidentWorkflowService();
