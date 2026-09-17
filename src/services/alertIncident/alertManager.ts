/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 9: AlertManager Service
 *
 * Implements:
 * - Alert generation from RiskAssessments
 * - Configurable generation thresholds (Critical, High, Medium, Low)
 * - Time-windowed deduplication with burst counter and evidence collation
 * - Complete alert lifecycle management (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, SUPPRESSED)
 * - Safe response simulation audit logging
 * - n8n payload preparation
 */

import {
  SecurityAlert,
  AlertType,
  AlertLifecycleStatus,
  AlertGenerationConfig,
  AlertHistoryEntry,
  SimulatedResponseRecord,
  ResponseSimulationActionType,
  N8nAlertPayload
} from '../../types/alertIncident';
import { RiskAssessment } from '../../types/riskScoring';
import { INITIAL_ALERTS, INITIAL_CORRELATIONS } from '../mockData';
import { riskService } from '../riskService';

export const DEFAULT_ALERT_CONFIG: AlertGenerationConfig = {
  criticalRiskAutoAlert: true,
  highRiskAutoAlert: true,
  mediumRiskAutoAlert: true,
  mediumRiskThreshold: 50,
  lowRiskAutoAlert: false,
  lowRiskThreshold: 30,
  deduplicationWindowMinutes: 15,
  autoGroupCorrelatedIncidents: true
};

export class AlertManager {
  private alerts: SecurityAlert[] = [];
  private config: AlertGenerationConfig = { ...DEFAULT_ALERT_CONFIG };
  private listeners: Array<() => void> = [];
  private isInitialized = false;

  constructor() {
    this.initializeAlerts();
  }

  public subscribe(callback: () => void): () => void {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(cb => cb !== callback);
    };
  }

  private notify(): void {
    this.listeners.forEach(cb => {
      try {
        cb();
      } catch (err) {
        console.error('AlertManager listener error:', err);
      }
    });
  }

  public getConfig(): AlertGenerationConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<AlertGenerationConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.notify();
  }

  /**
   * Initialize initial alerts from Risk Assessments & Mock Data
   */
  public async initializeAlerts(): Promise<void> {
    if (this.isInitialized && this.alerts.length > 0) return;

    try {
      const riskAssessments = await riskService.getRiskAssessments();
      const generated: SecurityAlert[] = [];

      for (const assessment of riskAssessments) {
        const alert = this.createAlertFromAssessment(assessment);
        if (alert) {
          generated.push(alert);
        }
      }

      // Merge with INITIAL_ALERTS if not already present
      for (const initial of INITIAL_ALERTS) {
        if (!generated.some(a => a.id === initial.alertId || a.title === initial.threat)) {
          const legacyAlert: SecurityAlert = {
            id: initial.alertId,
            alertId: initial.alertId,
            alertType: this.mapClassificationToAlertType(initial.ruleTriggered || 'SUSPICIOUS'),
            title: initial.threat,
            threat: initial.threat,
            description: `Automated detection triggered by rule ${initial.ruleTriggered || 'SURICATA_PERIMETER_ANOMALY'}.`,
            timestamp: initial.timestamp,
            source: initial.source,
            threatClassification: 'Anomalous Threat Pattern',
            severity: initial.severity,
            riskScore: initial.riskScore,
            priority: initial.riskScore >= 90 ? 'P1' : initial.riskScore >= 70 ? 'P2' : initial.riskScore >= 40 ? 'P3' : 'P4',
            confidence: 88,
            correlationStrength: 0.85,
            affectedEntities: [initial.source],
            participatingAgents: ['NETWORK_AGENT'],
            evidence: [`Rule triggered: ${initial.ruleTriggered}`, `Observed telemetry from ${initial.source}`],
            explanation: `Signal triggered security rule on ${initial.source}. Requires containment assessment.`,
            recommendedAction: 'Inspect host connections, analyze endpoint telemetry, verify firewall posture.',
            status: (initial.status === 'UNACKNOWLEDGED' ? 'NEW' : initial.status) as AlertLifecycleStatus,
            incidentId: initial.alertId === 'ALT-1099' ? 'INC-2026-0042' : undefined,
            isRead: initial.status !== 'UNACKNOWLEDGED',
            deduplicationCount: 1,
            lastSeenTimestamp: initial.timestamp,
            history: [
              {
                id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                timestamp: initial.timestamp,
                action: 'ALERT_GENERATED',
                actor: 'Multi-Agent Security Engine',
                details: `Alert generated with initial risk score of ${initial.riskScore}/100.`
              }
            ],
            simulatedResponses: [],
            notificationStatus: (initial.notificationStatus as any) || 'SENT',
            targetChannels: initial.targetChannels || ['#soc-alerts'],
            ruleTriggered: initial.ruleTriggered || 'RULE_DEFENSE_01',
            n8nWorkflowId: initial.n8nWorkflowId
          };
          generated.push(legacyAlert);
        }
      }

      this.alerts = generated;
      this.isInitialized = true;
      this.notify();
    } catch (err) {
      console.error('Error initializing alerts:', err);
    }
  }

  /**
   * Evaluate whether a RiskAssessment should trigger an alert based on rules
   */
  public shouldGenerateAlert(assessment: RiskAssessment): boolean {
    const score = assessment.riskScore;
    const sev = assessment.severity;

    if (sev === 'CRITICAL' && this.config.criticalRiskAutoAlert) return true;
    if (sev === 'HIGH' && this.config.highRiskAutoAlert) return true;
    if (sev === 'MEDIUM') {
      if (this.config.mediumRiskAutoAlert && score >= this.config.mediumRiskThreshold) return true;
      if (assessment.participatingAgents && assessment.participatingAgents.length >= 2) return true;
    }
    if (sev === 'LOW') {
      if (this.config.lowRiskAutoAlert && score >= this.config.lowRiskThreshold) return true;
      return false;
    }
    return score >= 50;
  }

  /**
   * Construct a clean SecurityAlert from a RiskAssessment
   */
  public createAlertFromAssessment(assessment: RiskAssessment): SecurityAlert | null {
    if (!this.shouldGenerateAlert(assessment)) {
      return null;
    }

    const alertId = `ALT-${assessment.id.replace('RISK-', '').replace('CORR-', '')}`;
    const alertType = this.mapClassificationToAlertType(assessment.threatClassification);

    const corr = INITIAL_CORRELATIONS.find(c => c.id === assessment.correlationId);
    const title = corr ? corr.title : `Triaged Threat: ${assessment.threatClassification}`;
    const source = assessment.affectedSource || (corr && corr.sources[0]) || 'Network Ingress';
    const entities = corr && corr.sources && corr.sources.length > 0 ? corr.sources : [source];

    const evidenceList: string[] = [];
    if (corr && corr.sequence) {
      corr.sequence.forEach(s => evidenceList.push(`[${s.agentId}] ${s.description}`));
    } else {
      evidenceList.push(`Suspicious pattern detected on ${source}`);
      evidenceList.push(`Classification: ${assessment.threatClassification} with confidence ${assessment.confidence}%`);
    }

    return {
      id: alertId,
      alertId,
      alertType,
      title,
      threat: title,
      description: assessment.explanation || `Automated threat detection generated alert with priority ${assessment.priority}.`,
      timestamp: assessment.timestamp,
      source,
      threatClassification: assessment.threatClassification,
      severity: assessment.severity,
      riskScore: assessment.riskScore,
      priority: assessment.priority,
      confidence: assessment.confidence,
      correlationStrength: assessment.auditTrail?.correlationStrength || 0.85,
      correlationId: assessment.correlationId,
      threatDetectionId: assessment.threatDetectionId,
      riskAssessmentId: assessment.id,
      affectedEntities: entities,
      participatingAgents: assessment.participatingAgents || ['NETWORK_AGENT'],
      evidence: evidenceList,
      riskFactors: assessment.riskFactors,
      explanation: assessment.explanation,
      recommendedAction: assessment.recommendedAction,
      status: 'NEW',
      incidentId: assessment.correlationId === 'CORR-2026-001' ? 'INC-2026-0042' : undefined,
      isRead: false,
      deduplicationCount: 1,
      lastSeenTimestamp: assessment.timestamp,
      history: [
        {
          id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          timestamp: assessment.timestamp,
          action: 'ALERT_GENERATED',
          actor: 'Risk Scoring Engine (Stage 8)',
          details: `Generated from Risk Assessment ${assessment.id} with score ${assessment.riskScore}/100 and priority ${assessment.priority}.`
        }
      ],
      simulatedResponses: [],
      notificationStatus: 'PENDING',
      targetChannels: ['#soc-tier1-alerts', 'SOC In-App Center'],
      ruleTriggered: `RISK_RULE_${assessment.priority}_${assessment.severity}`
    };
  }

  /**
   * Process a new incoming RiskAssessment with deduplication logic
   */
  public processRiskAssessment(assessment: RiskAssessment): { alert: SecurityAlert | null; isDuplicate: boolean } {
    if (!this.shouldGenerateAlert(assessment)) {
      return { alert: null, isDuplicate: false };
    }

    // Deduplication check: check matching correlationId, riskAssessmentId, or same threatClassification on same source
    const now = new Date();
    const windowMs = this.config.deduplicationWindowMinutes * 60 * 1000;

    const existingIndex = this.alerts.findIndex(a => {
      if (a.riskAssessmentId && a.riskAssessmentId === assessment.id) return true;
      if (a.correlationId && a.correlationId === assessment.correlationId) return true;

      // Match entity and threat classification
      const sameSource = a.source === assessment.affectedSource;
      const sameClassification = a.threatClassification === assessment.threatClassification;
      if (sameSource && sameClassification) {
        const lastSeen = new Date(a.lastSeenTimestamp).getTime();
        if (now.getTime() - lastSeen < windowMs) {
          return true;
        }
      }
      return false;
    });

    if (existingIndex >= 0) {
      // Deduplicate: increment count, update lastSeen, add evidence
      const existing = this.alerts[existingIndex];
      existing.deduplicationCount += 1;
      existing.lastSeenTimestamp = assessment.timestamp || now.toISOString();

      // Collate any new evidence
      if (assessment.recommendedAction && !existing.recommendedAction.includes(assessment.recommendedAction)) {
        existing.recommendedAction += ` | Additional note: ${assessment.recommendedAction}`;
      }

      existing.history.unshift({
        id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: new Date().toLocaleTimeString(),
        action: 'DEDUPLICATED_BURST',
        actor: 'Alert Deduplication Engine',
        details: `Suppressed duplicate alert burst. Occurrence count increased to ${existing.deduplicationCount}.`
      });

      this.notify();
      return { alert: existing, isDuplicate: true };
    }

    // New unique alert
    const newAlert = this.createAlertFromAssessment(assessment);
    if (newAlert) {
      this.alerts.unshift(newAlert);
      this.notify();
      return { alert: newAlert, isDuplicate: false };
    }

    return { alert: null, isDuplicate: false };
  }

  public getAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  public getAlertById(id: string): SecurityAlert | undefined {
    return this.alerts.find(a => a.id === id || a.alertId === id);
  }

  public getUnreadCount(): number {
    return this.alerts.filter(a => !a.isRead).length;
  }

  public markAsRead(id: string): boolean {
    const alert = this.getAlertById(id);
    if (alert && !alert.isRead) {
      alert.isRead = true;
      this.notify();
      return true;
    }
    return false;
  }

  public markAllAsRead(): void {
    let changed = false;
    this.alerts.forEach(a => {
      if (!a.isRead) {
        a.isRead = true;
        changed = true;
      }
    });
    if (changed) this.notify();
  }

  /**
   * Update Alert Lifecycle Status with validation and audit logging
   */
  public updateAlertStatus(
    id: string,
    newStatus: AlertLifecycleStatus,
    reason?: string,
    actor: string = 'SOC Analyst (Current User)'
  ): boolean {
    const alert = this.getAlertById(id);
    if (!alert) return false;

    const prevStatus = alert.status;
    if (prevStatus === newStatus) return true;

    alert.status = newStatus;
    alert.isRead = true;

    if (newStatus === 'ACKNOWLEDGED') {
      alert.acknowledgedAt = new Date().toLocaleTimeString();
    } else if (newStatus === 'RESOLVED') {
      alert.resolvedAt = new Date().toLocaleTimeString();
    } else if (newStatus === 'FALSE_POSITIVE') {
      alert.falsePositiveReason = reason || 'Marked as false positive by security analyst.';
    }

    alert.history.unshift({
      id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      action: `STATUS_CHANGED_TO_${newStatus}`,
      actor,
      details: reason ? `Status changed from ${prevStatus} to ${newStatus}. Note: ${reason}` : `Status transitioned from ${prevStatus} to ${newStatus}.`,
      previousStatus: prevStatus,
      newStatus,
      reason
    });

    this.notify();
    return true;
  }

  /**
   * Link an alert to an incident
   */
  public assignAlertToIncident(alertId: string, incidentId: string): boolean {
    const alert = this.getAlertById(alertId);
    if (!alert) return false;

    alert.incidentId = incidentId;
    alert.history.unshift({
      id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      action: 'ASSIGNED_TO_INCIDENT',
      actor: 'SOC Correlation & Incident Layer',
      details: `Alert correlated and linked to Security Incident ${incidentId}.`
    });

    this.notify();
    return true;
  }

  /**
   * Record a Safe Simulated Response on the Alert
   */
  public recordSimulatedResponse(
    alertId: string,
    actionType: ResponseSimulationActionType,
    target: string,
    title: string,
    actor: string = 'SOC Analyst'
  ): SimulatedResponseRecord | null {
    const alert = this.getAlertById(alertId);
    if (!alert) return null;

    const record: SimulatedResponseRecord = {
      id: `sim-resp-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      actionType,
      title,
      target,
      commandSnippet: this.generateSimulatedCommandSnippet(actionType, target),
      disclaimer: 'SIMULATED ACTION ONLY: A real firewall/IP blocking action would be requested here. No network configuration was changed.',
      simulatedBy: actor,
      status: 'SIMULATED_SUCCESS'
    };

    alert.simulatedResponses.unshift(record);
    alert.history.unshift({
      id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: record.timestamp,
      action: 'SIMULATED_RESPONSE_EXECUTED',
      actor,
      details: `Executed safe response simulation: ${title} on target "${target}". ${record.disclaimer}`
    });

    this.notify();
    return record;
  }

  private generateSimulatedCommandSnippet(actionType: ResponseSimulationActionType, target: string): string {
    switch (actionType) {
      case 'BLOCK_IP':
        return `# [SIMULATED] Would execute firewall drop rule:\niptables -I INPUT -s ${target} -j DROP\n# iptables-save > /etc/iptables/rules.v4`;
      case 'ISOLATE_HOST':
        return `# [SIMULATED] Would dispatch host containment via EDR agent:\nedrctl isolate --host ${target} --allow-dhcp --allow-dns-soc`;
      case 'WAF_RULE_DEPLOY':
        return `# [SIMULATED] Would update Web Application Firewall regex rule:\nwafctl rules insert --uri "${target}" --action BLOCK --reason "SQLi_Exploit_Pattern"`;
      case 'REVOKE_TOKEN':
        return `# [SIMULATED] Would invalidate active JWT / OAuth session:\nauth-cli revoke-token --subject "${target}" --broadcast-invalidate`;
      case 'ESCALATE_TICKET':
        return `# [SIMULATED] Would generate automated Jira / ServiceNow SOC ticket:\ncurl -X POST https://soc-jira.corp.internal/rest/api/2/issue ...`;
      case 'GENERATE_REPORT':
        return `# [SIMULATED] Would compile forensic PDF audit report for ${target}.`;
      default:
        return `# [SIMULATED] Non-destructive containment action on ${target}`;
    }
  }

  /**
   * Generate n8n Webhook Payload
   */
  public generateN8nPayload(alert: SecurityAlert): N8nAlertPayload {
    return {
      alertId: alert.id,
      incidentId: alert.incidentId || null,
      timestamp: alert.timestamp,
      severity: alert.severity,
      priority: alert.priority,
      riskScore: alert.riskScore,
      threatClassification: String(alert.threatClassification),
      confidence: alert.confidence,
      status: alert.status,
      title: alert.title,
      description: alert.description,
      source: alert.source,
      participatingAgents: alert.participatingAgents,
      affectedEntities: alert.affectedEntities,
      recommendedAction: alert.recommendedAction,
      exportedAt: new Date().toISOString(),
      system: {
        source: 'AI-DRIVEN-MULTI-AGENT-SOC',
        version: '1.0.0',
        mode: 'DEMO / SIMULATED',
        dispatchStatus: 'PREPARED_FOR_N8N'
      }
    };
  }

  private mapClassificationToAlertType(threatClass: string): AlertType {
    const lower = threatClass.toLowerCase();
    if (lower.includes('network') || lower.includes('port') || lower.includes('scan') || lower.includes('syn')) return 'NETWORK_THREAT';
    if (lower.includes('brute') || lower.includes('auth') || lower.includes('spray') || lower.includes('login')) return 'AUTHENTICATION_THREAT';
    if (lower.includes('privilege') || lower.includes('escalat') || lower.includes('sudo') || lower.includes('uac')) return 'PRIVILEGE_ESCALATION';
    if (lower.includes('sql') || lower.includes('xss') || lower.includes('injection') || lower.includes('path')) return 'WEB_THREAT';
    if (lower.includes('api') || lower.includes('token') || lower.includes('key')) return 'API_THREAT';
    if (lower.includes('multi') || lower.includes('lateral') || lower.includes('kill') || lower.includes('chain')) return 'MULTI_STAGE_THREAT';
    if (lower.includes('anomaly') || lower.includes('tunnel') || lower.includes('entropy')) return 'ANOMALY';
    return 'SUSPICIOUS';
  }

  /**
   * Sync persistent alerts from backend API
   */
  public async syncWithBackend(): Promise<void> {
    try {
      const resp = await fetch('/api/alerts');
      if (!resp.ok) return;
      const data = await resp.json();
      const backendAlerts = Array.isArray(data) ? data : (data.alerts || []);
      if (!Array.isArray(backendAlerts) || backendAlerts.length === 0) return;

      for (const bAlert of backendAlerts) {
        const id = bAlert.id || bAlert.alertId;
        const existing = this.alerts.find(a => a.id === id || a.alertId === id);
        if (existing) {
          if (bAlert.status && existing.status !== bAlert.status) {
            existing.status = bAlert.status as AlertLifecycleStatus;
          }
        } else {
          const newAlert: SecurityAlert = {
            id,
            alertId: id,
            alertType: this.mapClassificationToAlertType(bAlert.alertType || bAlert.title || 'SUSPICIOUS'),
            title: bAlert.title || 'Security Alert',
            threat: bAlert.title || 'Detected Security Threat',
            description: bAlert.description || 'Threat detected by multi-agent analysis',
            timestamp: bAlert.createdAt ? new Date(bAlert.createdAt).toLocaleString() : new Date().toLocaleString(),
            source: bAlert.sourceIp || bAlert.affectedHost || 'server01',
            threatClassification: bAlert.alertType || 'Anomalous Threat Pattern',
            severity: bAlert.severity || 'HIGH',
            riskScore: bAlert.riskScore || 80,
            priority: bAlert.priority || (bAlert.riskScore >= 90 ? 'P1' : bAlert.riskScore >= 70 ? 'P2' : 'P3'),
            confidence: 90,
            correlationStrength: 0.85,
            affectedEntities: [bAlert.sourceIp || bAlert.affectedHost || 'server01'],
            participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'],
            evidence: bAlert.evidence || [`Rule: ${bAlert.title}`],
            explanation: bAlert.description || 'Observed telemetry indicates active security risk.',
            recommendedAction: 'Isolate affected host, analyze telemetry, block source indicator.',
            status: (bAlert.status as AlertLifecycleStatus) || 'NEW',
            incidentId: bAlert.incidentId || undefined,
            isRead: false,
            deduplicationCount: bAlert.burstCount || 1,
            lastSeenTimestamp: bAlert.createdAt ? new Date(bAlert.createdAt).toLocaleString() : new Date().toLocaleString(),
            history: [
              {
                id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                timestamp: bAlert.createdAt ? new Date(bAlert.createdAt).toLocaleString() : new Date().toLocaleString(),
                action: 'ALERT_GENERATED',
                actor: 'Multi-Agent Security Engine',
                details: `Alert generated with risk score ${bAlert.riskScore || 80}/100.`
              }
            ],
            simulatedResponses: [],
            notificationStatus: 'SENT',
            targetChannels: ['#soc-alerts'],
            ruleTriggered: bAlert.alertType || 'RULE_SECURITY'
          };
          this.alerts.unshift(newAlert);
        }
      }
      this.notify();
    } catch (err) {
      console.warn('[AlertManager] Backend sync warning:', err);
    }
  }
}

export const alertManager = new AlertManager();
