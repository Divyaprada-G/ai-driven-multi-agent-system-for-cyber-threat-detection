/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Unified Audit Logging Service
 *
 * Implements non-volatile audit records for:
 * - Alert creation, acknowledgment, status transitions
 * - False-positive declarations with analyst reasoning
 * - Incident lifecycle changes and analyst note attachments
 * - Safe response simulation actions
 * - Demo scenario executions and resets
 */

import { AuditLogEntry, AuditActionType } from '../types/analytics';

const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'AUD-1001',
    timestamp: '2026-09-11 22:58:30',
    action: 'INCIDENT_CREATED',
    entityType: 'INCIDENT',
    entityId: 'INC-2026-0042',
    actor: 'Correlation Scorer (Stage 6)',
    details: 'Triggered critical multi-stage incident from correlation cluster CORR-2026-001 (Confidence: 94%, Score: 94).',
    metadata: { rule: 'MULTI_STAGE_KILLCHAIN', severity: 'CRITICAL' }
  },
  {
    id: 'AUD-1002',
    timestamp: '2026-09-11 23:00:15',
    action: 'ALERT_CREATED',
    entityType: 'ALERT',
    entityId: 'ALT-1099',
    actor: 'Risk Scoring Engine (Stage 8)',
    details: 'Generated P1 priority alert for Multi-Stage APT Attack with risk score 94/100.',
    metadata: { riskScore: 94, priority: 'P1' }
  },
  {
    id: 'AUD-1003',
    timestamp: '2026-09-11 23:02:40',
    action: 'ALERT_ACKNOWLEDGED',
    entityType: 'ALERT',
    entityId: 'ALT-1099',
    actor: 'SOC Analyst (Tier-2)',
    details: 'Alert acknowledged and assigned for active cross-agent investigation.',
    previousValue: 'NEW',
    newValue: 'ACKNOWLEDGED'
  },
  {
    id: 'AUD-1004',
    timestamp: '2026-09-11 23:05:10',
    action: 'STATUS_CHANGED',
    entityType: 'INCIDENT',
    entityId: 'INC-2026-0042',
    actor: 'SOC Lead Analyst',
    details: 'Status transitioned to INVESTIGATING. Correlating system agent host tokens with web ingress logs.',
    previousValue: 'NEW',
    newValue: 'INVESTIGATING'
  },
  {
    id: 'AUD-1005',
    timestamp: '2026-09-11 23:08:22',
    action: 'ANALYST_NOTE_ADDED',
    entityType: 'INCIDENT',
    entityId: 'INC-2026-0042',
    actor: 'SOC Lead Analyst',
    details: 'Confirmed reconnaissance source 192.168.1.105 matched subsequent SQL injection and spoolsv.exe execution.',
    metadata: { sourceIp: '192.168.1.105', host: 'workstation-fin-04' }
  },
  {
    id: 'AUD-1006',
    timestamp: '2026-09-11 23:12:05',
    action: 'SIMULATION_EXECUTED',
    entityType: 'SYSTEM',
    entityId: 'SIM-RESP-01',
    actor: 'SOC Analyst (Tier-2)',
    details: '[SAFE SIMULATION] Validated containment policy proposal for blocking IP 192.168.1.105 without production execution.',
    metadata: { actionType: 'BLOCK_IP', isSimulated: true }
  },
  {
    id: 'AUD-1007',
    timestamp: '2026-09-12 00:15:30',
    action: 'FALSE_POSITIVE_MARKED',
    entityType: 'ALERT',
    entityId: 'ALT-1094',
    actor: 'Senior Security Engineer',
    details: 'Flagged as benign authorized vulnerability scan from internal IT scanner subnet 10.0.0.12.',
    previousValue: 'INVESTIGATING',
    newValue: 'FALSE_POSITIVE',
    metadata: { falsePositiveReason: 'Authorized vulnerability assessment window' }
  },
  {
    id: 'AUD-1008',
    timestamp: '2026-09-12 01:20:00',
    action: 'INCIDENT_RESOLVED',
    entityType: 'INCIDENT',
    entityId: 'INC-2026-0039',
    actor: 'Incident Commander',
    details: 'Incident marked RESOLVED following credential revocation and certificate rotation on auth-gateway-srv-02.',
    previousValue: 'INVESTIGATING',
    newValue: 'RESOLVED',
    metadata: { resolution: 'Root credential rotated; SSH public key access enforced.' }
  }
];

class AuditService {
  private logs: AuditLogEntry[] = [...INITIAL_AUDIT_LOGS];
  private listeners: Array<() => void> = [];

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
        console.error('AuditService listener error:', err);
      }
    });
  }

  public getAuditLogs(): AuditLogEntry[] {
    // Return sorted newest first
    return [...this.logs].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public recordAction(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const newEntry: AuditLogEntry = {
      id: `AUD-${Date.now().toString().slice(-6)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      ...entry
    };

    this.logs.unshift(newEntry);
    this.notify();
    return newEntry;
  }

  public recordStatusChange(
    entityType: 'ALERT' | 'INCIDENT',
    entityId: string,
    previousStatus: string,
    newStatus: string,
    actor = 'SOC Analyst',
    reason?: string
  ): void {
    const action: AuditActionType =
      newStatus === 'FALSE_POSITIVE'
        ? 'FALSE_POSITIVE_MARKED'
        : newStatus === 'RESOLVED'
        ? 'INCIDENT_RESOLVED'
        : newStatus === 'ACKNOWLEDGED'
        ? 'ALERT_ACKNOWLEDGED'
        : 'STATUS_CHANGED';

    this.recordAction({
      action,
      entityType,
      entityId,
      actor,
      details: reason
        ? `Status changed from ${previousStatus} to ${newStatus}. Reason: ${reason}`
        : `Status transitioned from ${previousStatus} to ${newStatus}.`,
      previousValue: previousStatus,
      newValue: newStatus,
      metadata: reason ? { reason } : undefined
    });
  }

  public resetDemoAudit(): void {
    this.logs = [...INITIAL_AUDIT_LOGS];
    this.recordAction({
      action: 'DEMO_SCENARIO_RESET',
      entityType: 'DEMO',
      entityId: 'DEMO-ENV-RESET',
      actor: 'Project Evaluator / Demo Studio',
      details: 'Demonstration environment reset to clean baseline state.'
    });
  }
}

export const auditService = new AuditService();
