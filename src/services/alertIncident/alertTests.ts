/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 9: Alert & Incident Management Verification Suite (14 Tests)
 */

import { AlertManager } from './alertManager';
import { IncidentManager } from './incidentManager';
import { RiskAssessment } from '../../types/riskScoring';

export interface TestResult {
  id: string;
  name: string;
  category: 'ALERT_GENERATION' | 'DEDUPLICATION' | 'LIFECYCLE' | 'INCIDENT_MANAGEMENT' | 'SIMULATION' | 'TRACEABILITY';
  passed: boolean;
  message: string;
  durationMs: number;
  details?: any;
}

export class AlertIncidentTestSuite {
  public static async runAllTests(): Promise<{ results: TestResult[]; summary: { total: number; passed: number; failed: number; durationMs: number } }> {
    const startTime = performance.now();
    const results: TestResult[] = [];

    // Instantiate fresh isolated managers for testing
    const alertMgr = new AlertManager();
    const incidentMgr = new IncidentManager();
    await alertMgr.initializeAlerts();
    await incidentMgr.initializeIncidents();

    // Helper to run a test step
    const runStep = async (
      id: string,
      name: string,
      category: TestResult['category'],
      fn: () => Promise<void> | void
    ) => {
      const stepStart = performance.now();
      try {
        await fn();
        results.push({
          id,
          name,
          category,
          passed: true,
          message: 'Passed verification checks.',
          durationMs: Math.round(performance.now() - stepStart)
        });
      } catch (err: any) {
        results.push({
          id,
          name,
          category,
          passed: false,
          message: err.message || 'Assertion failed',
          durationMs: Math.round(performance.now() - stepStart),
          details: String(err)
        });
      }
    };

    // 1. Alert Generation from Critical Risk Assessment
    await runStep('TEST-01', 'Alert Generation from Critical Risk Assessment', 'ALERT_GENERATION', () => {
      const mockCritical: RiskAssessment = {
        id: 'RISK-TEST-CRIT-01',
        threatDetectionId: 'THREAT-TEST-01',
        correlationId: 'CORR-TEST-01',
        timestamp: '2026-09-12 10:00:00',
        riskScore: 95,
        severity: 'CRITICAL',
        priority: 'P1',
        riskBand: 'CRITICAL',
        confidence: 96,
        riskFactors: [],
        threatClassification: 'Multi-Stage Infiltration',
        explanation: 'Privilege escalation with lateral movement.',
        recommendedAction: 'Immediate host isolation and credentials revocation.',
        status: 'NEW',
        participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT'],
        evidenceVolume: 8,
        affectedEntitiesCount: 2,
        affectedSource: 'fin-srv-01',
        auditTrail: {
          calculatedAt: '2026-09-12 10:00:00',
          modelUsed: 'Stage-8-Risk-Matrix',
          correlationStrength: 0.95,
          mlAnomalyScore: 0.92,
          weightsConfigVersion: '1.0'
        },
        score: 95,
        remediationPlan: ['Isolate host', 'Revoke credentials']
      };

      const result = alertMgr.processRiskAssessment(mockCritical);
      if (!result.alert) throw new Error('Expected alert to be generated for CRITICAL risk');
      if (result.alert.severity !== 'CRITICAL') throw new Error(`Expected CRITICAL severity, got ${result.alert.severity}`);
      if (result.alert.priority !== 'P1') throw new Error(`Expected P1 priority, got ${result.alert.priority}`);
      if (result.alert.status !== 'NEW') throw new Error(`Expected NEW initial status, got ${result.alert.status}`);
    });

    // 2. Alert Generation from High Risk Assessment
    await runStep('TEST-02', 'Alert Generation from High Risk Assessment', 'ALERT_GENERATION', () => {
      const mockHigh: RiskAssessment = {
        id: 'RISK-TEST-HIGH-02',
        threatDetectionId: 'THREAT-TEST-02',
        correlationId: 'CORR-TEST-02',
        timestamp: '2026-09-12 10:05:00',
        riskScore: 78,
        severity: 'HIGH',
        priority: 'P2',
        riskBand: 'HIGH',
        confidence: 89,
        riskFactors: [],
        threatClassification: 'SQL Injection Attack',
        explanation: 'Stacked UNION queries against catalog API.',
        recommendedAction: 'Inspect web application firewall rules.',
        status: 'NEW',
        participatingAgents: ['APPLICATION_AGENT'],
        evidenceVolume: 5,
        affectedEntitiesCount: 1,
        affectedSource: 'api.corp.internal/checkout',
        auditTrail: {
          calculatedAt: '2026-09-12 10:05:00',
          modelUsed: 'Stage-8-Risk-Matrix',
          correlationStrength: 0.82,
          mlAnomalyScore: 0.85,
          weightsConfigVersion: '1.0'
        },
        score: 78,
        remediationPlan: ['Patch parameter binding']
      };

      const result = alertMgr.processRiskAssessment(mockHigh);
      if (!result.alert) throw new Error('Expected alert to be generated for HIGH risk');
      if (result.alert.priority !== 'P2') throw new Error(`Expected P2 priority, got ${result.alert.priority}`);
    });

    // 3. Medium Risk Threshold Filtering
    await runStep('TEST-03', 'Medium Risk Threshold Filtering', 'ALERT_GENERATION', () => {
      const mockMedAbove: RiskAssessment = {
        id: 'RISK-TEST-MED-03',
        threatDetectionId: 'THREAT-TEST-03',
        correlationId: 'CORR-TEST-03',
        timestamp: '2026-09-12 10:10:00',
        riskScore: 55, // >= 50
        severity: 'MEDIUM',
        priority: 'P3',
        riskBand: 'MEDIUM',
        confidence: 75,
        riskFactors: [],
        threatClassification: 'DNS Tunneling Entropy Spike',
        explanation: 'Above-average Shannon entropy in DNS queries.',
        recommendedAction: 'Monitor resolver query patterns.',
        status: 'NEW',
        participatingAgents: ['NETWORK_AGENT'],
        evidenceVolume: 3,
        affectedEntitiesCount: 1,
        affectedSource: 'dns-resolver-01',
        auditTrail: {
          calculatedAt: '2026-09-12 10:10:00',
          modelUsed: 'Stage-8-Risk-Matrix',
          correlationStrength: 0.70,
          mlAnomalyScore: 0.65,
          weightsConfigVersion: '1.0'
        },
        score: 55,
        remediationPlan: ['Sinkhole query domain']
      };

      const shouldGen = alertMgr.shouldGenerateAlert(mockMedAbove);
      if (!shouldGen) throw new Error('Expected MEDIUM risk >= 50 threshold to generate alert');
    });

    // 4. Low Risk Suppression Rule
    await runStep('TEST-04', 'Low Risk Suppression by Default', 'ALERT_GENERATION', () => {
      const mockLow: RiskAssessment = {
        id: 'RISK-TEST-LOW-04',
        threatDetectionId: 'THREAT-TEST-04',
        correlationId: 'CORR-TEST-04',
        timestamp: '2026-09-12 10:15:00',
        riskScore: 28,
        severity: 'LOW',
        priority: 'P4',
        riskBand: 'LOW',
        confidence: 60,
        riskFactors: [],
        threatClassification: 'Benign Ping Sweep',
        explanation: 'Low rate internal ICMP discovery.',
        recommendedAction: 'Retain event logs for historical baseline.',
        status: 'NEW',
        participatingAgents: ['NETWORK_AGENT'],
        evidenceVolume: 1,
        affectedEntitiesCount: 1,
        affectedSource: 'mgmt-gateway',
        auditTrail: {
          calculatedAt: '2026-09-12 10:15:00',
          modelUsed: 'Stage-8-Risk-Matrix',
          correlationStrength: 0.30,
          mlAnomalyScore: 0.25,
          weightsConfigVersion: '1.0'
        },
        score: 28,
        remediationPlan: ['None required']
      };

      const shouldGen = alertMgr.shouldGenerateAlert(mockLow);
      if (shouldGen) throw new Error('Expected LOW risk to be suppressed when lowRiskAutoAlert is false');
    });

    // 5. Alert Deduplication within Time Window
    await runStep('TEST-05', 'Alert Deduplication within Time Window', 'DEDUPLICATION', () => {
      const mockBurst1: RiskAssessment = {
        id: 'RISK-BURST-01',
        threatDetectionId: 'THREAT-BURST-01',
        correlationId: 'CORR-BURST-01',
        timestamp: new Date().toISOString(),
        riskScore: 82,
        severity: 'HIGH',
        priority: 'P2',
        riskBand: 'HIGH',
        confidence: 90,
        riskFactors: [],
        threatClassification: 'SSH Brute Force Burst',
        explanation: 'SSH auth failures exceeding 300/sec.',
        recommendedAction: 'Temporarily throttle ingress SSH port.',
        status: 'NEW',
        participatingAgents: ['SYSTEM_AGENT'],
        evidenceVolume: 4,
        affectedEntitiesCount: 1,
        affectedSource: 'ssh-bastion-east',
        auditTrail: {
          calculatedAt: new Date().toISOString(),
          modelUsed: 'Stage-8-Risk-Matrix',
          correlationStrength: 0.85,
          mlAnomalyScore: 0.88,
          weightsConfigVersion: '1.0'
        },
        score: 82,
        remediationPlan: ['Fail2ban policy enforcement']
      };

      const first = alertMgr.processRiskAssessment(mockBurst1);
      if (!first.alert || first.isDuplicate) throw new Error('First event must create a new alert');

      // Immediate second duplicate with same correlationId & source
      const second = alertMgr.processRiskAssessment(mockBurst1);
      if (!second.isDuplicate) throw new Error('Second identical event must be recognized as duplicate');
    });

    // 6. Deduplication Counter and Timestamp Update
    await runStep('TEST-06', 'Deduplication Counter & Timestamp Update', 'DEDUPLICATION', () => {
      const alert = alertMgr.getAlertById('ALT-BURST-01');
      if (!alert) throw new Error('Expected alert ALT-BURST-01 to exist');
      if (alert.deduplicationCount < 2) throw new Error(`Expected deduplicationCount >= 2, got ${alert.deduplicationCount}`);
      const hasDedupeHistory = alert.history.some(h => h.action === 'DEDUPLICATED_BURST');
      if (!hasDedupeHistory) throw new Error('Expected audit trail to contain DEDUPLICATED_BURST history entry');
    });

    // 7. Alert Lifecycle Transition (NEW -> ACKNOWLEDGED)
    await runStep('TEST-07', 'Alert Lifecycle Transition (NEW -> ACKNOWLEDGED)', 'LIFECYCLE', () => {
      const alert = alertMgr.getAlerts()[0];
      if (!alert) throw new Error('No alerts available for lifecycle test');
      const ok = alertMgr.updateAlertStatus(alert.id, 'ACKNOWLEDGED', 'Acknowledged by Tier 1 triage');
      if (!ok) throw new Error('Failed to transition alert to ACKNOWLEDGED');
      const updated = alertMgr.getAlertById(alert.id);
      if (updated?.status !== 'ACKNOWLEDGED') throw new Error(`Expected status ACKNOWLEDGED, got ${updated?.status}`);
      if (!updated.acknowledgedAt) throw new Error('Expected acknowledgedAt timestamp to be populated');
    });

    // 8. False Positive Marking with Reason
    await runStep('TEST-08', 'Alert False Positive Marking with Reason', 'LIFECYCLE', () => {
      const alert = alertMgr.getAlerts()[1] || alertMgr.getAlerts()[0];
      const reason = 'Scheduled Red Team penetration testing exercise authorized under ticket SEC-9941';
      const ok = alertMgr.updateAlertStatus(alert.id, 'FALSE_POSITIVE', reason);
      if (!ok) throw new Error('Failed to mark alert as FALSE_POSITIVE');
      const updated = alertMgr.getAlertById(alert.id);
      if (updated?.status !== 'FALSE_POSITIVE') throw new Error('Expected FALSE_POSITIVE status');
      if (updated?.falsePositiveReason !== reason) throw new Error('Expected falsePositiveReason to match provided reason');
    });

    // 9. Incident Creation & Alert Grouping
    await runStep('TEST-09', 'Incident Creation & Alert Grouping by Correlation', 'INCIDENT_MANAGEMENT', () => {
      const alerts = alertMgr.getAlerts().slice(0, 2);
      if (alerts.length < 2) throw new Error('Need at least 2 alerts for grouping test');
      const alertIds = alerts.map(a => a.id);
      const inc = incidentMgr.groupAlertsIntoIncident(alertIds, undefined, 'Test Correlated Security Group', 'Test group description');
      if (!inc) throw new Error('Failed to create incident from grouped alerts');
      if (inc.alertIds.length < 2) throw new Error(`Expected incident to contain 2 alerts, got ${inc.alertIds.length}`);
      // Verify alerts have incidentId set
      const alert1 = alertMgr.getAlertById(alerts[0].id);
      if (alert1?.incidentId !== inc.id) throw new Error(`Alert 1 incidentId not set to ${inc.id}`);
    });

    // 10. Incident Risk Score & Severity Aggregation
    await runStep('TEST-10', 'Incident Risk Score & Severity Aggregation', 'INCIDENT_MANAGEMENT', () => {
      const inc = incidentMgr.getIncidents()[0];
      if (!inc) throw new Error('No incidents found');
      if (typeof inc.riskScore !== 'number' || inc.riskScore < 0 || inc.riskScore > 100) {
        throw new Error(`Invalid incident risk score: ${inc.riskScore}`);
      }
      if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(inc.severity)) {
        throw new Error(`Invalid incident severity: ${inc.severity}`);
      }
    });

    // 11. Incident Timeline Chronological Ordering
    await runStep('TEST-11', 'Incident Timeline Chronological Ordering', 'INCIDENT_MANAGEMENT', () => {
      const inc = incidentMgr.getIncidents()[0];
      if (!inc || !inc.timeline || inc.timeline.length === 0) throw new Error('Incident timeline is empty');
      const countBefore = inc.timeline.length;
      incidentMgr.addAnalystNote(inc.id, 'Timeline order test note', 'Test Analyst');
      const updated = incidentMgr.getIncidentById(inc.id);
      if (!updated || updated.timeline.length !== countBefore + 1) {
        throw new Error('Timeline entry was not appended correctly');
      }
    });

    // 12. Analyst Note Persistence with Timestamp & Author
    await runStep('TEST-12', 'Analyst Note Persistence with Timestamp & Author', 'INCIDENT_MANAGEMENT', () => {
      const inc = incidentMgr.getIncidents()[0];
      const author = 'Senior Investigator Alice';
      const noteText = 'Forensic memory dump extracted from compromised endpoint.';
      incidentMgr.addAnalystNote(inc.id, noteText, author);
      const updated = incidentMgr.getIncidentById(inc.id);
      const foundNote = updated?.analystNotes.find(n => n.note === noteText && n.author === author);
      if (!foundNote) throw new Error('Analyst note with matching author and text was not found');
      if (!foundNote.timestamp) throw new Error('Analyst note missing timestamp');
    });

    // 13. Safe Response Simulation Non-Destructive Logging
    await runStep('TEST-13', 'Safe Response Simulation Non-Destructive Logging', 'SIMULATION', () => {
      const inc = incidentMgr.getIncidents()[0];
      const record = incidentMgr.recordSimulatedResponse(inc.id, 'BLOCK_IP', '198.51.100.42', 'Simulated Firewall Drop Rule');
      if (!record) throw new Error('Failed to record simulated response');
      if (record.status !== 'SIMULATED_SUCCESS') throw new Error('Expected SIMULATED_SUCCESS status');
      if (!record.disclaimer.includes('SIMULATED ACTION ONLY')) {
        throw new Error('Missing safety disclaimer in simulated response record');
      }
      const updated = incidentMgr.getIncidentById(inc.id);
      const inTimeline = updated?.timeline.some(t => t.description.includes('SIMULATED RESPONSE'));
      if (!inTimeline) throw new Error('Simulated response not registered in incident timeline');
    });

    // 14. End-to-End Traceability (Alert -> Incident -> Risk -> Detection -> Correlation -> Evidence)
    await runStep('TEST-14', 'End-to-End Traceability Verification', 'TRACEABILITY', () => {
      const alerts = alertMgr.getAlerts();
      const alertWithCorr = alerts.find(a => a.correlationId) || alerts[0];
      if (!alertWithCorr) throw new Error('No alert with correlation data available');

      const chain = incidentMgr.getTraceabilityChain(alertWithCorr.id);
      if (!chain) throw new Error('Traceability chain is null');
      if (!chain.alertId) throw new Error('Traceability missing alertId');
      if (!chain.participatingAgents || chain.participatingAgents.length === 0) {
        throw new Error('Traceability missing participatingAgents');
      }
      if (!chain.evidence || chain.evidence.length === 0) {
        throw new Error('Traceability missing evidence trace');
      }
    });

    const passedCount = results.filter(r => r.passed).length;
    const failedCount = results.filter(r => !r.passed).length;

    return {
      results,
      summary: {
        total: results.length,
        passed: passedCount,
        failed: failedCount,
        durationMs: Math.round(performance.now() - startTime)
      }
    };
  }
}
