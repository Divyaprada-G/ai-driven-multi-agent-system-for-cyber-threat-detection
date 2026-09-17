/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 9: IncidentManager Service
 *
 * Implements:
 * - Correlation and entity-based alert grouping into incidents
 * - Incident lifecycle management (NEW, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE)
 * - Chronological timeline tracking
 * - Analyst notes with author and timestamp
 * - Safe response simulation audit logging (non-destructive)
 * - End-to-end traceability mapping (Alert -> Incident -> Risk -> Detection -> Correlation -> Evidence)
 */

import {
  SecurityIncident,
  IncidentLifecycleStatus,
  IncidentTimelineEntry,
  AnalystNote,
  SimulatedResponseRecord,
  ResponseSimulationActionType
} from '../../types/alertIncident';
import { CorrelatedEvent } from '../../types/correlation';
import { INITIAL_INCIDENTS } from '../mockData';
import { alertManager } from './alertManager';

export class IncidentManager {
  private incidents: SecurityIncident[] = [];
  private listeners: Array<() => void> = [];
  private isInitialized = false;

  constructor() {
    this.initializeIncidents();
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
        console.error('IncidentManager listener error:', err);
      }
    });
  }

  /**
   * Initialize initial incidents with enriched attributes
   */
  public initializeIncidents(): void {
    if (this.isInitialized && this.incidents.length > 0) return;

    const enriched: SecurityIncident[] = INITIAL_INCIDENTS.map((init, idx) => {
      const now = new Date();
      const detectedDate = init.detectedAt || '2026-09-11 22:58:30';
      const risk = init.riskScore || 85;
      const priority = risk >= 90 ? 'P1' : risk >= 75 ? 'P2' : risk >= 50 ? 'P3' : 'P4';

      const timelineEntries: IncidentTimelineEntry[] = (init.timeline || []).map((t, tIdx) => ({
        id: `tl-${idx}-${tIdx}`,
        time: t.time,
        timestamp: `${detectedDate.split(' ')[0]} ${t.time}`,
        description: t.description,
        actor: t.actor,
        phase: t.description.toLowerCase().includes('contained') || t.description.toLowerCase().includes('rate-limit')
          ? 'CONTAINMENT'
          : t.description.toLowerCase().includes('analy')
          ? 'INVESTIGATION'
          : 'DETECTION'
      }));

      // Find any initial alerts that correspond to this incident
      const alertIds = init.incidentId === 'INC-2026-0042'
        ? ['ALT-1099', 'ALT-1098']
        : init.incidentId === 'INC-2026-0041'
        ? ['ALT-1096']
        : init.incidentId === 'INC-2026-0040'
        ? ['ALT-1097']
        : [];

      return {
        id: init.incidentId,
        incidentId: init.incidentId,
        title: init.threatType,
        description: init.summary,
        createdAt: detectedDate,
        updatedAt: detectedDate,
        detectedAt: detectedDate,
        severity: init.severity,
        priority,
        riskScore: risk,
        status: (init.status as IncidentLifecycleStatus) || 'INVESTIGATING',
        alertIds,
        correlationIds: init.incidentId === 'INC-2026-0042' ? ['CORR-2026-001'] : [],
        threatTypes: [init.threatType],
        participatingAgents: init.incidentId === 'INC-2026-0042'
          ? ['NETWORK_AGENT', 'APPLICATION_AGENT', 'SYSTEM_AGENT']
          : ['NETWORK_AGENT', 'SYSTEM_AGENT'],
        affectedEntities: [init.affectedSource],
        affectedSource: init.affectedSource,
        evidence: [
          `Detected on ${init.affectedSource}`,
          `Tactic: ${init.mitreTactic || 'TA0001'}`,
          `Technique: ${init.mitreTechnique || 'T1190'}`
        ],
        timeline: timelineEntries,
        analystNotes: [
          {
            id: `note-init-${idx}`,
            timestamp: detectedDate,
            author: 'SOC Lead Analyst',
            note: `Incident opened via multi-agent correlation. Containment protocol: ${init.containmentRecommendation}`
          }
        ],
        recommendedActions: [init.containmentRecommendation],
        assignedTo: init.assignedTo || 'SOC Tier 2 Incident Team',
        mitreTactic: init.mitreTactic || 'TA0001 - Initial Access',
        mitreTechnique: init.mitreTechnique || 'T1190 - Exploit Public-Facing Application',
        containmentRecommendation: init.containmentRecommendation,
        summary: init.summary,
        history: [
          {
            id: `hist-inc-init-${idx}`,
            timestamp: detectedDate,
            action: 'INCIDENT_CREATED',
            actor: 'SOC Correlation Engine',
            details: `Incident created from correlated detection cluster on ${init.affectedSource}.`
          }
        ],
        simulatedResponses: []
      };
    });

    this.incidents = enriched;
    this.isInitialized = true;
    this.notify();
  }

  public getIncidents(): SecurityIncident[] {
    return [...this.incidents];
  }

  public getIncidentById(id: string): SecurityIncident | undefined {
    return this.incidents.find(i => i.id === id || i.incidentId === id);
  }

  /**
   * Create an Incident from a Correlated Event
   */
  public createIncidentFromCorrelation(correlation: CorrelatedEvent): SecurityIncident {
    const existing = this.incidents.find(i => i.correlationIds.includes(correlation.id) || i.id === `INC-${correlation.id}`);
    if (existing) {
      return existing;
    }

    const incId = `INC-${correlation.id.replace('CORR-', '')}`;
    const risk = Math.round((correlation.correlationConfidence || 0.85) * 100);
    const priority = risk >= 90 ? 'P1' : risk >= 75 ? 'P2' : risk >= 50 ? 'P3' : 'P4';
    const now = new Date();
    const timeString = correlation.startTime || now.toLocaleTimeString();

    const timeline: IncidentTimelineEntry[] = (correlation.sequence || []).map((s, idx) => ({
      id: `seq-${Date.now()}-${idx}`,
      time: s.timestamp,
      timestamp: s.timestamp,
      description: `[${s.agentId}] ${s.description}`,
      actor: s.agentId,
      phase: 'CORRELATION',
      relatedEventId: s.eventId
    }));

    // Add incident creation entry
    timeline.unshift({
      id: `tl-create-${Date.now()}`,
      time: timeString,
      timestamp: timeString,
      description: `Incident created from Correlation Cluster ${correlation.id}`,
      actor: 'Event Correlation Engine (Stage 5)',
      phase: 'DETECTION'
    });

    const newIncident: SecurityIncident = {
      id: incId,
      incidentId: incId,
      title: correlation.title || correlation.attackPattern,
      description: correlation.description || correlation.summary,
      createdAt: correlation.startTime || now.toISOString(),
      updatedAt: now.toISOString(),
      detectedAt: correlation.startTime || now.toISOString(),
      severity: correlation.severity,
      priority,
      riskScore: risk,
      status: 'INVESTIGATING',
      alertIds: [],
      correlationIds: [correlation.id],
      threatTypes: [correlation.attackPattern],
      participatingAgents: correlation.participatingAgents || ['NETWORK_AGENT', 'APPLICATION_AGENT'],
      affectedEntities: correlation.sources || ['Corporate Subnet'],
      affectedSource: (correlation.sources && correlation.sources[0]) || 'Correlated Assets',
      evidence: [
        `Correlated ${correlation.eventCount} multi-agent signals`,
        `Confidence: ${Math.round((correlation.correlationConfidence || 0.85) * 100)}%`,
        `MITRE Technique: ${correlation.mitreTechniqueId || 'T1190'}`
      ],
      timeline,
      analystNotes: [
        {
          id: `note-${Date.now()}`,
          timestamp: timeString,
          author: 'SOC Automation',
          note: `Automated incident generated from ${correlation.id}. Containment: ${correlation.recommendedAction}`
        }
      ],
      recommendedActions: [correlation.recommendedAction || 'Execute endpoint isolation and investigate affected assets.'],
      assignedTo: 'SOC Correlation Engine',
      mitreTactic: 'TA0001 - Initial Access & Lateral Movement',
      mitreTechnique: correlation.mitreTechniqueId || 'T1190',
      containmentRecommendation: correlation.recommendedAction,
      summary: correlation.summary,
      history: [
        {
          id: `hist-${Date.now()}`,
          timestamp: timeString,
          action: 'INCIDENT_CREATED',
          actor: 'Event Correlation Engine',
          details: `Correlated ${correlation.eventCount} events across ${correlation.participatingAgents.join(', ')}.`
        }
      ],
      simulatedResponses: []
    };

    this.incidents.unshift(newIncident);
    this.notify();
    return newIncident;
  }

  /**
   * Group selected alerts into an existing or new Incident
   */
  public groupAlertsIntoIncident(
    alertIds: string[],
    targetIncidentId?: string,
    newTitle?: string,
    newDescription?: string
  ): SecurityIncident | null {
    if (alertIds.length === 0) return null;

    const allAlerts = alertManager.getAlerts();
    const selectedAlerts = allAlerts.filter(a => alertIds.includes(a.id) || alertIds.includes(a.alertId));
    if (selectedAlerts.length === 0) return null;

    let incident: SecurityIncident;
    const now = new Date();
    const timeStr = now.toLocaleTimeString();

    if (targetIncidentId) {
      const found = this.getIncidentById(targetIncidentId);
      if (!found) return null;
      incident = found;

      // Add alerts to incident
      selectedAlerts.forEach(a => {
        if (!incident.alertIds.includes(a.id)) {
          incident.alertIds.push(a.id);
        }
        // Link alert to incident
        alertManager.assignAlertToIncident(a.id, incident.id);
      });

      // Update max risk score and severity
      const maxRisk = Math.max(incident.riskScore, ...selectedAlerts.map(a => a.riskScore));
      incident.riskScore = maxRisk;
      incident.updatedAt = now.toISOString();

      incident.timeline.unshift({
        id: `tl-${Date.now()}`,
        time: timeStr,
        timestamp: timeStr,
        description: `Linked ${selectedAlerts.length} alert(s) [${selectedAlerts.map(a => a.id).join(', ')}] into incident.`,
        actor: 'SOC Analyst',
        phase: 'ALERT'
      });

      incident.history.unshift({
        id: `hist-${Date.now()}`,
        timestamp: timeStr,
        action: 'ALERTS_LINKED',
        actor: 'SOC Analyst',
        details: `Linked alerts: ${selectedAlerts.map(a => a.id).join(', ')}`
      });
    } else {
      // Create a brand new incident
      const incId = `INC-2026-${String(Math.floor(1000 + Math.random() * 9000))}`;
      const highestRiskAlert = [...selectedAlerts].sort((a, b) => b.riskScore - a.riskScore)[0];
      const maxRisk = highestRiskAlert.riskScore;
      const priority = maxRisk >= 90 ? 'P1' : maxRisk >= 75 ? 'P2' : maxRisk >= 50 ? 'P3' : 'P4';

      const participatingAgents = Array.from(
        new Set(selectedAlerts.flatMap(a => a.participatingAgents))
      );
      const affectedEntities = Array.from(
        new Set(selectedAlerts.flatMap(a => a.affectedEntities))
      );

      const timeline: IncidentTimelineEntry[] = [
        {
          id: `tl-init-${Date.now()}`,
          time: timeStr,
          timestamp: timeStr,
          description: `Incident manually initiated from ${selectedAlerts.length} alert(s): ${selectedAlerts.map(a => a.id).join(', ')}`,
          actor: 'SOC Analyst',
          phase: 'ALERT'
        }
      ];

      selectedAlerts.forEach(a => {
        timeline.push({
          id: `tl-alert-${a.id}`,
          time: a.timestamp.includes(' ') ? a.timestamp.split(' ')[1] : a.timestamp,
          timestamp: a.timestamp,
          description: `Alert [${a.id}]: ${a.title} (${a.severity}, Risk ${a.riskScore}/100)`,
          actor: a.participatingAgents.join(', ') || 'Security Agent',
          phase: 'DETECTION'
        });
      });

      incident = {
        id: incId,
        incidentId: incId,
        title: newTitle || `Correlated Security Group: ${highestRiskAlert.title}`,
        description: newDescription || `Incident compiled from ${selectedAlerts.length} correlated alert events. Highest risk: ${maxRisk}/100.`,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        detectedAt: highestRiskAlert.timestamp,
        severity: highestRiskAlert.severity,
        priority,
        riskScore: maxRisk,
        status: 'NEW',
        alertIds: selectedAlerts.map(a => a.id),
        correlationIds: selectedAlerts.filter(a => a.correlationId).map(a => a.correlationId as string),
        threatTypes: Array.from(new Set(selectedAlerts.map(a => String(a.threatClassification)))),
        participatingAgents,
        affectedEntities,
        affectedSource: affectedEntities.join(', ') || highestRiskAlert.source,
        evidence: selectedAlerts.flatMap(a => a.evidence).slice(0, 8),
        timeline,
        analystNotes: [
          {
            id: `note-${Date.now()}`,
            timestamp: timeStr,
            author: 'SOC Analyst',
            note: `Grouped ${selectedAlerts.length} alerts into incident ${incId}. Recommended containment: ${highestRiskAlert.recommendedAction}`
          }
        ],
        recommendedActions: [highestRiskAlert.recommendedAction],
        assignedTo: 'SOC Triage Queue',
        mitreTactic: 'TA0001 - Initial Access & Execution',
        mitreTechnique: 'T1190 / T1059',
        containmentRecommendation: highestRiskAlert.recommendedAction,
        summary: `Incident tracking group of ${selectedAlerts.length} alerts affecting ${affectedEntities.join(', ')}.`,
        history: [
          {
            id: `hist-${Date.now()}`,
            timestamp: timeStr,
            action: 'INCIDENT_CREATED_FROM_ALERTS',
            actor: 'SOC Analyst',
            details: `Created incident ${incId} with ${selectedAlerts.length} alerts.`
          }
        ],
        simulatedResponses: []
      };

      this.incidents.unshift(incident);

      // Link alerts
      selectedAlerts.forEach(a => {
        alertManager.assignAlertToIncident(a.id, incident.id);
      });
    }

    this.notify();
    return incident;
  }

  /**
   * Update Incident Status with resolution or false positive details
   */
  public updateIncidentStatus(
    incidentId: string,
    newStatus: IncidentLifecycleStatus,
    resolutionNote?: string,
    actor: string = 'SOC Analyst (Current User)'
  ): boolean {
    const inc = this.getIncidentById(incidentId);
    if (!inc) return false;

    const prevStatus = inc.status;
    if (prevStatus === newStatus) return true;

    const now = new Date();
    const timeStr = now.toLocaleTimeString();

    inc.status = newStatus;
    inc.updatedAt = now.toISOString();

    if (newStatus === 'RESOLVED') {
      inc.resolvedAt = now.toISOString();
      inc.resolution = resolutionNote || 'Incident successfully mitigated and closed.';
    } else if (newStatus === 'FALSE_POSITIVE') {
      inc.falsePositiveReason = resolutionNote || 'Marked as false positive during analyst triage.';
    }

    // Add to timeline
    inc.timeline.unshift({
      id: `tl-status-${Date.now()}`,
      time: timeStr,
      timestamp: timeStr,
      description: resolutionNote
        ? `Status transitioned to ${newStatus}. Details: ${resolutionNote}`
        : `Status transitioned from ${prevStatus} to ${newStatus}`,
      actor,
      phase: newStatus === 'CONTAINED' ? 'CONTAINMENT' : 'INVESTIGATION'
    });

    inc.history.unshift({
      id: `hist-${Date.now()}`,
      timestamp: timeStr,
      action: `STATUS_CHANGED_TO_${newStatus}`,
      actor,
      details: resolutionNote || `Status changed from ${prevStatus} to ${newStatus}.`,
      previousStatus: prevStatus,
      newStatus,
      reason: resolutionNote
    });

    // Sync status change to backend database / local store
    fetch(`/api/incidents/${incidentId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus, reason: resolutionNote, actor })
    }).catch(() => {});

    this.notify();
    return true;
  }

  /**
   * Sync persistent incidents from backend API
   */
  public async syncWithBackend(): Promise<void> {
    try {
      const resp = await fetch('/api/incidents');
      if (!resp.ok) return;
      const data = await resp.json();
      const backendIncidents = Array.isArray(data) ? data : (data.incidents || []);
      if (!Array.isArray(backendIncidents) || backendIncidents.length === 0) return;

      for (const bInc of backendIncidents) {
        const id = bInc.incidentId || bInc.id;
        const existing = this.incidents.find((i) => i.incidentId === id || i.id === id);
        if (existing) {
          if (bInc.status && existing.status !== bInc.status) {
            existing.status = bInc.status;
          }
        } else {
          this.incidents.unshift({
            id: bInc.id || id,
            incidentId: id,
            title: bInc.title || 'Multi-Agent Security Incident',
            description: bInc.description || 'Threat detected by multi-agent analysis',
            createdAt: bInc.createdAt ? new Date(bInc.createdAt).toLocaleString() : new Date().toLocaleString(),
            updatedAt: bInc.updatedAt ? new Date(bInc.updatedAt).toLocaleString() : new Date().toLocaleString(),
            detectedAt: bInc.createdAt ? new Date(bInc.createdAt).toLocaleString() : new Date().toLocaleString(),
            severity: bInc.severity || 'HIGH',
            priority: bInc.priority || 'P1',
            riskScore: bInc.riskScore || 75,
            status: (bInc.status as IncidentLifecycleStatus) || 'NEW',
            alertIds: bInc.alertIds || [],
            correlationIds: bInc.correlationIds || [],
            threatTypes: [bInc.title || 'Multi-Agent Threat'],
            participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'],
            affectedEntities: [bInc.primaryIp || bInc.affectedHost || 'server01'],
            affectedSource: bInc.primaryIp || bInc.affectedHost || 'server01',
            evidence: [`Target Host: ${bInc.affectedHost || 'server01'}`, `Source IP: ${bInc.primaryIp || 'Unknown'}`],
            timeline: [
              {
                id: `tl-${Date.now()}`,
                time: new Date().toLocaleTimeString(),
                timestamp: new Date().toLocaleTimeString(),
                description: `Incident logged with severity ${bInc.severity || 'HIGH'}`,
                actor: 'Multi-Agent Engine',
                phase: 'ALERT'
              }
            ],
            analystNotes: bInc.investigationNotes || [],
            recommendedActions: ['Isolate host', 'Block IP'],
            assignedTo: bInc.assignee || 'Unassigned',
            mitreTactic: 'TA0001 - Initial Access',
            mitreTechnique: (bInc.mitreTechniques && bInc.mitreTechniques[0]) || 'T1190',
            containmentRecommendation: 'Block offending IP address and inspect affected system.',
            summary: bInc.description || bInc.title,
            history: [],
            simulatedResponses: []
          });
        }
      }
      this.notify();
    } catch (err) {
      console.warn('[IncidentManager] Backend sync non-fatal warning:', err);
    }
  }

  /**
   * Assign Incident to an Analyst / Team
   */
  public assignIncident(incidentId: string, assignee: string, actor: string = 'SOC Lead'): boolean {
    const inc = this.getIncidentById(incidentId);
    if (!inc) return false;

    const timeStr = new Date().toLocaleTimeString();
    inc.assignedTo = assignee;
    inc.updatedAt = new Date().toISOString();

    inc.timeline.unshift({
      id: `tl-assign-${Date.now()}`,
      time: timeStr,
      timestamp: timeStr,
      description: `Assigned incident to ${assignee}`,
      actor,
      phase: 'INVESTIGATION'
    });

    inc.history.unshift({
      id: `hist-${Date.now()}`,
      timestamp: timeStr,
      action: 'INCIDENT_REASSIGNED',
      actor,
      details: `Reassigned to ${assignee}`
    });

    this.notify();
    return true;
  }

  /**
   * Add an investigator note
   */
  public addAnalystNote(incidentId: string, noteText: string, author: string = 'SOC Analyst (Current User)'): boolean {
    const inc = this.getIncidentById(incidentId);
    if (!inc) return false;

    const timeStr = new Date().toLocaleTimeString();
    const newNote: AnalystNote = {
      id: `note-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: timeStr,
      author,
      note: noteText
    };

    inc.analystNotes.unshift(newNote);
    inc.updatedAt = new Date().toISOString();

    // Also append to chronological timeline
    inc.timeline.unshift({
      id: `tl-note-${Date.now()}`,
      time: timeStr,
      timestamp: timeStr,
      description: `Analyst Note [${author}]: ${noteText}`,
      actor: author,
      phase: 'INVESTIGATION'
    });

    this.notify();
    return true;
  }

  /**
   * Record a Safe Simulated Response Action
   */
  public recordSimulatedResponse(
    incidentId: string,
    actionType: ResponseSimulationActionType,
    target: string,
    title: string,
    actor: string = 'SOC Analyst'
  ): SimulatedResponseRecord | null {
    const inc = this.getIncidentById(incidentId);
    if (!inc) return null;

    const timeStr = new Date().toLocaleTimeString();
    const record: SimulatedResponseRecord = {
      id: `sim-resp-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: timeStr,
      actionType,
      title,
      target,
      commandSnippet: this.generateSimulatedCommandSnippet(actionType, target),
      disclaimer: 'SIMULATED ACTION ONLY: A real firewall/IP blocking action would be requested here. No network configuration was changed.',
      simulatedBy: actor,
      status: 'SIMULATED_SUCCESS'
    };

    inc.simulatedResponses.unshift(record);
    inc.updatedAt = new Date().toISOString();

    inc.timeline.unshift({
      id: `tl-sim-${Date.now()}`,
      time: timeStr,
      timestamp: timeStr,
      description: `SIMULATED RESPONSE: ${title} on "${target}". (No network rules altered)`,
      actor,
      phase: 'SIMULATION'
    });

    inc.history.unshift({
      id: `hist-${Date.now()}`,
      timestamp: timeStr,
      action: 'SIMULATED_RESPONSE_RECORDED',
      actor,
      details: `${title} simulated on target ${target}. Audit status: SIMULATED_SUCCESS.`
    });

    this.notify();
    return record;
  }

  /**
   * Directly inject a pre-constructed incident (e.g. from workflow engine)
   */
  public addDirectIncident(incident: SecurityIncident): void {
    const existingIndex = this.incidents.findIndex(i => i.id === incident.id || i.incidentId === incident.incidentId);
    if (existingIndex >= 0) {
      this.incidents[existingIndex] = incident;
    } else {
      this.incidents.unshift(incident);
    }
    this.notify();
  }

  /**
   * Append an authorized response simulation record
   */
  public addSimulatedResponse(incidentId: string, record: SimulatedResponseRecord): void {
    const inc = this.getIncidentById(incidentId);
    if (!inc) return;
    if (!inc.simulatedResponses) inc.simulatedResponses = [];
    inc.simulatedResponses.unshift(record);
    this.notify();
  }

  private generateSimulatedCommandSnippet(actionType: ResponseSimulationActionType, target: string): string {
    switch (actionType) {
      case 'BLOCK_IP':
        return `# [SIMULATED] Would execute firewall drop rule:\niptables -I INPUT -s ${target} -j DROP\n# iptables-save > /etc/iptables/rules.v4`;
      case 'ISOLATE_HOST':
        return `# [SIMULATED] Would dispatch host containment via EDR agent:\nedrctl isolate --host ${target} --allow-dhcp --allow-dns-soc`;
      case 'WAF_RULE_DEPLOY':
        return `# [SIMULATED] Would update Web Application Firewall regex rule:\nwafctl rules insert --uri "${target}" --action BLOCK --reason "Exploit_Pattern"`;
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
   * Get Traceability Record for an Alert or Incident (Prompt 09 Section 30)
   * Trace: Alert ID -> Incident ID -> Risk Assessment ID -> Threat Detection ID -> Correlation ID -> Agent Evidence -> Original Log/Event
   */
  public getTraceabilityChain(alertIdOrIncidentId: string): {
    alertId?: string;
    incidentId?: string;
    riskAssessmentId?: string;
    threatDetectionId?: string;
    correlationId?: string;
    participatingAgents: string[];
    evidence: string[];
    summary: string;
  } {
    // Check if it's an incident
    const inc = this.getIncidentById(alertIdOrIncidentId);
    if (inc) {
      const firstAlertId = inc.alertIds[0];
      const alert = firstAlertId ? alertManager.getAlertById(firstAlertId) : undefined;
      return {
        alertId: firstAlertId || (alert ? alert.id : undefined),
        incidentId: inc.id,
        riskAssessmentId: alert?.riskAssessmentId || 'RISK-ASSESS-001',
        threatDetectionId: alert?.threatDetectionId || 'THREAT-ML-2026-001',
        correlationId: inc.correlationIds[0] || alert?.correlationId || 'CORR-2026-001',
        participatingAgents: inc.participatingAgents,
        evidence: inc.evidence,
        summary: `Trace chain: Incident ${inc.id} linked to ${inc.alertIds.length} alert(s) across ${inc.participatingAgents.join(', ')}.`
      };
    }

    // Check if it's an alert
    const alert = alertManager.getAlertById(alertIdOrIncidentId);
    if (alert) {
      return {
        alertId: alert.id,
        incidentId: alert.incidentId,
        riskAssessmentId: alert.riskAssessmentId || 'RISK-ASSESS-001',
        threatDetectionId: alert.threatDetectionId || 'THREAT-ML-2026-001',
        correlationId: alert.correlationId || 'CORR-2026-001',
        participatingAgents: alert.participatingAgents,
        evidence: alert.evidence,
        summary: `Trace chain: Alert ${alert.id} originating from Risk Assessment ${alert.riskAssessmentId || 'N/A'}.`
      };
    }

    return {
      participatingAgents: ['NETWORK_AGENT'],
      evidence: ['No telemetry chain found for requested ID.'],
      summary: 'Unknown traceability entity'
    };
  }
}

export const incidentManager = new IncidentManager();
