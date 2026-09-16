/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Advanced Security Reporting & Multi-Entity Export Service
 *
 * Implements Sections 27-32 of Prompt 10:
 * - Structured security report generation from live SOC state
 * - Executive summary with calculated figures
 * - Date-range filtering (24H, 7D, 30D, Custom, ALL)
 * - CSV and JSON exports for Alerts, Incidents, Risks, Threats, Events
 * - Relational ID preservation
 */

import { alertManager } from './alertIncident/alertManager';
import { incidentManager } from './alertIncident/incidentManager';
import { riskService } from './riskService';
import { threatDetectionService } from './threatDetectionService';
import { correlationService } from './correlationService';
import { logRepository } from './logRepository';
import { unifiedAnalyticsService } from './unifiedAnalyticsService';
import { TimeRangeFilter } from '../types/analytics';
import { localApiClient } from './apiClient';

export interface StructuredSecurityReport {
  reportId: string;
  title: string;
  generatedAt: string;
  timeRange: TimeRangeFilter;
  dateRangeLabel: string;
  executiveSummary: string;
  eventSummary: {
    totalEvents: number;
    networkEvents: number;
    systemEvents: number;
    applicationEvents: number;
  };
  threatSummary: {
    totalThreats: number;
    criticalThreats: number;
    highThreats: number;
    dominantClassification: string;
  };
  riskSummary: {
    averageRiskScore: number;
    highestRiskScore: number;
    criticalCount: number;
    highCount: number;
  };
  alertSummary: {
    totalAlerts: number;
    openAlerts: number;
    resolvedAlerts: number;
    falsePositives: number;
    falsePositiveRate: string;
  };
  incidentSummary: {
    totalIncidents: number;
    openIncidents: number;
    containedIncidents: number;
    resolvedIncidents: number;
  };
  multiAgentAnalysis: {
    agent: string;
    events: number;
    findings: number;
    threats: number;
  }[];
  threatDistribution: {
    classification: string;
    count: number;
    percentage: number;
  }[];
  riskDistribution: {
    level: string;
    count: number;
    percentage: number;
  }[];
  importantEvents: {
    id: string;
    timestamp: string;
    title: string;
    severity: string;
    riskScore: number;
  }[];
  incidentTimeline: {
    incidentId: string;
    title: string;
    status: string;
    severity: string;
    createdAt: string;
  }[];
  currentStatus: string;
  recommendedActions: string[];
  limitationsAndDemoStatus: string;
}

export const reportService = {
  async generateComprehensiveReport(timeRange: TimeRangeFilter = 'ALL'): Promise<StructuredSecurityReport> {
    const overview = await unifiedAnalyticsService.getSecurityOverview();
    const threatData = await unifiedAnalyticsService.getThreatAnalytics(timeRange);
    const riskData = await unifiedAnalyticsService.getRiskAnalytics();
    const agentData = await unifiedAnalyticsService.getMultiAgentAnalytics();
    const alertIncData = await unifiedAnalyticsService.getAlertIncidentAnalytics();
    const timeline = await unifiedAnalyticsService.getTimelineEvents();
    const incidents = incidentManager.getIncidents();

    const rangeLabels: Record<TimeRangeFilter, string> = {
      '24H': 'Last 24 Hours',
      '7D': 'Last 7 Days',
      '30D': 'Last 30 Days',
      'ALL': 'All Available Historical Data',
      'CUSTOM': 'Custom Date Interval'
    };

    const topThreat = threatData.classifications[0]?.displayName || 'Multi-Stage Infiltration';
    const highCritCount = overview.criticalThreats + overview.highThreats;

    const execSummary = `The AI-Driven Multi-Agent Cyber Threat Detection System monitored ${overview.totalEvents.toLocaleString()} operational security events across Network, System, and Application layers. Analysis identified ${overview.totalThreats} confirmed threat detections, predominantly characterized by ${topThreat}. A total of ${alertIncData.alerts.total} security alerts were generated, with ${highCritCount} prioritized at High or Critical severity. Currently, ${overview.openIncidents} active incident dossier(s) remain open for triage, with an overall False Positive rate of ${overview.falsePositiveRate}.`;

    const reportId = `SOC-REP-${Date.now().toString().slice(-6)}`;
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

    return {
      reportId,
      title: 'Comprehensive Security Threat Intelligence & Incident Dossier',
      generatedAt: now,
      timeRange,
      dateRangeLabel: rangeLabels[timeRange],
      executiveSummary: execSummary,
      eventSummary: {
        totalEvents: overview.totalEvents,
        networkEvents: agentData.agents.find(a => a.id === 'NETWORK_AGENT')?.eventCount || 0,
        systemEvents: agentData.agents.find(a => a.id === 'SYSTEM_AGENT')?.eventCount || 0,
        applicationEvents: agentData.agents.find(a => a.id === 'APPLICATION_AGENT')?.eventCount || 0
      },
      threatSummary: {
        totalThreats: overview.totalThreats,
        criticalThreats: overview.criticalThreats,
        highThreats: overview.highThreats,
        dominantClassification: topThreat
      },
      riskSummary: {
        averageRiskScore: riskData.averageRiskScore,
        highestRiskScore: riskData.highestRiskScore,
        criticalCount: riskData.criticalRiskCount,
        highCount: riskData.highRiskCount
      },
      alertSummary: {
        totalAlerts: alertIncData.alerts.total,
        openAlerts: overview.openAlerts,
        resolvedAlerts: alertIncData.alerts.resolved,
        falsePositives: alertIncData.alerts.falsePositive,
        falsePositiveRate: overview.falsePositiveRate
      },
      incidentSummary: {
        totalIncidents: alertIncData.incidents.total,
        openIncidents: alertIncData.incidents.new + alertIncData.incidents.investigating,
        containedIncidents: alertIncData.incidents.contained,
        resolvedIncidents: alertIncData.incidents.resolved
      },
      multiAgentAnalysis: agentData.agents.map(a => ({
        agent: a.name,
        events: a.eventCount,
        findings: a.findingCount,
        threats: a.threatContribution
      })),
      threatDistribution: threatData.classifications.slice(0, 6).map(c => ({
        classification: c.displayName,
        count: c.count,
        percentage: c.percentage
      })),
      riskDistribution: riskData.riskDistribution.map(r => ({
        level: `${r.level} (${r.range})`,
        count: r.count,
        percentage: r.percentage
      })),
      importantEvents: timeline
        .filter(t => t.severity === 'CRITICAL' || t.severity === 'HIGH')
        .slice(0, 6)
        .map(t => ({
          id: t.id,
          timestamp: t.timestamp,
          title: t.title,
          severity: t.severity,
          riskScore: t.riskScore || 0
        })),
      incidentTimeline: incidents.slice(0, 5).map(i => ({
        incidentId: i.id,
        title: i.title,
        status: i.status,
        severity: i.severity,
        createdAt: i.createdAt
      })),
      currentStatus: `Application Security Activity: ${overview.securityPosture}. ${overview.postureDescription}`,
      recommendedActions: [
        'Enforce multi-factor verification across all public-facing auth endpoints and API gateways.',
        'Review Sysmon and Wazuh host agent integrity rules on critical financial and database servers.',
        'Review web application firewall parameter filtering on legacy unauthenticated checkout routes.',
        'Conduct cross-agent forensic audit on pivot IP addresses identified in multi-stage clusters.',
        'Validate planned n8n automated response workflows prior to production dispatch.'
      ],
      limitationsAndDemoStatus:
        'DEMO / ACADEMIC SIMULATION: All telemetry is evaluated locally in a safe simulated runtime. No external network reconfiguration, firewall blocking, or host isolation was triggered on production hosts. Models are verified via deterministic evaluation heuristics.'
    };
  },

  exportCSV(data: Record<string, unknown>[], filenamePrefix = 'soc_threat_export'): void {
    if (!data || !data.length) return;
    const headers = Object.keys(data[0]);
    const csvRows = [
      headers.join(','),
      ...data.map(row =>
        headers
          .map(header => {
            const val = row[header];
            const str = typeof val === 'object' ? JSON.stringify(val) : String(val ?? '');
            return `"${str.replace(/"/g, '""')}"`;
          })
          .join(',')
      )
    ];
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filenamePrefix}_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  },

  exportJSON(data: unknown, filenamePrefix = 'soc_threat_export'): void {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filenamePrefix}_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  },

  /**
   * Export specific entity collections maintaining relational IDs (Section 31 & 32)
   */
  async exportEntities(entityType: 'ALERTS' | 'INCIDENTS' | 'RISKS' | 'THREATS' | 'EVENTS' | 'ALL_RELATIONAL', format: 'CSV' | 'JSON'): Promise<void> {
    const alerts = alertManager.getAlerts();
    const incidents = incidentManager.getIncidents();
    const risks = await riskService.getRiskAssessments();
    const threats = await threatDetectionService.getDetectionResults();

    let exportData: unknown = null;
    let filenamePrefix = 'soc_export';

    if (entityType === 'ALERTS') {
      filenamePrefix = 'soc_alerts';
      exportData = alerts.map(a => ({
        alertId: a.id,
        incidentId: a.incidentId || '',
        riskAssessmentId: a.riskAssessmentId || '',
        threatDetectionId: a.threatDetectionId || '',
        correlationId: a.correlationId || '',
        title: a.title,
        severity: a.severity,
        priority: a.priority,
        riskScore: a.riskScore,
        status: a.status,
        threatClassification: a.threatClassification,
        createdAt: (a as any).createdAt || a.timestamp,
        summary: a.description || (a as any).summary || ''
      }));
    } else if (entityType === 'INCIDENTS') {
      filenamePrefix = 'soc_incidents';
      exportData = incidents.map(i => ({
        incidentId: i.id || i.incidentId,
        correlationId: i.correlationIds?.[0] || '',
        title: i.title || i.incidentId,
        severity: i.severity,
        priority: i.priority || 'P2',
        riskScore: i.riskScore,
        status: i.status,
        assignedTo: i.assignedTo || '',
        createdAt: i.createdAt || i.detectedAt,
        updatedAt: i.updatedAt || i.detectedAt,
        alertCount: i.alertIds?.length || 0
      }));
    } else if (entityType === 'RISKS') {
      filenamePrefix = 'soc_risk_assessments';
      exportData = risks.map(r => ({
        riskAssessmentId: r.id,
        threatDetectionId: r.threatDetectionId,
        correlationId: r.correlationId || '',
        threatClassification: r.threatClassification,
        riskScore: r.riskScore,
        severity: r.severity,
        priority: r.priority,
        status: r.status,
        calculatedAt: r.auditTrail?.calculatedAt || r.timestamp || '',
        modelUsed: r.auditTrail?.modelUsed || ''
      }));
    } else if (entityType === 'THREATS') {
      filenamePrefix = 'soc_threat_detections';
      exportData = threats.map(t => ({
        threatId: t.id,
        correlationId: t.correlationId,
        classification: t.classification,
        severity: t.severity,
        confidence: (t.confidence * 100).toFixed(1) + '%',
        model: t.model,
        modelStatus: t.modelStatus,
        timestamp: t.timestamp
      }));
    } else if (entityType === 'EVENTS') {
      filenamePrefix = 'soc_security_events';
      if (logRepository.hasRealData()) {
        const { events } = logRepository.getEvents();
        exportData = events.slice(0, 100).map(e => ({
          eventId: e.id,
          timestamp: e.timestamp,
          logType: e.logType,
          source: e.source,
          message: e.message,
          sourceIp: e.normalizedFields?.sourceIp || '',
          destinationIp: e.normalizedFields?.destinationIp || '',
          validationStatus: e.validation?.status || 'VALID'
        }));
      } else {
        exportData = [
          { eventId: 'EVT-DEMO-01', logType: 'NETWORK', source: 'suricata_eve.json', message: 'SURICATA ET SCAN Potential Port Scan', timestamp: '2026-09-12 00:08:45' },
          { eventId: 'EVT-DEMO-02', logType: 'APPLICATION', source: 'nginx_access.log', message: 'GET /api/v1/auth?id=1+UNION+SELECT 200', timestamp: '2026-09-12 00:09:12' },
          { eventId: 'EVT-DEMO-03', logType: 'SYSTEM', source: 'sysmon.csv', message: 'Process Create cmd.exe parent spoolsv.exe', timestamp: '2026-09-12 00:09:40' }
        ];
      }
    } else if (entityType === 'ALL_RELATIONAL') {
      filenamePrefix = 'soc_relational_bundle';
      exportData = {
        metadata: {
          exportedAt: new Date().toISOString(),
          system: 'AI-Driven Multi-Agent Cyber Threat Detection',
          version: 'Stage 10 Complete',
          mode: 'DEMO / EVALUATION DATASET'
        },
        incidents,
        alerts,
        riskAssessments: risks,
        threatDetections: threats
      };
    }

    if (format === 'JSON') {
      this.exportJSON(exportData, filenamePrefix);
    } else {
      if (Array.isArray(exportData)) {
        this.exportCSV(exportData as Record<string, unknown>[], filenamePrefix);
      } else {
        // Fallback for non-tabular object
        this.exportJSON(exportData, filenamePrefix);
      }
    }
  }
};
