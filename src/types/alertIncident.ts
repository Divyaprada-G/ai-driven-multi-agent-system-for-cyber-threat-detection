/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 9: Alert & Incident Management Data Models & Interfaces
 */

import { SeverityLevel, AgentType, NotificationStatus } from './index';
import { PriorityLevel, RiskFactorContribution, RiskAssessment } from './riskScoring';
import { ThreatClass } from './threatDetection';

export type AlertType =
  | 'NETWORK_THREAT'
  | 'AUTHENTICATION_THREAT'
  | 'PRIVILEGE_ESCALATION'
  | 'WEB_THREAT'
  | 'API_THREAT'
  | 'MULTI_STAGE_THREAT'
  | 'ANOMALY'
  | 'SUSPICIOUS'
  | 'UNKNOWN';

export type AlertLifecycleStatus =
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'SUPPRESSED'
  | 'UNACKNOWLEDGED';

// Backward compatible alias
export type AlertStatus = AlertLifecycleStatus;

export type IncidentLifecycleStatus =
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

// Backward compatible alias
export type IncidentStatus = IncidentLifecycleStatus;

export type ResponseSimulationActionType =
  | 'BLOCK_IP'
  | 'ISOLATE_HOST'
  | 'GENERATE_REPORT'
  | 'ESCALATE_TICKET'
  | 'WAF_RULE_DEPLOY'
  | 'REVOKE_TOKEN';

export interface SimulatedResponseRecord {
  id: string;
  timestamp: string;
  actionType: ResponseSimulationActionType;
  title: string;
  target: string;
  commandSnippet?: string;
  disclaimer: string;
  simulatedBy: string;
  status: 'SIMULATED_SUCCESS';
}

export interface AlertHistoryEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  details: string;
  previousStatus?: AlertLifecycleStatus;
  newStatus?: AlertLifecycleStatus;
  reason?: string;
}

export interface IncidentTimelineEntry {
  id?: string;
  time: string;
  timestamp?: string;
  description: string;
  actor: string;
  phase?: 'DETECTION' | 'CORRELATION' | 'ALERT' | 'INVESTIGATION' | 'CONTAINMENT' | 'SIMULATION';
  relatedEventId?: string;
}

export interface AnalystNote {
  id: string;
  timestamp: string;
  author: string;
  note: string;
}

export interface IncidentHistoryEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  details: string;
  previousStatus?: IncidentLifecycleStatus;
  newStatus?: IncidentLifecycleStatus;
  reason?: string;
}

/**
 * Stage 9: Security Alert Model (Prompt 09 Section 3)
 */
export interface SecurityAlert {
  id: string;
  alertId: string; // Backward compatibility alias
  alertType: AlertType | string;
  title: string;
  threat: string; // Backward compatibility alias
  description: string;
  timestamp: string;
  source: string;
  threatClassification: ThreatClass | string;
  severity: SeverityLevel;
  riskScore: number; // 0 - 100
  priority: PriorityLevel; // P1 - P4
  confidence: number; // 0 - 100
  correlationStrength?: number;

  correlationId?: string;
  threatDetectionId?: string;
  riskAssessmentId?: string;

  affectedEntities: string[];
  participatingAgents: AgentType[];
  evidence: string[];
  riskFactors?: RiskFactorContribution[];
  explanation: string;
  recommendedAction: string;

  status: AlertLifecycleStatus;
  incidentId?: string;

  acknowledgedAt?: string;
  resolvedAt?: string;
  falsePositiveReason?: string;

  isRead: boolean;
  deduplicationCount: number;
  lastSeenTimestamp: string;

  history: AlertHistoryEntry[];
  simulatedResponses: SimulatedResponseRecord[];

  // Explicit workflow fields
  agentName?: string;
  threatCategory?: string;
  detectionMethod?: string;
  incidentStatus?: IncidentLifecycleStatus;

  // Notification and dispatch attributes
  notificationStatus: NotificationStatus;
  targetChannels: string[];
  ruleTriggered: string;
  n8nWorkflowId?: string;
}

/**
 * Stage 9: Security Incident Model (Prompt 09 Section 12)
 */
export interface SecurityIncident {
  id?: string;
  incidentId: string; // Backward compatibility alias
  title?: string;
  description?: string;
  createdAt?: string;
  updatedAt?: string;
  detectedAt: string; // Backward compatibility alias

  severity: SeverityLevel;
  priority?: PriorityLevel;
  riskScore: number;
  status: IncidentLifecycleStatus;

  alertIds?: string[];
  correlationIds?: string[];
  threatTypes?: string[];
  threatType?: string; // Backward compatibility alias
  participatingAgents?: AgentType[];
  affectedEntities?: string[];
  affectedSource: string;

  evidence?: string[];
  timeline: IncidentTimelineEntry[];
  analystNotes?: AnalystNote[];
  recommendedActions?: string[];

  resolution?: string;
  resolvedAt?: string;
  falsePositiveReason?: string;
  assignedTo: string;

  // MITRE framework mapping
  mitreTactic: string;
  mitreTechnique: string;
  containmentRecommendation: string;
  summary: string;

  history?: IncidentHistoryEntry[];
  simulatedResponses?: SimulatedResponseRecord[];
}

// Backward compatibility alias for Incident
export type Incident = SecurityIncident;

/**
 * Alert Generation Rules Configuration
 */
export interface AlertGenerationConfig {
  criticalRiskAutoAlert: boolean;
  highRiskAutoAlert: boolean;
  mediumRiskAutoAlert: boolean;
  mediumRiskThreshold: number; // e.g. 50
  lowRiskAutoAlert: boolean;
  lowRiskThreshold: number; // e.g. 30
  deduplicationWindowMinutes: number; // e.g. 15
  autoGroupCorrelatedIncidents: boolean;
}

/**
 * Future n8n Integration Webhook Payload Schema (Section 41)
 */
export interface N8nAlertPayload {
  alertId: string;
  incidentId: string | null;
  timestamp: string;
  severity: SeverityLevel;
  priority: PriorityLevel;
  riskScore: number;
  threatClassification: string;
  confidence: number;
  status: AlertLifecycleStatus;
  title: string;
  description: string;
  source: string;
  participatingAgents: AgentType[];
  affectedEntities: string[];
  recommendedAction: string;
  exportedAt: string;
  system: {
    source: 'AI-DRIVEN-MULTI-AGENT-SOC';
    version: '1.0.0';
    mode: 'DEMO / SIMULATED';
    dispatchStatus: 'PREPARED_FOR_N8N';
  };
}
