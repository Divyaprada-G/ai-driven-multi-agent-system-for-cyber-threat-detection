/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Scoring & Threat Prioritization Data Types
 */

import { SeverityLevel, AgentType } from './index';
import { ThreatClass } from './threatDetection';

export type PriorityLevel = 'P1' | 'P2' | 'P3' | 'P4';

export type RiskBand = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type RiskStatus = 'NEW' | 'REVIEWING' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';

export type RiskFactorName =
  | 'threatSeverity'
  | 'mlConfidence'
  | 'correlationStrength'
  | 'attackComplexity'
  | 'agentInvolvement'
  | 'evidenceVolume'
  | 'affectedEntities';

export interface RiskFactorContribution {
  name: RiskFactorName;
  label: string;
  rawScore: number; // 0 - 100 normalized score
  weight: number; // e.g. 0.30
  weightedScore: number; // rawScore * weight (e.g. 22.5)
  maxPossibleWeightedScore: number; // weight * 100 (e.g. 30.0)
  description: string;
  evidenceItems?: string[];
  evidence?: string[];
}

export interface RiskModelConfig {
  name: string;
  label: string;
  version: string;
  weights: {
    threatSeverity: number; // 0.30 (30%)
    mlConfidence: number; // 0.20 (20%)
    correlationStrength: number; // 0.15 (15%)
    attackComplexity: number; // 0.15 (15%)
    agentInvolvement: number; // 0.10 (10%)
    evidenceVolume: number; // 0.05 (5%)
    affectedEntities: number; // 0.05 (5%)
  };
  severityPoints: Record<SeverityLevel, number>;
  agentInvolvementPoints: {
    zero: number;
    one: number;
    two: number;
    three: number;
  };
  riskBands: {
    LOW: { min: number; max: number; priority: PriorityLevel };
    MEDIUM: { min: number; max: number; priority: PriorityLevel };
    HIGH: { min: number; max: number; priority: PriorityLevel };
    CRITICAL: { min: number; max: number; priority: PriorityLevel };
  };
  disclaimer: string;
}

/**
 * Clean Explainable Risk Assessment Interface (Prompt 08 Specification)
 */
export interface RiskAssessment {
  id: string;
  threatDetectionId: string;
  correlationId: string;
  timestamp: string;

  // Primary Triaged Risk
  riskScore: number; // 0 - 100 clamped, rounded
  severity: SeverityLevel;
  priority: PriorityLevel; // P1 (Critical), P2 (High), P3 (Medium), P4 (Low)
  riskBand: RiskBand;

  confidence: number; // 0 - 100 normalized

  // Multi-Factor Breakdown
  riskFactors: RiskFactorContribution[];

  threatClassification: ThreatClass | string;
  explanation: string;

  recommendedAction: string;

  status: RiskStatus;

  // Multi-Agent Architecture Context
  participatingAgents: AgentType[];
  evidenceVolume: number;
  affectedEntitiesCount: number;
  affectedSource: string;

  // Auditability & Traceability Metadata
  auditTrail: {
    calculatedAt: string;
    modelUsed: string;
    correlationStrength: number;
    mlAnomalyScore: number;
    weightsConfigVersion: string;
  };

  // Backward compatibility fields for existing UI components
  score: number; // alias for riskScore
  threatCategory?: string;
  factors?: {
    assetCriticality: number;
    exploitability: number;
    lateralMovementPotential: number;
    dataLossExposure: number;
  };
  remediationPlan: string[];
}

/**
 * Output format prepared for future n8n consumption (Section 33)
 */
export interface N8nPreparedPayload {
  riskAssessmentId: string;
  threatDetectionId: string;
  correlationId: string;
  riskScore: number;
  severity: SeverityLevel;
  priority: PriorityLevel;
  threatClassification: string;
  confidence: number;
  timestamp: string;
  recommendedAction: string;
  participatingAgents: AgentType[];
  affectedSource: string;
  status: RiskStatus;
  exportTimestamp: string;
  systemVersion: string;
}
