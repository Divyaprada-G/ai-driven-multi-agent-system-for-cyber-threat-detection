/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Transparent Severity Rule Engine
 * 
 * Provides deterministic, explainable, and transparent rules
 * to assign alert and incident severity across the 5 required tiers:
 * - Informational
 * - Low
 * - Medium
 * - High
 * - Critical
 */

import { SeverityLevel } from '../../types';

export interface SeverityRuleDefinition {
  id: string;
  name: string;
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  minRiskScore: number;
  maxRiskScore: number;
  criteria: string;
  triggerConditions: string[];
  recommendedAction: string;
}

export interface SeverityEvaluationInput {
  threatCategory?: string;
  threatType?: string;
  riskScore?: number;
  confidence?: number;
  anomalyScore?: number;
  participatingAgents?: string[];
  mitreTactic?: string;
  isMultiStage?: boolean;
  affectedHost?: string;
  eventCount?: number;
  indicators?: string[];
}

export interface SeverityEvaluationResult {
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  normalizedSeverity: SeverityLevel;
  ruleId: string;
  ruleName: string;
  justification: string;
  evaluatedFactors: string[];
  calculatedRiskScore: number;
}

export const TRANSPARENT_SEVERITY_RULES: SeverityRuleDefinition[] = [
  {
    id: 'RULE_CRITICAL_SEV_1',
    name: 'Multi-Stage Infiltration & Critical Compromise',
    severity: 'Critical',
    minRiskScore: 85,
    maxRiskScore: 100,
    criteria: 'Risk Score >= 85, or Multi-Stage cross-agent attack chain, or confirmed Ransomware / Root Privilege Escalation / Data Exfiltration.',
    triggerConditions: [
      'Multi-stage correlation spanning 2 or more specialized agents',
      'High-impact attack pattern (Ransomware, Remote Code Execution, Token Duplication)',
      'Calculated Risk Score >= 85/100',
      'High confidence (>= 85%) on targeted critical infrastructure'
    ],
    recommendedAction: 'Immediate Tier-1 incident containment required. Request human authorization to quarantine host or isolate network flow.'
  },
  {
    id: 'RULE_HIGH_SEV_2',
    name: 'Active Exploitation & Credential Abuse',
    severity: 'High',
    minRiskScore: 70,
    maxRiskScore: 84,
    criteria: 'Risk Score 70-84, or confirmed SQL Injection, SSH / Credential Brute-Force, unauthorized Privilege Escalation attempt, or Lateral Movement.',
    triggerConditions: [
      'SQL Injection or Web Application exploit payload verified',
      'Credential stuffing or repeated authentication breach',
      'Calculated Risk Score between 70 and 84',
      'Lateral reconnaissance with internal pivoting indicators'
    ],
    recommendedAction: 'Engage SOC investigation team. Review affected endpoint, verify authorization for containment, and monitor adjacent subnets.'
  },
  {
    id: 'RULE_MEDIUM_SEV_3',
    name: 'Anomalous Behavior & Port Reconnaissance',
    severity: 'Medium',
    minRiskScore: 40,
    maxRiskScore: 69,
    criteria: 'Risk Score 40-69, or ML Anomaly Score > 0.60, or aggressive port scanning (>20 target ports), or unexpected outbound data spike.',
    triggerConditions: [
      'Isolation Forest anomaly score exceeds baseline threshold (> 0.60)',
      'Active port scanning sweep or service enumeration detected',
      'Calculated Risk Score between 40 and 69',
      'Unusual outbound traffic flow to unclassified external IP'
    ],
    recommendedAction: 'Triage via SOC queue. Validate whether traffic matches authorized network maintenance or penetration testing activity.'
  },
  {
    id: 'RULE_LOW_SEV_4',
    name: 'Suspicious Probe & Minor Policy Violation',
    severity: 'Low',
    minRiskScore: 20,
    maxRiskScore: 39,
    criteria: 'Risk Score 20-39, or single-target ping sweep, unusual user-agent string, non-standard protocol usage without confirmed exploit.',
    triggerConditions: [
      'Isolated perimeter scan or non-standard protocol ping',
      'Unusual HTTP user-agent header without payload execution',
      'Calculated Risk Score between 20 and 39',
      'Minor compliance or configuration deviation'
    ],
    recommendedAction: 'Log and monitor for correlation with subsequent attack phases. No immediate containment needed.'
  },
  {
    id: 'RULE_INFORMATIONAL_SEV_5',
    name: 'Routine Telemetry & Administrative Milestone',
    severity: 'Informational',
    minRiskScore: 0,
    maxRiskScore: 19,
    criteria: 'Risk Score < 20, standard agent heartbeat, authorized service start/stop, benign baseline flow verification.',
    triggerConditions: [
      'Agent health verification or heartbeat check',
      'Scheduled automated maintenance or diagnostic flow',
      'Calculated Risk Score under 20/100',
      'Benign baseline telemetry flow'
    ],
    recommendedAction: 'Record in audit log for historical provenance. Routine tracking.'
  }
];

class SeverityRuleEngine {
  /**
   * Evaluate transparent severity rules against a threat or risk input
   */
  public evaluateSeverity(input: SeverityEvaluationInput): SeverityEvaluationResult {
    const factors: string[] = [];
    let risk = typeof input.riskScore === 'number' ? Math.max(0, Math.min(100, input.riskScore)) : 50;

    const cat = (input.threatCategory || input.threatType || '').toUpperCase();
    const agents = input.participatingAgents || [];
    const isMultiAgent = agents.length >= 2 || Boolean(input.isMultiStage);
    const confidence = input.confidence !== undefined ? input.confidence : 0.8;
    const anomaly = input.anomalyScore !== undefined ? input.anomalyScore : 0.4;

    // Evaluate heuristic indicators
    if (isMultiAgent) {
      factors.push(`Cross-Agent correlation active (${agents.join(', ') || 'Multi-Source'})`);
    }

    if (cat.includes('MULTI_STAGE') || cat.includes('RANSOMWARE') || cat.includes('EXFILTRATION') || cat.includes('ROOT')) {
      factors.push(`Critical threat classification: ${cat}`);
      risk = Math.max(risk, 88);
    } else if (cat.includes('SQL') || cat.includes('INJECTION') || cat.includes('EXPLOIT') || cat.includes('BRUTE') || cat.includes('PRIVILEGE')) {
      factors.push(`Exploitation pattern detected: ${cat}`);
      risk = Math.max(risk, 74);
    } else if (cat.includes('SCAN') || cat.includes('ANOMALY')) {
      factors.push(`Reconnaissance / Anomaly pattern: ${cat}`);
      risk = Math.max(risk, 45);
    } else if (cat.includes('PROBE') || cat.includes('POLICY') || cat.includes('PING') || cat.includes('MINOR')) {
      factors.push(`Minor reconnaissance / policy deviation: ${cat}`);
      if (input.riskScore === undefined) {
        risk = 28;
      }
    } else if (cat.includes('BENIGN') || cat.includes('HEARTBEAT') || cat.includes('INFO') || cat.includes('AUDIT')) {
      factors.push(`Administrative/Benign activity: ${cat}`);
      risk = Math.min(risk, 15);
    }

    if (confidence >= 0.90) {
      factors.push(`High analytical confidence: ${(confidence * 100).toFixed(0)}%`);
    }
    if (anomaly >= 0.70) {
      factors.push(`Severe ML anomaly deviation: ${(anomaly * 100).toFixed(0)}%`);
      risk = Math.max(risk, 65);
    }

    // Apply rule thresholds
    if (risk >= 85 || (isMultiAgent && risk >= 75)) {
      const rule = TRANSPARENT_SEVERITY_RULES[0]; // Critical
      return {
        severity: 'Critical',
        normalizedSeverity: 'CRITICAL',
        ruleId: rule.id,
        ruleName: rule.name,
        justification: `Assigned Critical severity under ${rule.name}: Risk score is ${risk}/100 with ${factors.join('; ')}.`,
        evaluatedFactors: factors,
        calculatedRiskScore: risk
      };
    }

    if (risk >= 70) {
      const rule = TRANSPARENT_SEVERITY_RULES[1]; // High
      return {
        severity: 'High',
        normalizedSeverity: 'HIGH',
        ruleId: rule.id,
        ruleName: rule.name,
        justification: `Assigned High severity under ${rule.name}: Risk score is ${risk}/100. Factors: ${factors.join('; ')}.`,
        evaluatedFactors: factors,
        calculatedRiskScore: risk
      };
    }

    if (risk >= 40) {
      const rule = TRANSPARENT_SEVERITY_RULES[2]; // Medium
      return {
        severity: 'Medium',
        normalizedSeverity: 'MEDIUM',
        ruleId: rule.id,
        ruleName: rule.name,
        justification: `Assigned Medium severity under ${rule.name}: Risk score is ${risk}/100. Factors: ${factors.join('; ')}.`,
        evaluatedFactors: factors,
        calculatedRiskScore: risk
      };
    }

    if (risk >= 20) {
      const rule = TRANSPARENT_SEVERITY_RULES[3]; // Low
      return {
        severity: 'Low',
        normalizedSeverity: 'LOW',
        ruleId: rule.id,
        ruleName: rule.name,
        justification: `Assigned Low severity under ${rule.name}: Minor security anomaly (Risk ${risk}/100). Factors: ${factors.join('; ')}.`,
        evaluatedFactors: factors,
        calculatedRiskScore: risk
      };
    }

    const rule = TRANSPARENT_SEVERITY_RULES[4]; // Informational
    return {
      severity: 'Informational',
      normalizedSeverity: 'INFORMATIONAL',
      ruleId: rule.id,
      ruleName: rule.name,
      justification: `Assigned Informational severity under ${rule.name}: Telemetry baseline milestone (Risk ${risk}/100). Factors: ${factors.join('; ') || 'Standard monitoring'}.`,
      evaluatedFactors: factors,
      calculatedRiskScore: risk
    };
  }

  /**
   * Get the list of all transparent rules for documentation and display in the UI
   */
  public getRules(): SeverityRuleDefinition[] {
    return [...TRANSPARENT_SEVERITY_RULES];
  }

  public getAllRules(): SeverityRuleDefinition[] {
    return this.getRules();
  }
}

export const severityRuleEngine = new SeverityRuleEngine();
