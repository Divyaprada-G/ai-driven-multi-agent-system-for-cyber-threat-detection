/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Centralized Risk Scoring Engine Configuration
 *
 * NOTE: Clearly labeled as "Configurable Academic/Demo Risk Model".
 * Risk bands and factor weights are configurable academic/demo thresholds
 * and are not universal industry standards.
 */

import { RiskModelConfig } from '../../types/riskScoring';

export const RISK_CONFIG: RiskModelConfig = {
  name: 'Academic-MultiFactor-RiskModel-v1',
  label: 'Configurable Academic/Demo Risk Model',
  version: '1.0.0-academic',
  weights: {
    threatSeverity: 0.30, // 30% contribution
    mlConfidence: 0.20, // 20% contribution
    correlationStrength: 0.15, // 15% contribution
    attackComplexity: 0.15, // 15% contribution
    agentInvolvement: 0.10, // 10% contribution
    evidenceVolume: 0.05, // 5% contribution
    affectedEntities: 0.05 // 5% contribution
  },
  severityPoints: {
    INFORMATIONAL: 10,
    LOW: 25,
    MEDIUM: 50,
    HIGH: 75,
    CRITICAL: 100
  },
  agentInvolvementPoints: {
    zero: 0,
    one: 33.3,
    two: 66.6,
    three: 100.0
  },
  riskBands: {
    LOW: { min: 0, max: 30, priority: 'P4' },
    MEDIUM: { min: 31, max: 60, priority: 'P3' },
    HIGH: { min: 61, max: 80, priority: 'P2' },
    CRITICAL: { min: 81, max: 100, priority: 'P1' }
  },
  disclaimer:
    'Risk bands are configurable academic/demo thresholds and are not universal industry standards.'
};
