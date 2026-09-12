import { SecurityFinding, CorrelationStrength, CorrelationRuleResult } from '../types/correlation';
import { SeverityLevel } from '../types';

export interface ScoreCalculationResult {
  confidence: number; // 0.00 to 1.00
  strength: CorrelationStrength;
  severity: SeverityLevel;
  breakdown: {
    factor: string;
    weight: number;
    contribution: number;
    explanation: string;
  }[];
}

export class CorrelationScorer {
  /**
   * Computes deterministic, mathematical correlation confidence & strength
   */
  public static calculate(
    findings: SecurityFinding[],
    ruleResults: CorrelationRuleResult[]
  ): ScoreCalculationResult {
    const breakdown: ScoreCalculationResult['breakdown'] = [];

    // Base score from rule evaluations
    let weightedScoreSum = 0;
    let totalWeights = 0;

    // 1. Shared Entity Weights (Source IP, Host, Username)
    const srcIpRule = ruleResults.find(r => r.category === 'SOURCE_IP_MATCH');
    if (srcIpRule?.matched) {
      const weight = 0.25;
      const contrib = srcIpRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Shared Source IP',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: srcIpRule.reason
      });
    }

    const hostRule = ruleResults.find(r => r.category === 'HOST_MATCH');
    if (hostRule?.matched) {
      const weight = 0.20;
      const contrib = hostRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Common Target Host',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: hostRule.reason
      });
    }

    const userRule = ruleResults.find(r => r.category === 'USERNAME_MATCH');
    if (userRule?.matched) {
      const weight = 0.20;
      const contrib = userRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Shared User Identity',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: userRule.reason
      });
    }

    // 2. Cross-Agent Synergy Weight
    const crossAgentRule = ruleResults.find(r => r.category === 'CROSS_AGENT_ACTIVITY');
    if (crossAgentRule?.matched) {
      const weight = 0.25;
      const contrib = crossAgentRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Cross-Agent Multi-Domain Involvement',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: crossAgentRule.reason
      });
    }

    // 3. Attack Sequence Weight
    const seqRule = ruleResults.find(r => r.category === 'EVENT_SEQUENCE');
    if (seqRule?.matched) {
      const weight = 0.20;
      const contrib = seqRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Attack Progression Sequence',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: seqRule.reason
      });
    }

    // 4. Temporal Window Weight
    const timeRule = ruleResults.find(r => r.category === 'TIME_PROXIMITY');
    if (timeRule?.matched) {
      const weight = 0.15;
      const contrib = timeRule.score * weight;
      weightedScoreSum += contrib;
      totalWeights += weight;
      breakdown.push({
        factor: 'Temporal Proximity',
        weight,
        contribution: Math.round(contrib * 100) / 100,
        explanation: timeRule.reason
      });
    }

    // 5. Base Agent Confidence Average
    const avgFindingConf = findings.reduce((acc, f) => acc + (f.confidence || 0.8), 0) / (findings.length || 1);
    const agentWeight = 0.15;
    const agentContrib = avgFindingConf * agentWeight;
    weightedScoreSum += agentContrib;
    totalWeights += agentWeight;
    breakdown.push({
      factor: 'Underlying Agent Detection Confidence',
      weight: agentWeight,
      contribution: Math.round(agentContrib * 100) / 100,
      explanation: `Average confidence of ${findings.length} supporting findings: ${Math.round(avgFindingConf * 100)}%`
    });

    // Compute raw confidence
    const rawConfidence = totalWeights > 0 ? (weightedScoreSum / totalWeights) : 0.5;

    // Apply strict safety bounds: Never claim 1.00 (never "Confirmed Attack"), minimum 0.15
    const confidence = Math.min(0.96, Math.max(0.15, Math.round(rawConfidence * 100) / 100));

    // Determine Correlation Strength (distinct from threat severity)
    let strength: CorrelationStrength = 'LOW';
    if (confidence >= 0.75 && findings.length >= 2) {
      strength = 'HIGH';
    } else if (confidence >= 0.50) {
      strength = 'MEDIUM';
    } else {
      strength = 'LOW';
    }

    // Determine Combined Threat Severity
    // Priority: CRITICAL > HIGH > MEDIUM > LOW
    const severities = findings.map(f => f.severity);
    let severity: SeverityLevel = 'LOW';
    if (severities.includes('CRITICAL')) {
      severity = 'CRITICAL';
    } else if (severities.includes('HIGH')) {
      severity = 'HIGH';
    } else if (severities.includes('MEDIUM')) {
      severity = 'MEDIUM';
    }

    // If correlation strength is HIGH and there's multi-stage attack progression with authentication abuse or injection, escalate
    if (strength === 'HIGH' && seqRule?.matched && seqRule.score > 0.85 && severity === 'MEDIUM') {
      severity = 'HIGH';
    }

    return {
      confidence,
      strength,
      severity,
      breakdown
    };
  }
}
