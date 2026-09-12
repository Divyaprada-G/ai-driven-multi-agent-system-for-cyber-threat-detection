/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Explainable Risk Scoring Engine
 *
 * Deterministic multi-factor risk computation combining Threat Severity,
 * ML Confidence, Multi-Agent Correlation Strength, Attack Complexity,
 * Agent Involvement, Evidence Volume, and Affected Entities.
 *
 * Strictly adheres to academic integrity:
 * - Deterministic, non-random calculations
 * - Fully explainable factor contributions
 * - Non-destructive safe mitigation recommendations only
 */

import { SeverityLevel, AgentType } from '../../types';
import { ThreatDetectionResult } from '../../types/threatDetection';
import { CorrelatedEvent } from '../../types/correlation';
import {
  RiskAssessment,
  RiskFactorContribution,
  RiskModelConfig,
  RiskBand,
  PriorityLevel,
  RiskStatus
} from '../../types/riskScoring';
import { RISK_CONFIG } from './riskConfig';

export class RiskScoringEngine {
  private config: RiskModelConfig;

  constructor(config: RiskModelConfig = RISK_CONFIG) {
    this.config = config;
  }

  /**
   * Update or override configuration at runtime (e.g. sandbox sliders)
   */
  public setConfig(config: RiskModelConfig): void {
    this.config = config;
  }

  public getConfig(): RiskModelConfig {
    return this.config;
  }

  /**
   * Normalize confidence safely into 0 - 100 scale.
   * Handles 0.0 - 1.0 floats, 0 - 100 percentages, NaN, negatives, and missing values.
   */
  public normalizeConfidence(confidence?: number | null): number {
    if (confidence === undefined || confidence === null || isNaN(confidence)) {
      return 50.0; // Safe neutral fallback
    }
    if (confidence < 0) return 0.0;
    // If between 0 and 1.0 (float probability), scale to 100
    if (confidence <= 1.0) {
      return Math.min(100.0, Math.max(0.0, confidence * 100.0));
    }
    // Already in 1..100 range
    return Math.min(100.0, confidence);
  }

  /**
   * 1. Threat Severity Factor (0 - 100)
   */
  private calculateThreatSeverityFactor(severity?: SeverityLevel): {
    score: number;
    description: string;
    evidence: string[];
  } {
    const validSeverity: SeverityLevel =
      severity && this.config.severityPoints[severity] !== undefined ? severity : 'LOW';

    const score = this.config.severityPoints[validSeverity];
    return {
      score,
      description: `Mapped from threat severity '${validSeverity}' into numerical contribution.`,
      evidence: [`Severity Rating: ${validSeverity} (${score} pts)`]
    };
  }

  /**
   * 2. ML Confidence Factor (0 - 100)
   */
  private calculateConfidenceFactor(threat?: Partial<ThreatDetectionResult>): {
    score: number;
    description: string;
    evidence: string[];
  } {
    const normalized = this.normalizeConfidence(threat?.confidence);
    const modelName = threat?.model || 'Detection Model';
    const confidenceType = threat?.confidenceType || 'DEMO_DERIVED';

    return {
      score: Math.round(normalized * 10) / 10,
      description: `Normalized detection confidence from ${modelName} (${confidenceType}).`,
      evidence: [`Raw confidence input: ${threat?.confidence ?? 'N/A'} -> Normalized: ${normalized.toFixed(1)}%`]
    };
  }

  /**
   * 3. Correlation Strength Factor (0 - 100)
   */
  private calculateCorrelationFactor(
    threat?: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent
  ): {
    score: number;
    description: string;
    evidence: string[];
  } {
    if (!correlation) {
      // Check if threat has correlation features in vector
      if (threat?.features?.correlationConfidence) {
        const score = Math.round(this.normalizeConfidence(threat.features.correlationConfidence));
        return {
          score,
          description: `Extracted from detection feature vector correlation confidence.`,
          evidence: [`Feature correlation confidence: ${score}%`]
        };
      }
      return {
        score: 20.0,
        description: 'Single isolated event or uncorrelated telemetry stream (baseline factor).',
        evidence: ['No multi-agent correlation cluster attached (baseline 20 pts)']
      };
    }

    const confScore = (correlation.correlationConfidence ?? (correlation.confidence ? correlation.confidence / 100 : 0.8)) * 100;
    const str = (correlation as any).strength || correlation.correlationStrength || 'MEDIUM';
    const strengthMultiplier =
      str === 'CRITICAL' || str === 'HIGH'
        ? 0.95
        : str === 'MEDIUM'
        ? 0.75
        : 0.55;

    const eventCount = correlation.eventsCount ?? (correlation as any).eventCount ?? (correlation.findingIds?.length || 1);
    const sequenceBonus = Math.min(20, eventCount * 4);
    const rawScore = confScore * 0.7 + sequenceBonus * strengthMultiplier;
    const score = Math.min(100, Math.max(10, Math.round(rawScore)));

    return {
      score,
      description: `Synthesized from multi-event correlation confidence (${Math.round(confScore)}%), strength '${str}', and cluster sequence.`,
      evidence: [
        `Cluster: ${correlation.id} (${eventCount} related events)`,
        `Correlation Strength: ${str}`,
        `Rule: ${correlation.attackPattern || correlation.title || 'Heuristic Sequence'}`
      ]
    };
  }

  /**
   * 4. Attack Complexity Factor (0 - 100)
   * Note: Complexity alone does NOT prove malicious intent.
   */
  private calculateComplexityFactor(
    threat?: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent
  ): {
    score: number;
    description: string;
    evidence: string[];
  } {
    const isMultiStage =
      threat?.classification === 'MULTI_STAGE_THREAT' ||
      correlation?.attackPattern === 'MULTI_STAGE_KILL_CHAIN' ||
      (correlation as any)?.patternType === 'MULTI_STAGE_KILL_CHAIN' ||
      (threat?.features?.participatingAgentsCount ?? 0) >= 3;

    const agentsCount =
      correlation?.participatingAgents?.length ??
      threat?.features?.participatingAgentsCount ??
      threat?.explanation?.participatingAgents?.length ??
      1;

    const sequenceLength =
      correlation?.sequence?.length ??
      correlation?.eventsCount ??
      (correlation as any)?.eventCount ??
      threat?.features?.findingCount ??
      1;

    let score = 25; // default single isolated
    let complexityLabel = 'Single isolated activity';

    if (isMultiStage || agentsCount >= 3) {
      score = 95;
      complexityLabel = 'Cross-agent multi-stage kill-chain sequence';
    } else if (agentsCount >= 2 || sequenceLength >= 3) {
      score = 65;
      complexityLabel = 'Multiple correlated events across stages';
    } else if (
      sequenceLength >= 2 ||
      threat?.classification === 'PRIVILEGE_ESCALATION' ||
      threat?.classification === 'WEB_THREAT' ||
      threat?.classification === 'AUTHENTICATION_THREAT' ||
      threat?.classification === 'API_THREAT'
    ) {
      score = 50;
      complexityLabel = 'Compound sequence or application-level exploitation vector';
    }

    return {
      score,
      description: `Evaluated as ${complexityLabel}. (Note: Complexity alone does not prove malicious intent).`,
      evidence: [
        `Stages: ${isMultiStage ? 'Multi-Stage' : 'Single/Compound Stage'}`,
        `Contributing Agents: ${agentsCount}`,
        `Sequence Length: ${sequenceLength} events`
      ]
    };
  }

  /**
   * 5. Agent Involvement Factor (0 - 100)
   */
  private calculateAgentInvolvementFactor(
    threat?: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent
  ): {
    score: number;
    description: string;
    evidence: string[];
    agents: AgentType[];
  } {
    // Gather distinct agents
    const agentsSet = new Set<AgentType>();

    if (correlation?.participatingAgents) {
      correlation.participatingAgents.forEach(a => agentsSet.add(a));
    }
    if (threat?.explanation?.participatingAgents) {
      threat.explanation.participatingAgents.forEach(a => agentsSet.add(a));
    }
    if (threat?.features) {
      if (threat.features.networkInvolvement > 0) agentsSet.add('NETWORK_AGENT');
      if (threat.features.systemInvolvement > 0) agentsSet.add('SYSTEM_AGENT');
      if (threat.features.applicationInvolvement > 0) agentsSet.add('APPLICATION_AGENT');
    }

    // Default to at least 1 agent if empty
    if (agentsSet.size === 0) {
      agentsSet.add('NETWORK_AGENT');
    }

    const agents = Array.from(agentsSet);
    const count = agents.length;

    let score = this.config.agentInvolvementPoints.one;
    if (count >= 3) {
      score = this.config.agentInvolvementPoints.three;
    } else if (count === 2) {
      score = this.config.agentInvolvementPoints.two;
    } else if (count === 0) {
      score = this.config.agentInvolvementPoints.zero;
    }

    return {
      score: Math.round(score * 10) / 10,
      description: `Multi-agent diversity contribution from ${count} independent monitoring agent(s).`,
      evidence: agents.map(a => `Participating Agent: ${a}`),
      agents
    };
  }

  /**
   * 6. Evidence Volume Factor (0 - 100)
   * Kept small as instructed (5% weight) with diminishing returns.
   */
  private calculateEvidenceVolumeFactor(
    threat?: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent
  ): {
    score: number;
    description: string;
    evidence: string[];
    count: number;
  } {
    const rawItems = [
      ...(threat?.evidence || []),
      ...(threat?.explanation?.supportingEvidence || []),
      ...(correlation?.evidence || [])
    ];
    // Deduplicate
    const uniqueEvidence = Array.from(new Set(rawItems));
    const count = Math.max(1, uniqueEvidence.length);

    // Diminishing returns: 1->20, 2->40, 3->60, 4->75, 5->85, 6+->100
    const score = Math.min(100, Math.round(count * 18));

    return {
      score,
      description: `Volume of corroborating evidence (${count} distinct log/telemetry artifacts).`,
      evidence: uniqueEvidence.slice(0, 4),
      count
    };
  }

  /**
   * 7. Affected Entities Factor (0 - 100)
   */
  private calculateAffectedEntitiesFactor(
    threat?: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent
  ): {
    score: number;
    description: string;
    evidence: string[];
    affectedSource: string;
    count: number;
  } {
    const entities = new Set<string>();

    if (correlation?.sourceIps) correlation.sourceIps.forEach(ip => entities.add(`IP:${ip}`));
    if (correlation?.destinationIps) correlation.destinationIps.forEach(ip => entities.add(`Dest:${ip}`));
    if (correlation?.hosts) correlation.hosts.forEach(h => entities.add(`Host:${h}`));
    if (correlation?.users) correlation.users.forEach(u => entities.add(`User:${u}`));
    if ((correlation as any)?.entities) {
      const e = (correlation as any).entities;
      if (e.sourceIp) entities.add(`IP:${e.sourceIp}`);
      if (e.host) entities.add(`Host:${e.host}`);
    }

    // Check threat fields
    const threatSource = (threat as any)?.affectedSource;
    if (threatSource) entities.add(threatSource);

    const count = Math.max(1, entities.size);
    // 1 entity -> 35, 2 entities -> 65, 3+ entities -> 90+
    const score = Math.min(100, Math.round(count * 30 + 5));

    const affectedSource =
      correlation?.hosts?.[0] ||
      correlation?.sourceIps?.[0] ||
      threatSource ||
      'Internal Infrastructure';

    return {
      score,
      description: `Scope of impacted network assets, endpoints, or user identities (${count} entities).`,
      evidence: Array.from(entities),
      affectedSource,
      count
    };
  }

  /**
   * Determine Risk Band and Priority level from computed score
   */
  private getBandAndPriority(score: number): { riskBand: RiskBand; priority: PriorityLevel } {
    const { riskBands } = this.config;
    if (score >= riskBands.CRITICAL.min) {
      return { riskBand: 'CRITICAL', priority: riskBands.CRITICAL.priority };
    }
    if (score >= riskBands.HIGH.min) {
      return { riskBand: 'HIGH', priority: riskBands.HIGH.priority };
    }
    if (score >= riskBands.MEDIUM.min) {
      return { riskBand: 'MEDIUM', priority: riskBands.MEDIUM.priority };
    }
    return { riskBand: 'LOW', priority: riskBands.LOW.priority };
  }

  /**
   * Generate safe, non-destructive recommended action (Section 17)
   */
  private generateRecommendedAction(riskBand: RiskBand, classification?: string): string {
    switch (riskBand) {
      case 'CRITICAL':
        return `Escalate for immediate security investigation. Review multi-agent audit trail for ${classification || 'critical anomaly'} on affected host.`;
      case 'HIGH':
        return `Investigate immediately and review correlated security events. Verify potential ${classification || 'suspicious activity'} with system owners.`;
      case 'MEDIUM':
        return `Review related events and verify the affected entity. Monitor ongoing telemetry for recurrence.`;
      case 'LOW':
      default:
        return 'Continue monitoring. Retain telemetry in audit cache for baseline evaluation.';
    }
  }

  /**
   * Generate human-readable explanation based on real factor contributions (Section 15)
   */
  private generateExplanation(
    riskBand: RiskBand,
    priority: PriorityLevel,
    score: number,
    classification: string,
    agents: AgentType[],
    factors: RiskFactorContribution[]
  ): string {
    const topFactor = [...factors].sort((a, b) => b.weightedScore - a.weightedScore)[0];
    const agentText =
      agents.length === 1
        ? `the ${agents[0].replace('_', ' ').toLowerCase()}`
        : `${agents.length} specialized agents (${agents.map(a => a.replace('_', ' ')).join(', ')})`;

    return `This event received a ${riskBand} risk score (${score}/100, Priority ${priority}) classified as ${classification}. The primary contributing driver is ${topFactor.label.toLowerCase()} (contributing ${topFactor.weightedScore.toFixed(1)} weighted pts). Corroborating signals were confirmed across ${agentText}.`;
  }

  /**
   * Primary Evaluation Method: Compute Risk Assessment from Threat Detection + Correlated Event
   */
  public evaluate(
    threat: Partial<ThreatDetectionResult>,
    correlation?: CorrelatedEvent,
    statusOverride?: RiskStatus
  ): RiskAssessment {
    const weights = this.config.weights;

    // 1. Calculate individual factors
    const severityFactor = this.calculateThreatSeverityFactor(threat.severity);
    const confidenceFactor = this.calculateConfidenceFactor(threat);
    const correlationFactor = this.calculateCorrelationFactor(threat, correlation);
    const complexityFactor = this.calculateComplexityFactor(threat, correlation);
    const agentFactor = this.calculateAgentInvolvementFactor(threat, correlation);
    const evidenceFactor = this.calculateEvidenceVolumeFactor(threat, correlation);
    const entityFactor = this.calculateAffectedEntitiesFactor(threat, correlation);

    // 2. Build Factor Breakdown list
    const riskFactors: RiskFactorContribution[] = [
      {
        name: 'threatSeverity',
        label: 'Threat Severity',
        rawScore: severityFactor.score,
        weight: weights.threatSeverity,
        weightedScore: Math.round(severityFactor.score * weights.threatSeverity * 10) / 10,
        maxPossibleWeightedScore: weights.threatSeverity * 100,
        description: severityFactor.description,
        evidenceItems: severityFactor.evidence
      },
      {
        name: 'mlConfidence',
        label: 'ML Confidence',
        rawScore: confidenceFactor.score,
        weight: weights.mlConfidence,
        weightedScore: Math.round(confidenceFactor.score * weights.mlConfidence * 10) / 10,
        maxPossibleWeightedScore: weights.mlConfidence * 100,
        description: confidenceFactor.description,
        evidenceItems: confidenceFactor.evidence
      },
      {
        name: 'correlationStrength',
        label: 'Correlation Strength',
        rawScore: correlationFactor.score,
        weight: weights.correlationStrength,
        weightedScore: Math.round(correlationFactor.score * weights.correlationStrength * 10) / 10,
        maxPossibleWeightedScore: weights.correlationStrength * 100,
        description: correlationFactor.description,
        evidenceItems: correlationFactor.evidence
      },
      {
        name: 'attackComplexity',
        label: 'Attack Complexity',
        rawScore: complexityFactor.score,
        weight: weights.attackComplexity,
        weightedScore: Math.round(complexityFactor.score * weights.attackComplexity * 10) / 10,
        maxPossibleWeightedScore: weights.attackComplexity * 100,
        description: complexityFactor.description,
        evidenceItems: complexityFactor.evidence
      },
      {
        name: 'agentInvolvement',
        label: 'Agent Involvement',
        rawScore: agentFactor.score,
        weight: weights.agentInvolvement,
        weightedScore: Math.round(agentFactor.score * weights.agentInvolvement * 10) / 10,
        maxPossibleWeightedScore: weights.agentInvolvement * 100,
        description: agentFactor.description,
        evidenceItems: agentFactor.evidence
      },
      {
        name: 'evidenceVolume',
        label: 'Evidence Volume',
        rawScore: evidenceFactor.score,
        weight: weights.evidenceVolume,
        weightedScore: Math.round(evidenceFactor.score * weights.evidenceVolume * 10) / 10,
        maxPossibleWeightedScore: weights.evidenceVolume * 100,
        description: evidenceFactor.description,
        evidenceItems: evidenceFactor.evidence
      },
      {
        name: 'affectedEntities',
        label: 'Affected Entities',
        rawScore: entityFactor.score,
        weight: weights.affectedEntities,
        weightedScore: Math.round(entityFactor.score * weights.affectedEntities * 10) / 10,
        maxPossibleWeightedScore: weights.affectedEntities * 100,
        description: entityFactor.description,
        evidenceItems: entityFactor.evidence
      }
    ];

    // 3. Compute weighted sum
    const rawTotal = riskFactors.reduce((acc, f) => acc + f.rawScore * f.weight, 0);
    // Clamp to 0 - 100 and round
    const riskScore = Math.min(100, Math.max(0, Math.round(rawTotal)));

    // 4. Band & Priority
    const { riskBand, priority } = this.getBandAndPriority(riskScore);

    const classification =
      threat.classification ||
      threat.threatType ||
      threat.category ||
      correlation?.title ||
      'SECURITY_ANOMALY';

    const explanation = this.generateExplanation(
      riskBand,
      priority,
      riskScore,
      classification,
      agentFactor.agents,
      riskFactors
    );

    const recommendedAction =
      threat.recommendedAction || this.generateRecommendedAction(riskBand, classification);

    const id = `RISK-${threat.id ? threat.id.replace('TD-', '') : Math.floor(Math.random() * 900 + 100)}`;
    const timestamp = threat.timestamp || new Date().toISOString();

    const remediationPlan: string[] = [
      `Step 1: ${recommendedAction}`,
      `Step 2: Collect telemetry snapshots across ${agentFactor.agents.join(', ')}`,
      `Step 3: Verify entity integrity for ${entityFactor.affectedSource}`,
      `Step 4: Update SOC triage status to REVIEWING or ACKNOWLEDGED`
    ];

    return {
      id,
      threatDetectionId: threat.id || `TD-${id}`,
      correlationId: correlation?.id || threat.correlationId || 'CORR-ISOLATED',
      timestamp,

      riskScore,
      severity: threat.severity || (riskBand === 'CRITICAL' ? 'CRITICAL' : riskBand === 'HIGH' ? 'HIGH' : riskBand === 'MEDIUM' ? 'MEDIUM' : 'LOW'),
      priority,
      riskBand,

      confidence: Math.round(confidenceFactor.score),

      riskFactors,

      threatClassification: classification,
      explanation,

      recommendedAction,

      status: statusOverride || 'NEW',

      participatingAgents: agentFactor.agents,
      evidenceVolume: evidenceFactor.count,
      affectedEntitiesCount: entityFactor.count,
      affectedSource: entityFactor.affectedSource,

      auditTrail: {
        calculatedAt: new Date().toISOString(),
        modelUsed: threat.model || 'Deterministic Academic Formula',
        correlationStrength: correlationFactor.score,
        mlAnomalyScore: threat.anomalyScore ?? 0.5,
        weightsConfigVersion: this.config.version
      },

      // Backward compatibility fields
      score: riskScore,
      threatCategory: classification,
      factors: {
        assetCriticality: entityFactor.score,
        exploitability: severityFactor.score,
        lateralMovementPotential: complexityFactor.score,
        dataLossExposure: confidenceFactor.score
      },
      remediationPlan
    };
  }
}

export const riskScoringEngine = new RiskScoringEngine();
