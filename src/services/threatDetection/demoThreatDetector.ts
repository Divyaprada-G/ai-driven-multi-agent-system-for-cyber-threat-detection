import { CorrelatedEvent } from '../../types/correlation';
import {
  ThreatClass,
  ThreatDetectionResult,
  ThreatFeatureVector,
  NormalizedFeatureVector,
  ThreatExplanation
} from '../../types/threatDetection';
import { ThreatFeatureExtractor } from './threatFeatureExtractor';

/**
 * Demo Threat Detector
 *
 * CRITICAL ACADEMIC INTEGRITY DIRECTIVE:
 * This engine operates in DEMO DETECTION MODE using structured correlation evidence
 * and deterministic heuristics to demonstrate how downstream ML outputs integrate
 * with the SOC platform.
 *
 * ALL OUTPUTS ARE EXPLICITLY LABELED:
 * - Model: "Rule-Based Demo Engine (Heuristic Simulator)"
 * - Model Status: "DEMO"
 * - Confidence Type: "DEMO-DERIVED"
 * - Anomaly Score: "DEMO ANOMALY SCORE"
 *
 * IT STRICTLY DOES NOT INVENT OR FABRICATE TRAINED MODEL WEIGHTS.
 */
export class DemoThreatDetector {
  /**
   * Analyze a CorrelatedEvent and produce a verified, deterministic ThreatDetectionResult
   */
  public static analyze(event: CorrelatedEvent): ThreatDetectionResult {
    const rawFeatures: ThreatFeatureVector = ThreatFeatureExtractor.extractFeatures(event);
    const normalizedFeatures: NormalizedFeatureVector = ThreatFeatureExtractor.normalizeFeatures(rawFeatures);

    const classification = this.determineClassification(event, rawFeatures);
    const confidence = this.calculateDeterministicConfidence(event, rawFeatures, classification);
    const anomalyScore = this.calculateDeterministicAnomalyScore(event, rawFeatures);
    const explanation = this.buildExplainableAi(event, rawFeatures, classification, confidence);

    const threatDetected = classification !== 'BENIGN' && classification !== 'UNKNOWN';

    // Map severity from event or classification
    let severity = event.severity || 'MEDIUM';
    if (classification === 'MULTI_STAGE_THREAT' || classification === 'PRIVILEGE_ESCALATION') {
      severity = 'CRITICAL';
    } else if (classification === 'BENIGN') {
      severity = 'LOW';
    }

    const recommendedAction = explanation.recommendedAction;

    return {
      id: `TD-${event.id.replace('CORR-', '')}`,
      correlationId: event.id || event.correlationId,
      timestamp: event.endTime || event.createdAt || new Date().toISOString(),
      model: 'Rule-Based Demo Engine (Heuristic Simulator)',
      modelType: 'RULE_BASED_DEMO',
      modelStatus: 'DEMO',
      classification,
      threatDetected,
      confidence,
      confidenceType: 'DEMO-DERIVED',
      anomalyScore,
      anomalyScoreLabel: 'DEMO ANOMALY SCORE',
      features: rawFeatures,
      normalizedFeatures,
      evidence: event.evidence || [
        `Observed ${rawFeatures.findingCount} cross-agent security findings`,
        `Involving ${rawFeatures.participatingAgentsCount} detection agents`
      ],
      severity,
      explanation,
      status: 'DETECTED',
      mitreTechniqueId: event.mitreTechniqueId,
      recommendedAction,

      // Backward compatibility fields for existing UI components
      threatType: this.formatThreatTitle(classification),
      category: this.mapClassificationToCategory(classification),
      predictedImpact: severity === 'CRITICAL' ? 'CATASTROPHIC' : severity === 'HIGH' ? 'HIGH' : severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
      baselineDeviation: Number((anomalyScore * 4.5).toFixed(1))
    };
  }

  /**
   * Deterministic classification rule logic based on multi-agent signals
   */
  private static determineClassification(
    event: CorrelatedEvent,
    features: ThreatFeatureVector
  ): ThreatClass {
    const textCorpus = [
      event.title || '',
      event.summary || '',
      event.description || '',
      event.attackPattern || '',
      ...(event.threatTypes || []),
      ...(event.eventTypes || [])
    ].join(' ').toLowerCase();

    // 1. Multi-Stage Threat: Spans 2+ agents across different kill chain phases or explicit multi-stage pattern
    if (
      (features.participatingAgentsCount >= 2 && features.threatTypesCount >= 2 && features.sequenceLength >= 2) ||
      (features.networkInvolvement === 1 && features.systemInvolvement === 1) ||
      textCorpus.includes('multi-stage') ||
      textCorpus.includes('lateral elevation') ||
      textCorpus.includes('infiltration')
    ) {
      return 'MULTI_STAGE_THREAT';
    }

    // 2. Privilege Escalation: Token manipulation, sudo, admin impersonation, service exploit
    if (
      features.systemInvolvement === 1 &&
      (textCorpus.includes('privilege') ||
        textCorpus.includes('elevation') ||
        textCorpus.includes('token') ||
        textCorpus.includes('impersonate') ||
        textCorpus.includes('sudo'))
    ) {
      return 'PRIVILEGE_ESCALATION';
    }

    // 3. Authentication Threat: Credential stuffing, brute force, auth failures
    if (
      textCorpus.includes('credential') ||
      textCorpus.includes('brute-force') ||
      textCorpus.includes('authentication') ||
      textCorpus.includes('auth failure') ||
      textCorpus.includes('failed login') ||
      (features.affectedUsersCount > 0 && features.suspiciousEventsCount >= 2)
    ) {
      return 'AUTHENTICATION_THREAT';
    }

    // 4. API Threat: API metadata enumeration, endpoint abuse, burst rate
    if (
      textCorpus.includes('api') ||
      textCorpus.includes('rate limit') ||
      textCorpus.includes('endpoint') ||
      (features.applicationInvolvement === 1 && features.eventDurationSeconds < 30 && features.findingCount >= 3)
    ) {
      return 'API_THREAT';
    }

    // 5. Web Threat: SQL injection, XSS, SSRF, web exploit
    if (
      features.applicationInvolvement === 1 &&
      (textCorpus.includes('injection') ||
        textCorpus.includes('sql') ||
        textCorpus.includes('xss') ||
        textCorpus.includes('traversal') ||
        textCorpus.includes('http'))
    ) {
      return 'WEB_THREAT';
    }

    // 6. Network Threat: Port scanning, DNS tunneling, DDoS, beaconing
    if (
      features.networkInvolvement === 1 &&
      (textCorpus.includes('port scan') ||
        textCorpus.includes('tunneling') ||
        textCorpus.includes('dns') ||
        textCorpus.includes('ddos') ||
        textCorpus.includes('syn flood') ||
        textCorpus.includes('beacon'))
    ) {
      return 'NETWORK_THREAT';
    }

    // 7. General Anomaly: High deviation or unusual burst without clear category
    if (features.findingCount >= 2 && features.correlationStrengthScore >= 2) {
      return 'ANOMALY';
    }

    // 8. Benign / Suspicious / Unknown based on severity and findings
    if (features.criticalSeverityCount === 0 && features.highSeverityCount === 0 && features.suspiciousEventsCount === 0) {
      return 'BENIGN';
    }

    if (features.suspiciousEventsCount > 0) {
      return 'SUSPICIOUS';
    }

    return 'UNKNOWN';
  }

  /**
   * Compute deterministic confidence from explicit empirical evidence (never random!)
   */
  private static calculateDeterministicConfidence(
    event: CorrelatedEvent,
    features: ThreatFeatureVector,
    classification: ThreatClass
  ): number {
    if (classification === 'BENIGN') {
      return 0.88; // high confidence in benign when no threat indicators found
    }
    if (classification === 'UNKNOWN') {
      return 0.40; // low confidence due to ambiguous evidence
    }

    // Start with normalized correlation confidence
    let base = features.correlationConfidence;

    // Weight 1: Number of participating agents (cross-agent verification adds weight)
    if (features.participatingAgentsCount >= 3) base += 0.08;
    else if (features.participatingAgentsCount === 2) base += 0.04;

    // Weight 2: Critical finding presence
    if (features.criticalSeverityCount >= 1) base += 0.06;
    if (features.highSeverityCount >= 1) base += 0.03;

    // Weight 3: Correlation strength
    if (features.correlationStrengthScore === 3) base += 0.05;

    // Weight 4: Evidence volume
    if (event.evidence && event.evidence.length >= 3) base += 0.04;

    // Clamp between 0.60 and 0.98 for demo detections
    const clamped = Math.max(0.60, Math.min(0.98, base));
    return Number(clamped.toFixed(4));
  }

  /**
   * Compute deterministic anomaly score (0.0 = nominal, 1.0 = highly anomalous)
   */
  private static calculateDeterministicAnomalyScore(
    event: CorrelatedEvent,
    features: ThreatFeatureVector
  ): number {
    // Dispersion based on multi-entity spread and severity
    let score = 0.15; // baseline nominal noise

    score += Math.min(0.35, features.criticalSeverityCount * 0.15 + features.highSeverityCount * 0.08);
    score += Math.min(0.25, features.participatingAgentsCount * 0.08);
    score += Math.min(0.15, features.uniqueSourceIpsCount * 0.03 + features.affectedHostsCount * 0.04);
    score += Math.min(0.15, features.threatTypesCount * 0.05);

    if (event.correlationStrength === 'HIGH') score += 0.08;

    return Number(Math.max(0.10, Math.min(0.96, score)).toFixed(4));
  }

  /**
   * Construct Explainable AI breakdown
   */
  private static buildExplainableAi(
    event: CorrelatedEvent,
    features: ThreatFeatureVector,
    classification: ThreatClass,
    confidence: number
  ): ThreatExplanation {
    const contributingFeatures = [
      {
        feature: 'Participating Agents',
        value: `${features.participatingAgentsCount} Agent(s)`,
        impact: features.participatingAgentsCount >= 2 ? ('HIGH' as const) : ('MEDIUM' as const)
      },
      {
        feature: 'Correlation Strength',
        value: event.correlationStrength || 'MEDIUM',
        impact: event.correlationStrength === 'HIGH' ? ('HIGH' as const) : ('MEDIUM' as const)
      },
      {
        feature: 'Critical Findings Count',
        value: features.criticalSeverityCount,
        impact: features.criticalSeverityCount > 0 ? ('HIGH' as const) : ('LOW' as const)
      },
      {
        feature: 'Unique Source IPs',
        value: features.uniqueSourceIpsCount,
        impact: features.uniqueSourceIpsCount > 1 ? ('MEDIUM' as const) : ('LOW' as const)
      },
      {
        feature: 'Event Duration',
        value: `${features.eventDurationSeconds}s`,
        impact: features.eventDurationSeconds < 60 ? ('HIGH' as const) : ('LOW' as const)
      }
    ];

    const participatingAgents = event.participatingAgents || [];

    const whyAnalyzed = `Event cluster ${event.id} was ingested by the Threat Detection Engine because it contains ${features.findingCount} correlated security findings spanning ${features.participatingAgentsCount} specialized agents within an observed temporal window of ${features.eventDurationSeconds} seconds.`;

    const supportingEvidence = [
      ...(event.evidence || []),
      `Deterministic Demo Engine classified activity as ${classification} with ${(confidence * 100).toFixed(1)}% confidence`,
      `Agent domains activated: ${[
        features.networkInvolvement ? 'Network' : null,
        features.systemInvolvement ? 'System' : null,
        features.applicationInvolvement ? 'Application' : null
      ].filter(Boolean).join(', ') || 'None'}`
    ];

    let recommendedAction = 'Continue passive monitoring and inspect correlated timeline.';
    if (classification === 'MULTI_STAGE_THREAT' || classification === 'PRIVILEGE_ESCALATION') {
      recommendedAction = 'Immediately escalate to Incident Response team, isolate affected host, and invalidate compromised session tokens.';
    } else if (classification === 'AUTHENTICATION_THREAT') {
      recommendedAction = 'Enforce multi-factor challenge, review firewall rate-limiting on target auth endpoint, and audit targeted user accounts.';
    } else if (classification === 'API_THREAT' || classification === 'WEB_THREAT') {
      recommendedAction = 'Review WAF inspection rules for targeted endpoints and verify database parameterization.';
    } else if (classification === 'NETWORK_THREAT') {
      recommendedAction = 'Inspect upstream firewall flow logs and add offending external IP to watchlist.';
    }

    return {
      whyAnalyzed,
      contributingFeatures,
      participatingAgents,
      supportingEvidence,
      recommendedAction
    };
  }

  private static formatThreatTitle(classification: ThreatClass): string {
    switch (classification) {
      case 'MULTI_STAGE_THREAT':
        return 'Multi-Stage Infiltration & Lateral Movement';
      case 'PRIVILEGE_ESCALATION':
        return 'Privilege Escalation via Service Exploitation';
      case 'AUTHENTICATION_THREAT':
        return 'Distributed Credential Stuffing & Auth Abuse';
      case 'API_THREAT':
        return 'High-Frequency API Resource Enumeration';
      case 'WEB_THREAT':
        return 'Web Application Injection / Exploit Vector';
      case 'NETWORK_THREAT':
        return 'Suspicious Ingress Reconnaissance / Tunneling';
      case 'ANOMALY':
        return 'Unsupervised Flow / Cadence Anomaly';
      case 'BENIGN':
        return 'Nominal Background Activity (Benign)';
      case 'SUSPICIOUS':
        return 'Suspicious Multi-Event Telemetry';
      case 'UNKNOWN':
      default:
        return 'Unclassified Security Event Sequence';
    }
  }

  private static mapClassificationToCategory(classification: ThreatClass): string {
    switch (classification) {
      case 'MULTI_STAGE_THREAT':
        return 'Lateral Movement';
      case 'PRIVILEGE_ESCALATION':
        return 'Privilege Escalation';
      case 'AUTHENTICATION_THREAT':
        return 'Credential Access';
      case 'API_THREAT':
      case 'WEB_THREAT':
        return 'Initial Access';
      case 'NETWORK_THREAT':
        return 'Discovery / Command & Control';
      case 'ANOMALY':
        return 'Defense Evasion';
      case 'BENIGN':
        return 'Benign';
      case 'SUSPICIOUS':
        return 'Suspicious Activity';
      case 'UNKNOWN':
      default:
        return 'Uncategorized';
    }
  }
}
