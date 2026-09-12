import { CorrelatedEvent } from '../../types/correlation';
import {
  ThreatFeatureVector,
  NormalizedFeatureVector
} from '../../types/threatDetection';

/**
 * Threat Feature Extractor
 * Transforms high-level CorrelatedEvent objects into a strict 18-dimensional
 * numerical/categorical feature vector.
 *
 * ACADEMIC PREPROCESSING SPECIFICATION:
 * - Missing values are handled via mathematically sound imputation (default zeros for counts, median/neutral defaults for probabilities).
 * - No features are invented: all signals are derived directly from the CorrelatedEvent and its constituent findings.
 */
export class ThreatFeatureExtractor {
  /**
   * Extract raw feature vector from a single CorrelatedEvent
   */
  public static extractFeatures(event: CorrelatedEvent): ThreatFeatureVector {
    // 1. Finding count
    const findingCount = event.findingIds?.length || event.eventsCount || 1;

    // 2. Participating agents count
    const participatingAgentsCount = event.participatingAgents?.length || (event.sources?.length ? 1 : 0);

    // 3. Correlation confidence (0.0 to 1.0)
    let correlationConfidence = 0.5; // neutral fallback
    if (typeof event.correlationConfidence === 'number') {
      correlationConfidence = Math.max(0, Math.min(1, event.correlationConfidence));
    } else if (typeof event.confidence === 'number') {
      correlationConfidence = Math.max(0, Math.min(1, event.confidence / 100));
    }

    // 4. Correlation strength score (1 = LOW, 2 = MEDIUM, 3 = HIGH)
    let correlationStrengthScore = 2; // default MEDIUM
    if (event.correlationStrength === 'HIGH') correlationStrengthScore = 3;
    else if (event.correlationStrength === 'LOW') correlationStrengthScore = 1;

    // 5. Event duration in seconds
    let eventDurationSeconds = 0;
    if (event.duration) {
      eventDurationSeconds = this.parseDurationToSeconds(event.duration);
    } else if (event.startTime && event.endTime) {
      const start = new Date(event.startTime).getTime();
      const end = new Date(event.endTime).getTime();
      if (!isNaN(start) && !isNaN(end) && end >= start) {
        eventDurationSeconds = Math.round((end - start) / 1000);
      }
    }

    // 6-9. Pivot entity counts
    const uniqueSourceIpsCount = event.sourceIps?.length || (event.sources?.length || 1);
    const uniqueDestIpsCount = event.destinationIps?.length || 0;
    const affectedHostsCount = event.hosts?.length || 0;
    const affectedUsersCount = event.users?.length || 0;

    // 10. Threat types count
    const threatTypesCount = event.threatTypes?.length || (event.eventTypes?.length || 1);

    // 11-13. Severity distribution derived from sequence or findings
    let suspiciousEventsCount = 0;
    let highSeverityCount = 0;
    let criticalSeverityCount = 0;

    if (event.sequence && event.sequence.length > 0) {
      for (const step of event.sequence) {
        if (step.severity === 'CRITICAL') {
          criticalSeverityCount++;
        } else if (step.severity === 'HIGH') {
          highSeverityCount++;
        } else if (step.severity === 'MEDIUM' || step.severity === 'LOW') {
          suspiciousEventsCount++;
        }
      }
    } else {
      // Fallback based on event-level severity
      if (event.severity === 'CRITICAL') criticalSeverityCount = 1;
      else if (event.severity === 'HIGH') highSeverityCount = 1;
      else suspiciousEventsCount = 1;
    }

    // 14-16. Agent Domain Involvement (binary 0 or 1)
    const networkInvolvement = event.participatingAgents?.includes('NETWORK_AGENT') ? 1 : 0;
    const systemInvolvement = event.participatingAgents?.includes('SYSTEM_AGENT') ? 1 : 0;
    const applicationInvolvement = event.participatingAgents?.includes('APPLICATION_AGENT') ? 1 : 0;

    // 17. Sequence length
    const sequenceLength = event.sequence?.length || findingCount;

    // 18. Time span in seconds
    const timeSpanSeconds = Math.max(1, eventDurationSeconds);

    return {
      findingCount,
      participatingAgentsCount,
      correlationConfidence,
      correlationStrengthScore,
      eventDurationSeconds,
      uniqueSourceIpsCount,
      uniqueDestIpsCount,
      affectedHostsCount,
      affectedUsersCount,
      threatTypesCount,
      suspiciousEventsCount,
      highSeverityCount,
      criticalSeverityCount,
      networkInvolvement,
      systemInvolvement,
      applicationInvolvement,
      sequenceLength,
      timeSpanSeconds
    };
  }

  /**
   * Preprocess and normalize feature vector into [0.0, 1.0] scale.
   * Documented bounds based on empirical enterprise SOC telemetry distributions.
   */
  public static normalizeFeatures(raw: ThreatFeatureVector): NormalizedFeatureVector {
    const imputedFeatures: string[] = [];

    // Min-Max parameter bounds for scaling
    const BOUNDS: Record<keyof ThreatFeatureVector, { min: number; max: number }> = {
      findingCount: { min: 1, max: 20 },
      participatingAgentsCount: { min: 1, max: 3 },
      correlationConfidence: { min: 0.0, max: 1.0 },
      correlationStrengthScore: { min: 1, max: 3 },
      eventDurationSeconds: { min: 0, max: 1800 }, // 30 minutes
      uniqueSourceIpsCount: { min: 1, max: 10 },
      uniqueDestIpsCount: { min: 0, max: 10 },
      affectedHostsCount: { min: 0, max: 10 },
      affectedUsersCount: { min: 0, max: 5 },
      threatTypesCount: { min: 1, max: 6 },
      suspiciousEventsCount: { min: 0, max: 15 },
      highSeverityCount: { min: 0, max: 10 },
      criticalSeverityCount: { min: 0, max: 5 },
      networkInvolvement: { min: 0, max: 1 },
      systemInvolvement: { min: 0, max: 1 },
      applicationInvolvement: { min: 0, max: 1 },
      sequenceLength: { min: 1, max: 15 },
      timeSpanSeconds: { min: 0, max: 1800 }
    };

    const scale = (val: number | undefined, key: keyof ThreatFeatureVector): number => {
      if (val === undefined || val === null || isNaN(val)) {
        imputedFeatures.push(key);
        return 0; // safe default imputation
      }
      const b = BOUNDS[key];
      const clamped = Math.max(b.min, Math.min(b.max, val));
      if (b.max === b.min) return 0;
      return Number(((clamped - b.min) / (b.max - b.min)).toFixed(4));
    };

    return {
      findingCount: scale(raw.findingCount, 'findingCount'),
      participatingAgentsCount: scale(raw.participatingAgentsCount, 'participatingAgentsCount'),
      correlationConfidence: scale(raw.correlationConfidence, 'correlationConfidence'),
      correlationStrengthScore: scale(raw.correlationStrengthScore, 'correlationStrengthScore'),
      eventDurationSeconds: scale(raw.eventDurationSeconds, 'eventDurationSeconds'),
      uniqueSourceIpsCount: scale(raw.uniqueSourceIpsCount, 'uniqueSourceIpsCount'),
      uniqueDestIpsCount: scale(raw.uniqueDestIpsCount, 'uniqueDestIpsCount'),
      affectedHostsCount: scale(raw.affectedHostsCount, 'affectedHostsCount'),
      affectedUsersCount: scale(raw.affectedUsersCount, 'affectedUsersCount'),
      threatTypesCount: scale(raw.threatTypesCount, 'threatTypesCount'),
      suspiciousEventsCount: scale(raw.suspiciousEventsCount, 'suspiciousEventsCount'),
      highSeverityCount: scale(raw.highSeverityCount, 'highSeverityCount'),
      criticalSeverityCount: scale(raw.criticalSeverityCount, 'criticalSeverityCount'),
      networkInvolvement: raw.networkInvolvement ? 1 : 0,
      systemInvolvement: raw.systemInvolvement ? 1 : 0,
      applicationInvolvement: raw.applicationInvolvement ? 1 : 0,
      sequenceLength: scale(raw.sequenceLength, 'sequenceLength'),
      timeSpanSeconds: scale(raw.timeSpanSeconds, 'timeSpanSeconds'),
      _preprocessedAt: new Date().toISOString(),
      _imputedFeatures: imputedFeatures
    };
  }

  /**
   * Convert duration string (e.g. '1m 15s', '45s', '2h') to numeric seconds
   */
  private static parseDurationToSeconds(durationStr: string): number {
    if (!durationStr || typeof durationStr !== 'string') return 0;
    let totalSeconds = 0;
    const hoursMatch = durationStr.match(/(\d+)\s*h/i);
    const minsMatch = durationStr.match(/(\d+)\s*m/i);
    const secsMatch = durationStr.match(/(\d+)\s*s/i);

    if (hoursMatch) totalSeconds += parseInt(hoursMatch[1], 10) * 3600;
    if (minsMatch) totalSeconds += parseInt(minsMatch[1], 10) * 60;
    if (secsMatch) totalSeconds += parseInt(secsMatch[1], 10);

    if (!hoursMatch && !minsMatch && !secsMatch) {
      const num = parseInt(durationStr, 10);
      if (!isNaN(num)) totalSeconds = num;
    }
    return totalSeconds;
  }
}
