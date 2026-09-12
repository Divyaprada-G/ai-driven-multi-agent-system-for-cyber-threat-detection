import { CommonAgentResult, AgentResult, LogEvent } from '../types';
import { SecurityFinding } from '../types/correlation';

/**
 * Normalizes findings from Network, System, and Application agents
 * into unified SecurityFinding instances.
 */
export class CorrelationNormalizer {
  private static readonly IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  private static readonly HOST_REGEX = /\b([a-zA-Z0-9_-]+(?:-(?:srv|fin|dc|ws|host|db|web|app)[a-zA-Z0-9_-]*|\b(?:localhost|workstation[a-zA-Z0-9_-]*))\b)/i;
  private static readonly USER_REGEX = /\b(?:user|username|uid|account|identity)[\s:=]+["']?([a-zA-Z0-9._-]+)["']?/i;

  /**
   * Normalizes a CommonAgentResult into a standard SecurityFinding
   */
  public static fromCommonAgentResult(res: CommonAgentResult): SecurityFinding {
    const raw = res.rawEvent;
    const nf = raw?.normalizedFields || {};

    let sourceIp: string | undefined = nf.sourceIp;
    let destinationIp: string | undefined = nf.destinationIp;
    let host: string | undefined = nf.hostName;
    let username: string | undefined = nf.userName;

    // Deep text extraction fallback if normalized fields are empty
    const allEvidenceText = [
      res.source || '',
      res.detection || '',
      ...(res.evidence || []),
      ...(res.indicators || []),
      raw?.message || ''
    ].join(' ');

    if (!sourceIp) {
      const match = allEvidenceText.match(this.IP_REGEX);
      if (match) sourceIp = match[0];
    }

    if (!host) {
      const hostMatch = allEvidenceText.match(this.HOST_REGEX);
      if (hostMatch) host = hostMatch[0];
      else if (raw?.source && !this.IP_REGEX.test(raw.source) && !raw.source.includes('/')) {
        host = raw.source;
      }
    }

    if (!username) {
      const userMatch = allEvidenceText.match(this.USER_REGEX);
      if (userMatch) username = userMatch[1];
    }

    return {
      id: res.id || `find-${res.agentId.toLowerCase()}-${res.eventId || Math.random().toString(36).substring(2, 7)}`,
      agentId: res.agentId,
      eventId: res.eventId || `EVT-${Math.floor(Math.random() * 9000 + 1000)}`,
      timestamp: res.timestamp || new Date().toISOString(),
      source: res.source || nf.sourceIp || host || 'Unified Agent Ingest',
      host,
      sourceIp,
      destinationIp,
      username,
      eventType: res.detection || res.threatType || 'Security Finding',
      threatType: res.threatType || 'Suspicious Activity',
      severity: res.severity || 'MEDIUM',
      confidence: typeof res.confidence === 'number'
        ? (res.confidence > 1 ? res.confidence / 100 : res.confidence)
        : 0.85,
      evidence: Array.isArray(res.evidence) ? [...res.evidence] : [],
      indicators: Array.isArray(res.indicators) ? [...res.indicators] : [],
      classification: res.classification || (res.threatDetected ? 'THREAT' : 'SUSPICIOUS'),
      rawEvent: raw,
      metadata: {
        observedActivity: res.observedActivity,
        detectedPattern: res.detectedPattern,
        recommendedAction: res.recommendedAction
      }
    };
  }

  /**
   * Normalizes a legacy AgentResult into a standard SecurityFinding
   */
  public static fromAgentResult(res: AgentResult): SecurityFinding {
    return this.fromCommonAgentResult({
      agentId: res.agentId,
      eventId: res.eventId,
      timestamp: res.timestamp,
      threatDetected: true,
      threatType: res.detection,
      severity: res.severity,
      confidence: res.confidence,
      evidence: res.rawEvidence ? [res.rawEvidence] : [],
      indicators: res.indicators,
      detection: res.detection
    });
  }

  /**
   * Batch normalizes an array of agent results
   */
  public static normalizeBatch(results: (CommonAgentResult | AgentResult | SecurityFinding)[]): SecurityFinding[] {
    return results.map(item => {
      if ('agentId' in item && 'eventType' in item && 'findingIds' === undefined) {
        // already a SecurityFinding
        return item as SecurityFinding;
      }
      if ('rawEvidence' in item && !('threatDetected' in item)) {
        return this.fromAgentResult(item as AgentResult);
      }
      return this.fromCommonAgentResult(item as CommonAgentResult);
    });
  }
}
