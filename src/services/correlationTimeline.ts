import { SecurityFinding, CorrelationSequenceStep, CorrelationRuleResult } from '../types/correlation';

export class CorrelationTimelineBuilder {
  /**
   * Builds an ordered sequence of attack steps from contributing findings
   */
  public static buildSequence(findings: SecurityFinding[]): CorrelationSequenceStep[] {
    const sorted = [...findings].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    return sorted.map((f, index) => {
      let desc = f.eventType || f.threatType;
      if (f.metadata?.observedActivity) {
        desc = `${f.eventType} — ${f.metadata.observedActivity}`;
      } else if (f.evidence && f.evidence.length > 0) {
        desc = `${f.eventType} (${f.evidence[0]})`;
      }

      return {
        step: index + 1,
        timestamp: f.timestamp,
        agentId: f.agentId,
        findingId: f.id,
        description: desc,
        threatType: f.threatType,
        severity: f.severity,
        sourceIp: f.sourceIp,
        host: f.host,
        user: f.username
      };
    });
  }

  /**
   * Generates a grounded, evidence-based causal explanation:
   * "WHY WERE THESE EVENTS CONNECTED?"
   */
  public static generateExplanation(
    findings: SecurityFinding[],
    ruleResults: CorrelationRuleResult[],
    timeSpanSeconds: number
  ): string {
    const lines: string[] = [];

    // 1. Entity linkage line
    const srcIpRule = ruleResults.find(r => r.category === 'SOURCE_IP_MATCH');
    const hostRule = ruleResults.find(r => r.category === 'HOST_MATCH');
    const userRule = ruleResults.find(r => r.category === 'USERNAME_MATCH');

    if (srcIpRule?.matched) {
      lines.push(`1. Shared Source IP: Multiple events originated from the identical source address (${srcIpRule.evidence[0] || 'consistent IP'}).`);
    } else if (hostRule?.matched) {
      lines.push(`1. Common Target Host: Events converged on the same monitored endpoint asset (${hostRule.evidence[0] || 'consistent host'}).`);
    } else if (userRule?.matched) {
      lines.push(`1. Target Account Identity: Correlated actions targeted the same account credential (${userRule.evidence[0] || 'consistent username'}).`);
    } else {
      lines.push('1. Temporal & Behavioral Linkage: Events demonstrated complementary threat indicators.');
    }

    // 2. Cross-agent breakdown
    const agents = Array.from(new Set(findings.map(f => f.agentId)));
    const agentNames = agents.map(a => {
      if (a === 'NETWORK_AGENT') return 'Network Agent';
      if (a === 'SYSTEM_AGENT') return 'System Agent';
      return 'Application Agent';
    });

    if (agents.length >= 2) {
      lines.push(`2. Multi-Domain Agent Synthesis: Discovered telemetry verified across ${agents.length} distinct domains (${agentNames.join(' and ')}).`);
    } else {
      lines.push(`2. Domain Specialization: Evaluated within ${agentNames[0]} domain telemetry.`);
    }

    // 3. Sequence / Pattern line
    const seqRule = ruleResults.find(r => r.category === 'EVENT_SEQUENCE');
    if (seqRule?.matched && seqRule.score > 0.6) {
      lines.push(`3. Tactical Attack Chain: Observations match a recognizable attack sequence (${seqRule.reason}).`);
    } else {
      const threatTypes = Array.from(new Set(findings.map(f => f.threatType)));
      lines.push(`3. Behavioral Pattern: Correlated ${threatTypes.join(', ')} occurring in synchronized proximity.`);
    }

    // 4. Temporal window line
    lines.push(`4. Temporal Coincidence: All supporting events transpired within ${Math.max(1, Math.round(timeSpanSeconds))}s, satisfying the active correlation window.`);

    return lines.join('\n');
  }
}
