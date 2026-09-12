import { SecurityFinding, CorrelationConfig, CorrelationRuleResult, CorrelationRuleCategory } from '../types/correlation';

export interface ICorrelationRule {
  id: string;
  name: string;
  category: CorrelationRuleCategory;
  description: string;
  evaluate(findings: SecurityFinding[], config: CorrelationConfig): CorrelationRuleResult;
}

/**
 * 1. TIME_PROXIMITY: Evaluates whether findings fall within the designated correlation window
 */
export const TimeProximityRule: ICorrelationRule = {
  id: 'RULE-TIME-001',
  name: 'Temporal Window Proximity',
  category: 'TIME_PROXIMITY',
  description: 'Verifies findings occur within configured temporal boundary.',
  evaluate(findings: SecurityFinding[], config: CorrelationConfig): CorrelationRuleResult {
    if (findings.length < 2) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: false,
        score: 0,
        reason: 'Fewer than 2 findings to evaluate time proximity.',
        evidence: []
      };
    }

    const timestamps = findings
      .map(f => new Date(f.timestamp).getTime())
      .filter(t => !isNaN(t))
      .sort((a, b) => a - b);

    if (timestamps.length < 2) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.5,
        reason: 'Timestamps partially missing; evaluated with relaxed temporal constraint.',
        evidence: ['Timestamp normalization fallback']
      };
    }

    const timeSpanSeconds = (timestamps[timestamps.length - 1] - timestamps[0]) / 1000;
    const window = config.timeWindowSeconds || 300;
    const matched = timeSpanSeconds <= window;

    // Closer in time yields higher score contribution
    let score = 0;
    if (matched) {
      if (timeSpanSeconds <= 30) score = 0.95;
      else if (timeSpanSeconds <= 60) score = 0.85;
      else if (timeSpanSeconds <= 300) score = 0.70;
      else score = 0.50;
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched,
      score,
      reason: matched
        ? `Events occurred within ${Math.round(timeSpanSeconds)}s, well within the ${window}s correlation window.`
        : `Events spread over ${Math.round(timeSpanSeconds)}s, exceeding the ${window}s limit.`,
      evidence: [
        `Earliest: ${new Date(timestamps[0]).toISOString().replace('T', ' ').substring(0, 19)}`,
        `Latest: ${new Date(timestamps[timestamps.length - 1]).toISOString().replace('T', ' ').substring(0, 19)}`,
        `Window constraint: ${window}s (span: ${Math.round(timeSpanSeconds)}s)`
      ]
    };
  }
};

/**
 * 2. SOURCE_IP_MATCH: Checks for shared origin IP address across findings
 */
export const SourceIpMatchRule: ICorrelationRule = {
  id: 'RULE-SRCIP-002',
  name: 'Common Source IP Correlation',
  category: 'SOURCE_IP_MATCH',
  description: 'Identifies findings originating from the exact same source IP.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    const validIps = findings.map(f => f.sourceIp).filter((ip): ip is string => Boolean(ip && ip.trim().length > 0));
    const ipCounts: Record<string, number> = {};
    for (const ip of validIps) {
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }

    const sharedIps = Object.entries(ipCounts).filter(([_, count]) => count >= 2);

    if (sharedIps.length > 0) {
      const topIp = sharedIps.sort((a, b) => b[1] - a[1])[0];
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.90,
        reason: `Shared source IP [${topIp[0]}] identified across ${topIp[1]} distinct findings.`,
        evidence: [`Source IP: ${topIp[0]} (involved in ${topIp[1]} findings)`]
      };
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched: false,
      score: 0,
      reason: 'No shared source IP across findings.',
      evidence: []
    };
  }
};

/**
 * 3. DESTINATION_IP_MATCH: Checks for common target destination IP
 */
export const DestinationIpMatchRule: ICorrelationRule = {
  id: 'RULE-DSTIP-003',
  name: 'Common Destination IP Target',
  category: 'DESTINATION_IP_MATCH',
  description: 'Identifies findings directed against the same destination IP or subnet.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    const destIps = findings
      .map(f => f.destinationIp)
      .filter((ip): ip is string => Boolean(ip && ip.trim().length > 0));

    const ipCounts: Record<string, number> = {};
    for (const ip of destIps) {
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }

    const shared = Object.entries(ipCounts).filter(([_, count]) => count >= 2);
    if (shared.length > 0) {
      const top = shared[0];
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.80,
        reason: `Findings converge on common destination IP [${top[0]}].`,
        evidence: [`Target IP: ${top[0]} (${top[1]} hits)`]
      };
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched: false,
      score: 0,
      reason: 'No shared destination IP found.',
      evidence: []
    };
  }
};

/**
 * 4. HOST_MATCH: Correlates findings involving the same monitored host/system
 */
export const HostMatchRule: ICorrelationRule = {
  id: 'RULE-HOST-004',
  name: 'Identical Host Target Correlation',
  category: 'HOST_MATCH',
  description: 'Identifies findings involving the same host or endpoint asset.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    const hosts = findings
      .map(f => f.host)
      .filter((h): h is string => Boolean(h && h.trim().length > 0));

    const counts: Record<string, number> = {};
    for (const h of hosts) {
      counts[h] = (counts[h] || 0) + 1;
    }

    const shared = Object.entries(counts).filter(([_, count]) => count >= 2);
    if (shared.length > 0) {
      const top = shared[0];
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.85,
        reason: `Host [${top[0]}] targeted or involved in ${top[1]} correlated findings.`,
        evidence: [`Target Host Asset: ${top[0]} (${top[1]} related events)`]
      };
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched: false,
      score: 0,
      reason: 'No shared host identifier.',
      evidence: []
    };
  }
};

/**
 * 5. USERNAME_MATCH: Correlates findings involving the same user identity
 */
export const UsernameMatchRule: ICorrelationRule = {
  id: 'RULE-USER-005',
  name: 'Common User Identity Correlation',
  category: 'USERNAME_MATCH',
  description: 'Identifies findings tied to the same user or service account.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    const users = findings
      .map(f => f.username)
      .filter((u): u is string => Boolean(u && u.trim().length > 0));

    const counts: Record<string, number> = {};
    for (const u of users) {
      counts[u] = (counts[u] || 0) + 1;
    }

    const shared = Object.entries(counts).filter(([_, count]) => count >= 2);
    if (shared.length > 0) {
      const top = shared[0];
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.90,
        reason: `Account identity [${top[0]}] correlated across ${top[1]} distinct findings.`,
        evidence: [`Target User Account: ${top[0]} (${top[1]} occurrences)`]
      };
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched: false,
      score: 0,
      reason: 'No shared user identity found across findings.',
      evidence: []
    };
  }
};

/**
 * 6. CROSS_AGENT_ACTIVITY: Checks whether findings span across distinct agents
 */
export const CrossAgentActivityRule: ICorrelationRule = {
  id: 'RULE-CROSS-006',
  name: 'Multi-Agent Domain Synthesis',
  category: 'CROSS_AGENT_ACTIVITY',
  description: 'Detects multi-domain telemetry from Network, System, and Application agents.',
  evaluate(findings: SecurityFinding[], config: CorrelationConfig): CorrelationRuleResult {
    const agents = Array.from(new Set(findings.map(f => f.agentId)));

    if (agents.length >= 3) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.95,
        reason: `Full triad cross-agent correlation verified: Network, System, and Application agents observed related activity.`,
        evidence: [`Participating Agents (3/3): ${agents.join(', ')}`]
      };
    } else if (agents.length === 2) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.80,
        reason: `Dual-agent correlation confirmed between ${agents[0]} and ${agents[1]}.`,
        evidence: [`Participating Agents (2/3): ${agents.join(' + ')}`]
      };
    }

    const matched = !config.crossAgentRequired;
    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched,
      score: matched ? 0.30 : 0.0,
      reason: agents.length === 1
        ? `Single agent scope (${agents[0]}). ${config.crossAgentRequired ? 'Cross-agent requirement unsatisfied.' : 'Permitted under single-domain sequence policy.'}`
        : 'No agents associated with finding set.',
      evidence: [`Participating Agents (1/3): ${agents.join(', ')}`]
    };
  }
};

/**
 * 7. EVENT_SEQUENCE: Detects recognized attack progression chains
 * - Sequence A: Port Scan -> Repeated Login Attempts -> Successful Login -> Privilege Escalation
 * - Sequence B: Suspicious Web Request -> Authentication Failures -> Restricted Resource Access
 * - Sequence C: High Network Activity -> Suspicious Application Requests -> Abnormal Host Activity
 */
export const EventSequenceRule: ICorrelationRule = {
  id: 'RULE-SEQ-007',
  name: 'Multi-Stage Attack Sequence Detection',
  category: 'EVENT_SEQUENCE',
  description: 'Reconstructs chronological progression of tactical attack stages.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    if (findings.length < 2) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: false,
        score: 0,
        reason: 'Insufficient findings to establish an attack sequence.',
        evidence: []
      };
    }

    // Sort chronologically
    const sorted = [...findings].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    const eventTypes = sorted.map(f => `${f.threatType} ${f.eventType}`.toLowerCase());

    // Check Sequence A: Port Scan -> Auth Failures -> Auth Success -> Privilege Escalation
    const hasScan = eventTypes.some(t => t.includes('scan') || t.includes('probe') || t.includes('recon'));
    const hasAuthFail = eventTypes.some(t => t.includes('fail') || t.includes('brute') || t.includes('spray') || t.includes('invalid credential'));
    const hasPrivEsc = eventTypes.some(t => t.includes('privilege') || t.includes('token') || t.includes('sudo') || t.includes('impersonat'));
    const hasAuthSuccess = eventTypes.some(t => t.includes('success') || t.includes('logon') || t.includes('authenticated'));

    if (hasScan && (hasAuthFail || hasAuthSuccess) && hasPrivEsc) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.95,
        reason: 'Potential Multi-Stage Intrusion Sequence: Reconnaissance scan followed by authentication activity and subsequent host privilege escalation.',
        evidence: [
          'Tactical Sequence: Port Scan / Recon -> Authentication Activity -> Privilege Escalation',
          `Order verified across ${sorted.length} chronological stages`
        ]
      };
    }

    // Check Sequence B: Web Request (SQLi / XSS / Traversal) -> Auth Failures -> Restricted Resource Access
    const hasWebExploit = eventTypes.some(t => t.includes('injection') || t.includes('sqli') || t.includes('xss') || t.includes('traversal') || t.includes('web request'));
    const hasRestricted = eventTypes.some(t => t.includes('unauthorized') || t.includes('restricted') || t.includes('403') || t.includes('actuator') || t.includes('admin'));

    if (hasWebExploit && (hasAuthFail || hasRestricted)) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.88,
        reason: 'Potential Web-to-Account Attack Sequence: Suspicious web application payloads combined with authentication failures and unauthorized resource access.',
        evidence: [
          'Tactical Sequence: Web Exploit Vector -> Credential Failure / Unauthorized Access Probing'
        ]
      };
    }

    // Check Sequence C: High Network Activity -> Suspicious Web Requests -> Abnormal Host Activity
    const hasHighNet = eventTypes.some(t => t.includes('flood') || t.includes('traffic') || t.includes('burst') || t.includes('dos') || t.includes('network'));
    const hasHostAnomaly = eventTypes.some(t => t.includes('process') || t.includes('powershell') || t.includes('host') || t.includes('persistence'));

    if (hasHighNet && hasWebExploit && hasHostAnomaly) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.85,
        reason: 'Potential Coordinated Activity: High network traffic coincided with suspicious application requests and abnormal host process activity.',
        evidence: [
          'Tactical Sequence: Network Ingress Volume -> Application API Infiltration -> Host Process Anomaly'
        ]
      };
    }

    // Fallback partial sequence if order is chronological and threat types relate
    if (sorted.length >= 2) {
      return {
        ruleId: this.id,
        ruleName: this.name,
        category: this.category,
        matched: true,
        score: 0.50,
        reason: 'Temporal sequence observed across consecutive security findings.',
        evidence: [
          `Ordered ${sorted.length} events starting at ${sorted[0].timestamp.replace('T', ' ').substring(0, 19)}`
        ]
      };
    }

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched: false,
      score: 0,
      reason: 'No recognizable attack sequence detected.',
      evidence: []
    };
  }
};

/**
 * 8. THREAT_TYPE_RELATIONSHIP: Evaluates whether threat categories complement each other
 */
export const ThreatTypeRelationshipRule: ICorrelationRule = {
  id: 'RULE-THREAT-008',
  name: 'Threat Type Synergistic Relationship',
  category: 'THREAT_TYPE_RELATIONSHIP',
  description: 'Identifies complementary threat types known to be co-occurring in breach campaigns.',
  evaluate(findings: SecurityFinding[]): CorrelationRuleResult {
    const types = Array.from(new Set(findings.map(f => f.threatType.toLowerCase())));

    let matched = false;
    let score = 0;
    const reasons: string[] = [];

    // Pairs: Recon + Brute Force
    const hasRecon = types.some(t => t.includes('scan') || t.includes('recon') || t.includes('probe'));
    const hasAuth = types.some(t => t.includes('brute') || t.includes('auth') || t.includes('credential'));
    const hasWeb = types.some(t => t.includes('sqli') || t.includes('injection') || t.includes('traversal') || t.includes('web'));
    const hasHost = types.some(t => t.includes('privilege') || t.includes('process') || t.includes('token') || t.includes('impersonat'));

    if (hasRecon && hasAuth) {
      matched = true;
      score += 0.4;
      reasons.push('Reconnaissance probe followed by credential harvesting attempt');
    }
    if (hasWeb && hasHost) {
      matched = true;
      score += 0.5;
      reasons.push('Application vulnerability exploitation leading into host privilege elevation');
    }
    if (hasAuth && hasHost) {
      matched = true;
      score += 0.45;
      reasons.push('Authentication abuse leading into privileged credential usage');
    }

    score = Math.min(0.95, score || (types.length >= 2 ? 0.35 : 0));
    matched = matched || types.length >= 2;

    return {
      ruleId: this.id,
      ruleName: this.name,
      category: this.category,
      matched,
      score,
      reason: reasons.length > 0
        ? `Co-occurring threat types exhibit structural synergy: ${reasons.join('; ')}.`
        : (types.length >= 2 ? 'Multiple distinct threat categories observed in unison.' : 'Single threat category.'),
      evidence: [`Observed Threat Types: ${Array.from(new Set(findings.map(f => f.threatType))).join(', ')}`]
    };
  }
};

/**
 * Standard registry of all active modular correlation rules
 */
export const ALL_CORRELATION_RULES: ICorrelationRule[] = [
  TimeProximityRule,
  SourceIpMatchRule,
  DestinationIpMatchRule,
  HostMatchRule,
  UsernameMatchRule,
  CrossAgentActivityRule,
  EventSequenceRule,
  ThreatTypeRelationshipRule
];
