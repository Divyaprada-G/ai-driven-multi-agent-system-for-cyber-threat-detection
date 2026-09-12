import {
  SecurityFinding,
  CorrelationConfig,
  CorrelatedEvent,
  CorrelationRuleResult
} from '../types/correlation';
import { ALL_CORRELATION_RULES } from './correlationRules';
import { CorrelationScorer } from './correlationScorer';
import { CorrelationTimelineBuilder } from './correlationTimeline';

export class CorrelationEngine {
  /**
   * Main correlation method: Takes normalized findings and groups them into
   * mathematically grounded, non-trivial CorrelatedEvent clusters.
   */
  public static correlate(
    findings: SecurityFinding[],
    config: CorrelationConfig
  ): CorrelatedEvent[] {
    if (!findings || findings.length === 0) {
      return [];
    }

    // Step 1: Filter out benign or non-actionable findings if any
    const actionable = findings.filter(f => f.classification !== 'BENIGN');
    if (actionable.length === 0) return [];

    // Step 2: Form candidate clusters using multi-dimensional entity indexing
    const candidateClusters = this.clusterFindings(actionable, config);

    // Step 3: Evaluate each candidate cluster against correlation rules & scoring
    const correlatedEvents: CorrelatedEvent[] = [];
    let clusterIdx = 1;

    for (const cluster of candidateClusters) {
      // Must meet minimum findings threshold
      if (cluster.length < (config.minFindings || 2)) {
        continue;
      }

      // Check cross-agent requirement if enabled in settings
      const participatingAgents = Array.from(new Set(cluster.map(f => f.agentId)));
      if (config.crossAgentRequired && participatingAgents.length < 2) {
        continue;
      }

      // Evaluate active correlation rules
      const ruleResults: CorrelationRuleResult[] = ALL_CORRELATION_RULES.map(rule =>
        rule.evaluate(cluster, config)
      );

      // Verify that at least one strong non-temporal correlation rule matched!
      // (False-positive prevention: Time proximity alone is NOT enough!)
      const nonTimeMatches = ruleResults.filter(
        r => r.category !== 'TIME_PROXIMITY' && r.matched && r.score >= 0.5
      );

      if (nonTimeMatches.length === 0) {
        // Discard: unrelated events happened to occur near each other with no shared entity or sequence
        continue;
      }

      // Calculate confidence and strength
      const scoreResult = CorrelationScorer.calculate(cluster, ruleResults);

      // Filter by minimum correlation strength threshold if set
      if (config.minCorrelationStrength === 'HIGH' && scoreResult.strength !== 'HIGH') {
        continue;
      }
      if (config.minCorrelationStrength === 'MEDIUM' && scoreResult.strength === 'LOW') {
        continue;
      }

      // Calculate timestamps & duration
      const timestamps = cluster
        .map(f => new Date(f.timestamp).getTime())
        .filter(t => !isNaN(t))
        .sort((a, b) => a - b);

      const startTime = timestamps.length > 0
        ? new Date(timestamps[0]).toISOString().replace('T', ' ').substring(0, 19)
        : new Date().toISOString().replace('T', ' ').substring(0, 19);

      const endTime = timestamps.length > 0
        ? new Date(timestamps[timestamps.length - 1]).toISOString().replace('T', ' ').substring(0, 19)
        : startTime;

      const durationMs = timestamps.length > 1 ? timestamps[timestamps.length - 1] - timestamps[0] : 0;
      const durationSeconds = Math.round(durationMs / 1000);
      const durationStr = durationSeconds < 60 ? `${durationSeconds}s` : `${Math.floor(durationSeconds / 60)}m ${durationSeconds % 60}s`;

      // Build chronological attack sequence
      const sequence = CorrelationTimelineBuilder.buildSequence(cluster);

      // Build explanation
      const explanation = CorrelationTimelineBuilder.generateExplanation(cluster, ruleResults, durationSeconds);

      // Deduplicate entities
      const sourceIps = Array.from(new Set(cluster.map(f => f.sourceIp).filter((ip): ip is string => Boolean(ip))));
      const destinationIps = Array.from(new Set(cluster.map(f => f.destinationIp).filter((ip): ip is string => Boolean(ip))));
      const hosts = Array.from(new Set(cluster.map(f => f.host).filter((h): h is string => Boolean(h))));
      const users = Array.from(new Set(cluster.map(f => f.username).filter((u): u is string => Boolean(u))));
      const threatTypes = Array.from(new Set(cluster.map(f => f.threatType)));
      const eventTypes = Array.from(new Set(cluster.map(f => f.eventType)));

      // Collect evidence and indicators
      const allEvidence: string[] = [];
      const allIndicators: string[] = [];
      for (const f of cluster) {
        allEvidence.push(...(f.evidence || []));
        allIndicators.push(...(f.indicators || []));
      }

      // Synthesize Title using Cautious Defensive Terminology
      let title = 'Potential Coordinated Security Activity';
      const seqRule = ruleResults.find(r => r.category === 'EVENT_SEQUENCE');

      if (participatingAgents.length >= 3) {
        title = 'Potential Multi-Stage Intrusion Sequence (Cross-Agent)';
      } else if (seqRule?.matched && seqRule.score >= 0.85) {
        if (seqRule.reason.includes('Intrusion')) {
          title = 'Potential Multi-Stage Intrusion Sequence';
        } else if (seqRule.reason.includes('Web-to-Account')) {
          title = 'Potential Web-to-Account Attack Sequence';
        } else if (seqRule.reason.includes('Coordinated')) {
          title = 'Potential Coordinated Activity';
        }
      } else if (users.length > 0 && threatTypes.some(t => t.toLowerCase().includes('auth') || t.toLowerCase().includes('privilege'))) {
        title = 'Suspicious Authentication and Privilege Sequence';
      } else if (sourceIps.length > 0) {
        title = `Cross-Source Correlated Activity (IP: ${sourceIps[0]})`;
      } else if (hosts.length > 0) {
        title = `Multi-Source Activity Targeting Host (${hosts[0]})`;
      }

      // Synthesize Agent Contributions
      const agentContributions: CorrelatedEvent['agentContributions'] = {};
      for (const f of cluster) {
        if (f.agentId === 'NETWORK_AGENT') {
          agentContributions.network = f.eventType || f.threatType;
        } else if (f.agentId === 'SYSTEM_AGENT') {
          agentContributions.system = f.eventType || f.threatType;
        } else if (f.agentId === 'APPLICATION_AGENT') {
          agentContributions.application = f.eventType || f.threatType;
        }
      }

      const id = `CORR-2026-${String(clusterIdx++).padStart(3, '0')}`;
      const sourcesList = [
        ...sourceIps,
        ...hosts,
        ...destinationIps
      ].filter((v, i, a) => a.indexOf(v) === i);

      const summary = `${title} spanning ${participatingAgents.length} agent domain(s) across ${cluster.length} flagged security findings.`;

      correlatedEvents.push({
        id,
        correlationId: id,
        createdAt: new Date().toISOString(),
        startTime,
        endTime,
        duration: durationStr,
        findingIds: cluster.map(f => f.id),
        eventIds: cluster.map(f => f.eventId),
        eventsCount: cluster.length,
        participatingAgents,
        sources: sourcesList.length > 0 ? sourcesList : ['Internal Telemetry'],
        sourceIps,
        destinationIps,
        hosts,
        users,
        eventTypes,
        threatTypes,
        sequence,
        correlationStrength: scoreResult.strength,
        correlationConfidence: scoreResult.confidence,
        confidence: Math.round(scoreResult.confidence * 100),
        severity: scoreResult.severity,
        title,
        attackPattern: title,
        summary,
        description: summary,
        evidence: Array.from(new Set(allEvidence)),
        indicators: Array.from(new Set(allIndicators)),
        explanation,
        status: 'CORRELATED',
        agentContributions,
        ruleResults,
        metadata: {
          scoreBreakdown: scoreResult.breakdown
        }
      });
    }

    // Sort by correlation confidence descending, then severity
    return correlatedEvents.sort((a, b) => b.correlationConfidence - a.correlationConfidence);
  }

  /**
   * Fast indexing and clustering algorithm that avoids quadratic N^2 comparison.
   */
  private static clusterFindings(
    findings: SecurityFinding[],
    config: CorrelationConfig
  ): SecurityFinding[][] {
    const windowMs = (config.timeWindowSeconds || 300) * 1000;

    // Build entity inverted indexes
    const ipIndex = new Map<string, number[]>();
    const hostIndex = new Map<string, number[]>();
    const userIndex = new Map<string, number[]>();

    findings.forEach((f, idx) => {
      if (f.sourceIp) {
        const list = ipIndex.get(f.sourceIp) || [];
        list.push(idx);
        ipIndex.set(f.sourceIp, list);
      }
      if (f.host) {
        const list = hostIndex.get(f.host) || [];
        list.push(idx);
        hostIndex.set(f.host, list);
      }
      if (f.username) {
        const list = userIndex.get(f.username) || [];
        list.push(idx);
        userIndex.set(f.username, list);
      }
    });

    // Disjoint Set (Union-Find) structure for clustering
    const parent = findings.map((_, i) => i);
    const find = (i: number): number => {
      if (parent[i] === i) return i;
      parent[i] = find(parent[i]);
      return parent[i];
    };
    const union = (i: number, j: number) => {
      const rootI = find(i);
      const rootJ = find(j);
      if (rootI !== rootJ) {
        // Temporal sanity check before union
        const tI = new Date(findings[i].timestamp).getTime();
        const tJ = new Date(findings[j].timestamp).getTime();
        if (!isNaN(tI) && !isNaN(tJ) && Math.abs(tI - tJ) > windowMs * 1.5) {
          // Beyond temporal boundary, do not merge
          return;
        }
        parent[rootI] = rootJ;
      }
    };

    // Union by shared Source IP
    for (const [_, indices] of ipIndex.entries()) {
      for (let k = 1; k < indices.length; k++) {
        union(indices[0], indices[k]);
      }
    }

    // Union by shared Host
    for (const [_, indices] of hostIndex.entries()) {
      for (let k = 1; k < indices.length; k++) {
        union(indices[0], indices[k]);
      }
    }

    // Union by shared Username
    for (const [_, indices] of userIndex.entries()) {
      for (let k = 1; k < indices.length; k++) {
        union(indices[0], indices[k]);
      }
    }

    // Group findings by root
    const clustersMap = new Map<number, SecurityFinding[]>();
    findings.forEach((f, idx) => {
      const root = find(idx);
      const cluster = clustersMap.get(root) || [];
      cluster.push(f);
      clustersMap.set(root, cluster);
    });

    return Array.from(clustersMap.values());
  }
}
