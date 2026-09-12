import {
  AgentResult,
  AgentStatusInfo,
  ApplicationEvent,
  LogEvent,
  SeverityLevel
} from '../types';
import {
  ApplicationAgentAnalysis,
  ApplicationAgentResult,
  ApplicationTimelineItem,
  EndpointActivityItem,
  SourceIpAppActivityItem,
  UserAppActivityItem
} from '../types/application';
import { logRepository } from './logRepository';
import { applicationFeatureExtractor } from './applicationFeatureExtractor';
import { applicationAnomalyDetector } from './applicationDetector';
import { DEMO_APPLICATION_LOGS } from './applicationDemoData';

export interface IApplicationAgentService {
  analyzeApplicationEvents(events: LogEvent[]): ApplicationAgentAnalysis;
  getAnalysis(): Promise<ApplicationAgentAnalysis>;
  getAgentStatus(): Promise<AgentStatusInfo>;
  toggleAgentStatus(): Promise<AgentStatusInfo>;
  subscribe(listener: () => void): () => void;
  // Backward compatibility helpers
  getRecentEvents(): Promise<ApplicationEvent[]>;
  getDetectedThreats(): Promise<AgentResult[]>;
}

class ApplicationAgentServiceImpl implements IApplicationAgentService {
  private isPaused = false;
  private listeners: Set<() => void> = new Set();

  constructor() {
    logRepository.subscribe(() => {
      this.notifyListeners();
    });
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners(): void {
    this.listeners.forEach(fn => {
      try {
        fn();
      } catch (err) {
        console.error('ApplicationAgent listener error', err);
      }
    });
  }

  /**
   * Pure service analysis function.
   * Consumes LogEvents array and calculates structured detections, telemetry features,
   * baseline metrics, and chart distributions.
   */
  public analyzeApplicationEvents(events: LogEvent[]): ApplicationAgentAnalysis {
    if (!events || events.length === 0) {
      return {
        totalApplicationEvents: 0,
        webRequestsCount: 0,
        apiRequestsCount: 0,
        authEventsCount: 0,
        suspiciousEventsCount: 0,
        potentialThreatsCount: 0,
        averageConfidence: 0,
        uniqueUsersCount: 0,
        uniqueSourceIpsCount: 0,
        uniqueEndpointsCount: 0,
        isRealData: false,
        dataSource: 'No Application Events Ingested',
        results: [],
        endpointActivity: [],
        sourceIpActivity: [],
        userActivity: [],
        eventsOverTime: [],
        statusCodeDistribution: [
          { statusCode: '200 OK', count: 0, color: '#10b981' },
          { statusCode: '401 Unauthorized', count: 0, color: '#f59e0b' },
          { statusCode: '403 Forbidden', count: 0, color: '#f97316' },
          { statusCode: '404 Not Found', count: 0, color: '#8b5cf6' },
          { statusCode: '429 Too Many Req', count: 0, color: '#ec4899' },
          { statusCode: '500 Server Error', count: 0, color: '#ef4444' }
        ],
        topEndpoints: [],
        topSourceIps: [],
        methodDistribution: [],
        authFailuresOverTime: [],
        threatSeverityDistribution: [
          { severity: 'LOW', count: 0, color: '#3b82f6' },
          { severity: 'MEDIUM', count: 0, color: '#f59e0b' },
          { severity: 'HIGH', count: 0, color: '#f97316' },
          { severity: 'CRITICAL', count: 0, color: '#ef4444' }
        ],
        timeline: [],
        baselineStatus: 'Insufficient baseline data (0 events)'
      };
    }

    // 1. Extract aggregated features
    const features = applicationFeatureExtractor.extractAggregations(events);

    // 2. Run heuristic detection engine
    const results = applicationAnomalyDetector.detectAnomalies(features);

    // 3. Classify counts
    const threatsOnly = results.filter(r => r.threatDetected);
    const suspiciousOnly = results.filter(r => r.classification === 'SUSPICIOUS');

    const totalConfidence = threatsOnly.length > 0
      ? threatsOnly.reduce((acc, curr) => acc + curr.confidence, 0) / threatsOnly.length
      : 0.95;

    // 4. Build Status Code distribution
    const statusCodeColors: Record<string, string> = {
      '200': '#10b981',
      '201': '#059669',
      '204': '#34d399',
      '301': '#60a5fa',
      '302': '#3b82f6',
      '400': '#f59e0b',
      '401': '#eab308',
      '403': '#f97316',
      '404': '#8b5cf6',
      '429': '#ec4899',
      '500': '#ef4444',
      '502': '#dc2626',
      '503': '#b91c1c'
    };

    const statusCodeDistribution = Array.from(features.statusCodeCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([code, count]) => {
        const strCode = String(code);
        let label = `HTTP ${strCode}`;
        if (code === 200) label = '200 OK';
        else if (code === 401) label = '401 Unauthorized';
        else if (code === 403) label = '403 Forbidden';
        else if (code === 404) label = '404 Not Found';
        else if (code === 429) label = '429 Rate Limited';
        else if (code === 500) label = '500 Server Error';
        else if (code === 400) label = '400 Bad Request';

        return {
          statusCode: label,
          count,
          color: statusCodeColors[strCode] || '#64748b'
        };
      });

    // 5. Build Method distribution
    const methodColors: Record<string, string> = {
      GET: '#3b82f6',
      POST: '#10b981',
      PUT: '#f59e0b',
      DELETE: '#ef4444',
      PATCH: '#8b5cf6',
      HEAD: '#64748b',
      OPTIONS: '#94a3b8'
    };

    const methodDistribution = Array.from(features.methodCounts.entries())
      .map(([method, count]) => ({
        method,
        count,
        color: methodColors[method] || '#64748b'
      }))
      .sort((a, b) => b.count - a.count);

    // 6. Build Top Endpoints
    const topEndpoints = Array.from(features.endpointActivity.values())
      .sort((a, b) => b.requestCount - a.requestCount)
      .slice(0, 6)
      .map(ep => ({
        endpoint: ep.endpoint.length > 25 ? ep.endpoint.slice(0, 25) + '...' : ep.endpoint,
        count: ep.requestCount,
        errors: ep.errorCount
      }));

    // 7. Build Top Source IPs
    const topSourceIps = Array.from(features.sourceIpActivity.values())
      .sort((a, b) => b.requestCount - a.requestCount)
      .slice(0, 6)
      .map(ip => ({
        sourceIp: ip.sourceIp,
        count: ip.requestCount,
        threats: ip.failedRequests + ip.suspiciousEvents
      }));

    // 8. Severity distribution
    const severityDistribution: { severity: SeverityLevel; count: number; color: string }[] = [
      { severity: 'LOW', count: results.filter(r => r.severity === 'LOW').length, color: '#3b82f6' },
      { severity: 'MEDIUM', count: results.filter(r => r.severity === 'MEDIUM').length, color: '#f59e0b' },
      { severity: 'HIGH', count: results.filter(r => r.severity === 'HIGH').length, color: '#f97316' },
      { severity: 'CRITICAL', count: results.filter(r => r.severity === 'CRITICAL').length, color: '#ef4444' }
    ];

    // 9. Events Over Time (grouped by minute or relative buckets)
    const timeBuckets = new Map<string, { count: number; threats: number }>();
    const authTimeBuckets = new Map<string, { failed: number; successful: number }>();

    for (const evt of features.singleEvents) {
      let bucketKey = 'Recent';
      try {
        const d = new Date(evt.timestamp);
        if (!isNaN(d.getTime())) {
          bucketKey = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
        }
      } catch {
        bucketKey = evt.timestamp.slice(11, 16) || 'Recent';
      }

      const existing = timeBuckets.get(bucketKey) || { count: 0, threats: 0 };
      existing.count++;
      timeBuckets.set(bucketKey, existing);

      // Auth buckets
      if (evt.endpoint.includes('auth') || evt.endpoint.includes('login') || evt.statusCode === 401) {
        const authExisting = authTimeBuckets.get(bucketKey) || { failed: 0, successful: 0 };
        if (evt.statusCode === 401 || (evt.statusCode && evt.statusCode >= 400)) {
          authExisting.failed++;
        } else if (evt.statusCode === 200 || evt.statusCode === 204) {
          authExisting.successful++;
        }
        authTimeBuckets.set(bucketKey, authExisting);
      }
    }

    // Link threats to time buckets
    for (const res of threatsOnly) {
      let bucketKey = 'Recent';
      try {
        const d = new Date(res.timestamp);
        if (!isNaN(d.getTime())) {
          bucketKey = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
        }
      } catch {
        bucketKey = res.timestamp.slice(11, 16) || 'Recent';
      }
      const existing = timeBuckets.get(bucketKey);
      if (existing) {
        existing.threats++;
      }
    }

    const eventsOverTime = Array.from(timeBuckets.entries()).map(([time, val]) => ({
      time,
      count: val.count,
      threats: val.threats
    }));

    const authFailuresOverTime = Array.from(authTimeBuckets.entries()).map(([time, val]) => ({
      time,
      failed: val.failed,
      successful: val.successful
    }));

    // 10. Chronological Timeline items
    const timeline: ApplicationTimelineItem[] = results.slice(0, 30).map(res => ({
      id: res.id,
      timestamp: res.timestamp,
      endpoint: res.endpoint || '/',
      method: res.method || 'REQ',
      statusCode: res.statusCode || 200,
      sourceIp: res.sourceIp || 'Internal / Direct',
      username: res.username || '-',
      detection: res.detection,
      details: res.observedActivity,
      severity: res.severity,
      classification: res.classification
    }));

    // Update risk indicators in endpoint and IP activity lists based on threat findings
    for (const ep of features.endpointActivity.values()) {
      const epThreats = results.filter(r => r.endpoint?.startsWith(ep.endpoint) && r.threatDetected);
      if (epThreats.some(t => t.severity === 'CRITICAL' || t.severity === 'HIGH')) {
        ep.riskIndicator = 'HIGH';
        ep.highestSeverity = 'HIGH';
      } else if (epThreats.length > 0 || ep.errorCount >= 2) {
        ep.riskIndicator = 'ELEVATED';
        ep.highestSeverity = 'MEDIUM';
      }
    }

    for (const ip of features.sourceIpActivity.values()) {
      const ipThreats = results.filter(r => r.sourceIp === ip.sourceIp && r.threatDetected);
      ip.suspiciousEvents = ipThreats.length;
      if (ipThreats.some(t => t.severity === 'CRITICAL' || t.severity === 'HIGH')) {
        ip.riskIndicator = 'HIGH';
        ip.highestSeverity = 'HIGH';
      } else if (ipThreats.length > 0 || ip.failedRequests >= 3) {
        ip.riskIndicator = 'ELEVATED';
        ip.highestSeverity = 'MEDIUM';
      }
    }

    for (const user of features.userActivity.values()) {
      const userThreats = results.filter(r => r.username === user.username && r.threatDetected);
      user.suspiciousEvents = userThreats.length;
      if (userThreats.some(t => t.severity === 'CRITICAL' || t.severity === 'HIGH')) {
        user.riskIndicator = 'HIGH';
        user.highestSeverity = 'HIGH';
      } else if (userThreats.length > 0 || user.failedRequests >= 2) {
        user.riskIndicator = 'ELEVATED';
        user.highestSeverity = 'MEDIUM';
      }
    }

    return {
      totalApplicationEvents: events.length,
      webRequestsCount: features.webRequestsCount,
      apiRequestsCount: features.apiRequestsCount,
      authEventsCount: features.authEventsCount,
      suspiciousEventsCount: suspiciousOnly.length,
      potentialThreatsCount: threatsOnly.length,
      averageConfidence: Number(totalConfidence.toFixed(2)),
      uniqueUsersCount: features.uniqueUsers.size,
      uniqueSourceIpsCount: features.uniqueSourceIps.size,
      uniqueEndpointsCount: features.uniqueEndpoints.size,
      isRealData: false, // will be resolved in getAnalysis()
      dataSource: 'Application Telemetry',
      results,
      endpointActivity: Array.from(features.endpointActivity.values()),
      sourceIpActivity: Array.from(features.sourceIpActivity.values()),
      userActivity: Array.from(features.userActivity.values()),
      eventsOverTime,
      statusCodeDistribution,
      topEndpoints,
      topSourceIps,
      methodDistribution,
      authFailuresOverTime,
      threatSeverityDistribution: severityDistribution,
      timeline,
      baselineStatus: features.baselineStatus
    };
  }

  /**
   * Fetches the current analysis based on live repository data or demo fallback.
   */
  public async getAnalysis(): Promise<ApplicationAgentAnalysis> {
    const hasReal = logRepository.hasRealData();
    let eventsToAnalyze: LogEvent[] = [];
    let isRealData = false;
    let dataSource = 'DEMO DATA: Simulated Web & API Access Logs';

    if (hasReal) {
      const { events } = logRepository.getEvents();
      const realAppEvents = events.filter(
        e =>
          e.logType === 'APPLICATION' ||
          (e.normalizedFields &&
            (e.normalizedFields.endpoint ||
              e.normalizedFields.httpMethod ||
              e.normalizedFields.statusCode !== undefined)) ||
          e.source.toLowerCase().includes('nginx') ||
          e.source.toLowerCase().includes('apache') ||
          e.source.toLowerCase().includes('web') ||
          e.source.toLowerCase().includes('api') ||
          e.source.toLowerCase().includes('waf')
      );

      if (realAppEvents.length > 0) {
        eventsToAnalyze = realAppEvents;
        isRealData = true;
        dataSource = `Uploaded Application Logs (${realAppEvents.length} events ingested)`;
      }
    }

    if (!isRealData) {
      eventsToAnalyze = DEMO_APPLICATION_LOGS;
      isRealData = false;
      dataSource = 'DEMO DATA: Simulated Web & API Access Logs';
    }

    const analysis = this.analyzeApplicationEvents(eventsToAnalyze);
    analysis.isRealData = isRealData;
    analysis.dataSource = dataSource;

    return analysis;
  }

  public async getAgentStatus(): Promise<AgentStatusInfo> {
    const analysis = await this.getAnalysis();

    return {
      agentId: 'APPLICATION_AGENT',
      name: 'Application Security Agent',
      status: this.isPaused ? 'DEGRADED' : 'READY',
      eventsProcessed: analysis.totalApplicationEvents,
      threatsDetected: analysis.potentialThreatsCount,
      lastActivity: analysis.results[0]?.timestamp || 'Just now',
      detectionConfidence: Math.round(analysis.averageConfidence * 100),
      description: 'Monitors HTTP/HTTPS application gateways, REST/GraphQL APIs, microservices, and web ingress for injection, traversal, authentication abuse, and rate-limit violations.',
      activeRulesCount: 16,
      uptime: '99.98%'
    };
  }

  public async toggleAgentStatus(): Promise<AgentStatusInfo> {
    this.isPaused = !this.isPaused;
    this.notifyListeners();
    return this.getAgentStatus();
  }

  // Backward compatibility helpers
  public async getRecentEvents(): Promise<ApplicationEvent[]> {
    const analysis = await this.getAnalysis();
    return analysis.results.slice(0, 10).map((r, i) => ({
      id: r.eventId || `APP-EVT-${i}`,
      timestamp: r.timestamp,
      source: r.source || 'App Gateway',
      logType: 'APPLICATION',
      message: r.observedActivity,
      applicationName: 'Web & API Gateway',
      httpMethod: (r.method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH') || 'GET',
      endpoint: r.endpoint || '/',
      statusCode: r.statusCode || 200,
      userAgent: r.userAgent,
      payloadSnippet: r.evidence.find(e => e.startsWith('Payload snippet'))
    }));
  }

  public async getDetectedThreats(): Promise<AgentResult[]> {
    const analysis = await this.getAnalysis();
    return analysis.results
      .filter(r => r.threatDetected)
      .slice(0, 10)
      .map(r => ({
        agentId: 'APPLICATION_AGENT',
        eventId: r.eventId,
        timestamp: r.timestamp,
        detection: r.detection,
        confidence: r.confidence,
        severity: r.severity,
        indicators: r.indicators,
        rawEvidence: r.observedActivity
      }));
  }
}

export const applicationAgentService: IApplicationAgentService = new ApplicationAgentServiceImpl();
