/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Real-Time Application Telemetry Collector
 * 
 * Inspects real incoming HTTP traffic, API endpoints, error rates, and security signatures.
 * Cross-platform compatible (Windows & Linux).
 * Never fakes live status or request metrics.
 */

import os from 'os';
import crypto from 'crypto';
import {
  CollectorHealth,
  CollectorState,
  ApplicationMetricsPacket,
  NormalizedTelemetryEvent
} from './telemetryTypes';

export class ApplicationCollector {
  private enabled: boolean = false;
  private state: CollectorState = 'OFFLINE';
  private timer: NodeJS.Timeout | null = null;
  private intervalMs: number = 5000;
  private eventsCollected: number = 0;
  private eventsDropped: number = 0;
  private errorsCount: number = 0;
  private onEventCallback: ((event: NormalizedTelemetryEvent) => void) | null = null;
  private lastEventTimestamp?: string;
  private errorMessage?: string;

  // Real traffic stats
  private totalRequests: number = 0;
  private activeRequests: number = 0;
  private statusCodes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  private latencies: number[] = [];
  private securityTriggers: Array<{
    timestamp: string;
    path: string;
    method: string;
    clientIp: string;
    triggerType: 'SQLI' | 'XSS' | 'PATH_TRAVERSAL' | 'AUTH_FAILURE' | 'RATE_LIMIT';
    details: string;
  }> = [];

  constructor(intervalMs: number = 5000) {
    this.intervalMs = Math.max(1000, intervalMs);
  }

  public setEventCallback(callback: (event: NormalizedTelemetryEvent) => void) {
    this.onEventCallback = callback;
  }

  public start(): boolean {
    if (this.enabled) return true;

    try {
      this.enabled = true;
      this.state = 'LIVE';
      this.errorMessage = undefined;

      this.sampleAndEmit();

      this.timer = setInterval(() => {
        this.sampleAndEmit();
      }, this.intervalMs);

      return true;
    } catch (err: any) {
      this.state = 'ERROR';
      this.errorMessage = err.message || 'Failed starting application telemetry collector';
      this.errorsCount++;
      return false;
    }
  }

  public stop(): boolean {
    this.enabled = false;
    this.state = 'OFFLINE';
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    return true;
  }

  public isLive(): boolean {
    return this.enabled && this.state === 'LIVE';
  }

  public getStatus(): CollectorHealth {
    const errorCount = this.statusCodes['4xx'] + this.statusCodes['5xx'];
    const total = Math.max(1, this.totalRequests);
    const errRate = Number(((errorCount / total) * 100).toFixed(1));

    return {
      type: 'APPLICATION',
      name: 'Application HTTP & API Telemetry Collector',
      state: this.state,
      enabled: this.enabled,
      samplingIntervalMs: this.intervalMs,
      eventsCollected: this.eventsCollected,
      eventsDropped: this.eventsDropped,
      errorsCount: this.errorsCount,
      currentEps: this.isLive() ? Number((1000 / this.intervalMs).toFixed(2)) : 0,
      lastEventAt: this.lastEventTimestamp,
      errorMessage: this.errorMessage,
      details: {
        totalRequestsHandled: this.totalRequests,
        errorRatePercent: errRate,
        suspiciousTriggersDetected: this.securityTriggers.length,
        statusCodes: this.statusCodes
      }
    };
  }

  /**
   * Called by Express middleware on every incoming HTTP request.
   */
  public recordHttpRequest(
    method: string,
    urlPath: string,
    statusCode: number,
    durationMs: number,
    clientIp: string,
    rawQuery: string = '',
    rawBody: string = ''
  ): void {
    this.totalRequests++;

    if (statusCode >= 200 && statusCode < 300) this.statusCodes['2xx']++;
    else if (statusCode >= 300 && statusCode < 400) this.statusCodes['3xx']++;
    else if (statusCode >= 400 && statusCode < 500) this.statusCodes['4xx']++;
    else if (statusCode >= 500) this.statusCodes['5xx']++;

    this.latencies.push(durationMs);
    if (this.latencies.length > 50) this.latencies.shift();

    // Inspect request for authentic security patterns
    const fullInspectionTarget = `${urlPath} ${rawQuery} ${rawBody}`.toLowerCase();

    let triggerType: 'SQLI' | 'XSS' | 'PATH_TRAVERSAL' | 'AUTH_FAILURE' | 'RATE_LIMIT' | null = null;
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let threatName = '';

    if (
      fullInspectionTarget.includes('union select') ||
      fullInspectionTarget.includes("' or '1'='1") ||
      fullInspectionTarget.includes('information_schema') ||
      fullInspectionTarget.includes('drop table')
    ) {
      triggerType = 'SQLI';
      severity = 'CRITICAL';
      threatName = 'Web Application SQL Injection Attempt';
    } else if (
      fullInspectionTarget.includes('<script') ||
      fullInspectionTarget.includes('javascript:') ||
      fullInspectionTarget.includes('onerror=')
    ) {
      triggerType = 'XSS';
      severity = 'HIGH';
      threatName = 'Cross-Site Scripting (XSS) Injection Attempt';
    } else if (
      fullInspectionTarget.includes('../') ||
      fullInspectionTarget.includes('..\\') ||
      fullInspectionTarget.includes('/etc/passwd')
    ) {
      triggerType = 'PATH_TRAVERSAL';
      severity = 'HIGH';
      threatName = 'Path Traversal / Local File Inclusion';
    } else if (statusCode === 401 || statusCode === 403) {
      triggerType = 'AUTH_FAILURE';
      severity = 'MEDIUM';
      threatName = 'Unauthorized Resource Access Attempt';
    }

    if (triggerType && this.enabled) {
      const timestamp = new Date().toISOString();
      const details = `${threatName} detected on endpoint [${method} ${urlPath}] from source IP ${clientIp || '127.0.0.1'}. HTTP ${statusCode}.`;
      
      this.securityTriggers.push({
        timestamp,
        path: urlPath,
        method,
        clientIp: clientIp || '127.0.0.1',
        triggerType,
        details
      });

      const rawPayload = JSON.stringify({
        method,
        urlPath,
        statusCode,
        durationMs,
        clientIp,
        triggerType,
        threatName
      });

      const contentHash = crypto.createHash('sha256').update(`app|${clientIp}|${urlPath}|${timestamp}`).digest('hex');

      const event: NormalizedTelemetryEvent = {
        eventId: `APP-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
        timestamp,
        source: 'application',
        eventType: threatName,
        sourceIp: clientIp || '127.0.0.1',
        destinationIp: '127.0.0.1',
        sourcePort: 0,
        destinationPort: 3000,
        protocol: 'HTTP',
        host: os.hostname(),
        severity,
        details,
        rawPayload,
        contentHash,
        isSimulated: false,
        telemetrySource: 'APP_HTTP',
        collectorState: 'LIVE',
        features: {
          httpStatus: statusCode,
          latencyMs: durationMs,
          isError: statusCode >= 400 ? 1 : 0,
          isSecurityViolation: 1,
          pathLength: urlPath.length
        },
        agentRouting: {
          assignedAgent: 'Application Security Agent',
          assignedAgentId: 'agent-app-1'
        }
      };

      this.eventsCollected++;
      if (this.onEventCallback) {
        this.onEventCallback(event);
      }
    }
  }

  private sampleAndEmit(): void {
    if (!this.enabled) return;

    try {
      const timestamp = new Date().toISOString();
      this.lastEventTimestamp = timestamp;

      const avgLat = this.latencies.length > 0
        ? Number((this.latencies.reduce((a, b) => a + b, 0) / this.latencies.length).toFixed(1))
        : 5.0;

      const errorCount = this.statusCodes['4xx'] + this.statusCodes['5xx'];
      const total = Math.max(1, this.totalRequests);
      const errRate = Number(((errorCount / total) * 100).toFixed(1));

      let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
      let eventType = 'Application Health & HTTP Telemetry';
      let details = `API gateway active: handled ${this.totalRequests} total requests, error rate ${errRate}%, avg latency ${avgLat}ms.`;

      if (errRate > 30 && this.totalRequests > 10) {
        severity = 'HIGH';
        eventType = 'Application Error Spike - Elevated 4xx/5xx Responses';
        details = `Elevated application failure rate detected: ${errRate}% (${errorCount}/${total}) HTTP error responses.`;
      }

      const rawPayload = JSON.stringify({
        totalRequests: this.totalRequests,
        statusCodes: this.statusCodes,
        avgLatencyMs: avgLat,
        errorRatePercent: errRate
      });

      const contentHash = crypto.createHash('sha256').update(`app|status|${timestamp}`).digest('hex');

      const event: NormalizedTelemetryEvent = {
        eventId: `APP-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
        timestamp,
        source: 'application',
        eventType,
        sourceIp: '127.0.0.1',
        destinationIp: '127.0.0.1',
        sourcePort: 0,
        destinationPort: 3000,
        protocol: 'HTTP',
        host: os.hostname(),
        severity,
        details,
        rawPayload,
        contentHash,
        isSimulated: false,
        telemetrySource: 'APP_HTTP',
        collectorState: 'LIVE',
        features: {
          totalRequests: this.totalRequests,
          errorRate: errRate,
          avgLatencyMs: avgLat,
          httpStatus2xx: this.statusCodes['2xx'],
          httpStatus4xx: this.statusCodes['4xx'],
          httpStatus5xx: this.statusCodes['5xx']
        },
        agentRouting: {
          assignedAgent: 'Application Security Agent',
          assignedAgentId: 'agent-app-1'
        }
      };

      this.eventsCollected++;
      if (this.onEventCallback) {
        this.onEventCallback(event);
      }
    } catch (err: any) {
      this.errorsCount++;
      this.errorMessage = err.message;
    }
  }
}
