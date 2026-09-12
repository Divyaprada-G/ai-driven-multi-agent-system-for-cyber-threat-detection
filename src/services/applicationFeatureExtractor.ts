import { LogEvent } from '../types';
import {
  SingleAppEventFields,
  EndpointActivityItem,
  SourceIpAppActivityItem,
  UserAppActivityItem
} from '../types/application';

export interface ApplicationAggregatedFeatures {
  singleEvents: SingleAppEventFields[];
  endpointActivity: Map<string, EndpointActivityItem>;
  sourceIpActivity: Map<string, SourceIpAppActivityItem>;
  userActivity: Map<string, UserAppActivityItem>;
  totalEvents: number;
  webRequestsCount: number;
  apiRequestsCount: number;
  authEventsCount: number;
  statusCodeCounts: Map<number, number>;
  methodCounts: Map<string, number>;
  uniqueEndpoints: Set<string>;
  uniqueSourceIps: Set<string>;
  uniqueUsers: Set<string>;
  baselineStatus: string;
  timeSpanSeconds: number;
}

export class ApplicationFeatureExtractor {
  /**
   * Safely extracts fields from an individual LogEvent without fabricating values.
   */
  public extractSingleEvent(event: LogEvent): SingleAppEventFields {
    const nf = event.normalizedFields || {};
    const meta = (event.metadata || {}) as Record<string, unknown>;

    // 1. Host / Source
    const host = (nf.hostName || meta.host || meta.hostname || undefined) as string | undefined;

    // 2. Network Addresses
    const sourceIp = (nf.sourceIp || meta.sourceIp || meta.clientIp || meta.src_ip || undefined) as string | undefined;
    const destinationIp = (nf.destinationIp || meta.destinationIp || meta.dest_ip || undefined) as string | undefined;

    // 3. User Identity (do not invent)
    let username = (nf.userName || meta.username || meta.user || meta.account || undefined) as string | undefined;
    if (username === '-' || username === 'unknown' || username === 'null') {
      username = undefined;
    }

    // 4. HTTP Method
    let method = (nf.httpMethod || meta.method || meta.httpMethod || meta.verb || undefined) as string | undefined;
    if (method) {
      method = method.toUpperCase();
    }

    // 5. Endpoint / URI / Path
    let endpoint = (nf.endpoint || meta.endpoint || meta.path || meta.url || meta.uri || undefined) as string | undefined;

    // 6. Status Code
    let statusCode: number | undefined;
    if (typeof nf.statusCode === 'number' && !isNaN(nf.statusCode)) {
      statusCode = nf.statusCode;
    } else if (meta.statusCode !== undefined && !isNaN(Number(meta.statusCode))) {
      statusCode = Number(meta.statusCode);
    } else if (meta.code !== undefined && !isNaN(Number(meta.code))) {
      statusCode = Number(meta.code);
    }

    // 7. User Agent
    const userAgent = (nf.userAgent || meta.userAgent || meta.user_agent || undefined) as string | undefined;

    // 8. Sizes
    const requestSize = typeof meta.requestSize === 'number' ? meta.requestSize : undefined;
    const responseSize = typeof meta.responseSize === 'number' ? meta.responseSize : (typeof nf.packetSize === 'number' ? nf.packetSize : undefined);

    // 9. Service / Application
    const application = (nf.applicationName || meta.application || meta.app || meta.service || undefined) as string | undefined;
    const service = (meta.service || undefined) as string | undefined;
    const api = (meta.api || undefined) as string | undefined;
    const payloadSnippet = (nf.payloadSnippet || meta.payloadSnippet || meta.payload || meta.body || undefined) as string | undefined;

    // 10. Secondary heuristic extraction from message or rawData if endpoint or method is missing
    const contentToSearch = `${event.message || ''} ${event.rawData || ''}`;

    if (!method || !endpoint || statusCode === undefined) {
      // Common Log Format pattern: "METHOD /path HTTP/x.x" 200
      const httpLineMatch = contentToSearch.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+([^\s"]+)\s+HTTP\/[0-9.]+"/i);
      if (httpLineMatch) {
        if (!method) method = httpLineMatch[1].toUpperCase();
        if (!endpoint) endpoint = httpLineMatch[2];
      }

      // If still no method, check for lone verbs
      if (!method) {
        const verbMatch = contentToSearch.match(/\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b/);
        if (verbMatch) method = verbMatch[1].toUpperCase();
      }

      // If still no endpoint, check for paths starting with /
      if (!endpoint) {
        const pathMatch = contentToSearch.match(/(?:\s|^)(\/(?:api|v[0-9]|admin|auth|static|login|search|users|docs|download)[^\s"']*)/i);
        if (pathMatch) endpoint = pathMatch[1];
      }

      // If still no status code, look for 3-digit HTTP status codes
      if (statusCode === undefined) {
        const statusMatch = contentToSearch.match(/\b([1-5][0-9]{2})\b/);
        if (statusMatch) {
          const parsed = parseInt(statusMatch[1], 10);
          if (parsed >= 100 && parsed <= 599) {
            statusCode = parsed;
          }
        }
      }
    }

    // Extract user from Combined Log format if missing: IP - username [date] "REQ"
    if (!username) {
      const combinedUserMatch = contentToSearch.match(/^[^\s]+\s+-\s+([a-zA-Z0-9._-]+)\s+\[/);
      if (combinedUserMatch && combinedUserMatch[1] !== '-') {
        username = combinedUserMatch[1];
      }
    }

    // Extract source IP from beginning of log line if missing
    let resolvedSourceIp = sourceIp;
    if (!resolvedSourceIp) {
      const ipMatch = contentToSearch.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
      if (ipMatch) {
        resolvedSourceIp = ipMatch[0];
      }
    }

    return {
      id: event.id,
      timestamp: event.timestamp,
      source: event.source || 'application-service',
      host,
      sourceIp: resolvedSourceIp,
      destinationIp,
      username,
      eventType: event.normalizedFields?.flags?.[0] || (meta.eventType as string) || undefined,
      method,
      url: endpoint,
      path: endpoint,
      endpoint: endpoint || '/',
      statusCode: statusCode ?? 200,
      responseCode: statusCode,
      userAgent,
      requestSize,
      responseSize,
      message: event.message,
      application,
      service,
      api,
      payloadSnippet,
      rawEvent: event
    };
  }

  /**
   * Processes a collection of LogEvents into an aggregated feature matrix.
   */
  public extractAggregations(events: LogEvent[]): ApplicationAggregatedFeatures {
    const singleEvents: SingleAppEventFields[] = [];
    const endpointActivity = new Map<string, EndpointActivityItem>();
    const sourceIpActivity = new Map<string, SourceIpAppActivityItem>();
    const userActivity = new Map<string, UserAppActivityItem>();
    const statusCodeCounts = new Map<number, number>();
    const methodCounts = new Map<string, number>();
    const uniqueEndpoints = new Set<string>();
    const uniqueSourceIps = new Set<string>();
    const uniqueUsers = new Set<string>();

    let webRequestsCount = 0;
    let apiRequestsCount = 0;
    let authEventsCount = 0;

    let minTimestamp = Infinity;
    let maxTimestamp = -Infinity;

    for (const evt of events) {
      const fields = this.extractSingleEvent(evt);
      singleEvents.push(fields);

      const ts = new Date(fields.timestamp).getTime();
      if (!isNaN(ts)) {
        if (ts < minTimestamp) minTimestamp = ts;
        if (ts > maxTimestamp) maxTimestamp = ts;
      }

      const ep = fields.endpoint || '/';
      const cleanEndpoint = ep.split('?')[0]; // aggregate base path
      uniqueEndpoints.add(cleanEndpoint);

      const method = fields.method || 'UNKNOWN';
      methodCounts.set(method, (methodCounts.get(method) || 0) + 1);

      const statusCode = fields.statusCode ?? 200;
      statusCodeCounts.set(statusCode, (statusCodeCounts.get(statusCode) || 0) + 1);

      // Categorize request domain
      if (cleanEndpoint.startsWith('/api') || cleanEndpoint.startsWith('/v1') || cleanEndpoint.startsWith('/v2') || cleanEndpoint.includes('graphql')) {
        apiRequestsCount++;
      } else {
        webRequestsCount++;
      }

      // Check if auth event
      const isAuth =
        cleanEndpoint.includes('/auth') ||
        cleanEndpoint.includes('/login') ||
        cleanEndpoint.includes('/token') ||
        cleanEndpoint.includes('/session') ||
        statusCode === 401;

      if (isAuth) {
        authEventsCount++;
      }

      // 1. Endpoint activity
      const isError = statusCode >= 400;
      const is4xx = statusCode >= 400 && statusCode < 500;
      const is5xx = statusCode >= 500;

      const existingEp = endpointActivity.get(cleanEndpoint);
      if (existingEp) {
        existingEp.requestCount++;
        if (fields.sourceIp) existingEp.uniqueIps++;
        if (fields.username) existingEp.uniqueUsers++;
        if (isError) existingEp.errorCount++;
        if (is4xx) existingEp.status4xxCount++;
        if (is5xx) existingEp.status5xxCount++;
        if (method && !existingEp.methods.includes(method)) {
          existingEp.methods.push(method);
        }
        if (fields.userAgent && !existingEp.sampleUserAgents.includes(fields.userAgent) && existingEp.sampleUserAgents.length < 3) {
          existingEp.sampleUserAgents.push(fields.userAgent);
        }
        existingEp.lastSeen = fields.timestamp;
      } else {
        endpointActivity.set(cleanEndpoint, {
          endpoint: cleanEndpoint,
          requestCount: 1,
          uniqueUsers: fields.username ? 1 : 0,
          uniqueIps: fields.sourceIp ? 1 : 0,
          errorCount: isError ? 1 : 0,
          status4xxCount: is4xx ? 1 : 0,
          status5xxCount: is5xx ? 1 : 0,
          riskIndicator: 'NORMAL',
          highestSeverity: 'LOW',
          methods: [method],
          sampleUserAgents: fields.userAgent ? [fields.userAgent] : [],
          lastSeen: fields.timestamp
        });
      }

      // 2. Source IP activity
      if (fields.sourceIp) {
        uniqueSourceIps.add(fields.sourceIp);
        const existingIp = sourceIpActivity.get(fields.sourceIp);
        if (existingIp) {
          existingIp.requestCount++;
          if (isError) existingIp.failedRequests++;
          if (statusCode === 401 || (isAuth && statusCode >= 400)) existingIp.authFailures++;
          existingIp.lastSeen = fields.timestamp;
          if (fields.userAgent && !existingIp.primaryUserAgent) {
            existingIp.primaryUserAgent = fields.userAgent;
          }
        } else {
          sourceIpActivity.set(fields.sourceIp, {
            sourceIp: fields.sourceIp,
            requestCount: 1,
            uniqueEndpoints: 1,
            failedRequests: isError ? 1 : 0,
            authFailures: statusCode === 401 || (isAuth && statusCode >= 400) ? 1 : 0,
            suspiciousEvents: 0,
            riskIndicator: 'NORMAL',
            highestSeverity: 'LOW',
            lastSeen: fields.timestamp,
            primaryUserAgent: fields.userAgent
          });
        }
      }

      // 3. User activity
      if (fields.username) {
        uniqueUsers.add(fields.username);
        const existingUser = userActivity.get(fields.username);
        if (existingUser) {
          existingUser.requestCount++;
          if (isError) existingUser.failedRequests++;
          if (statusCode === 401 || (isAuth && statusCode >= 400)) existingUser.authFailures++;
          if (fields.sourceIp && !existingUser.associatedIps.includes(fields.sourceIp)) {
            existingUser.associatedIps.push(fields.sourceIp);
          }
          existingUser.lastSeen = fields.timestamp;
        } else {
          userActivity.set(fields.username, {
            username: fields.username,
            requestCount: 1,
            uniqueEndpoints: 1,
            failedRequests: isError ? 1 : 0,
            authFailures: statusCode === 401 || (isAuth && statusCode >= 400) ? 1 : 0,
            suspiciousEvents: 0,
            riskIndicator: 'NORMAL',
            highestSeverity: 'LOW',
            lastSeen: fields.timestamp,
            associatedIps: fields.sourceIp ? [fields.sourceIp] : []
          });
        }
      }
    }

    const timeSpanSeconds =
      minTimestamp !== Infinity && maxTimestamp !== -Infinity
        ? Math.max(1, Math.round((maxTimestamp - minTimestamp) / 1000))
        : 1;

    let baselineStatus = '';
    if (events.length === 0) {
      baselineStatus = 'No application logs loaded. Waiting for telemetry ingestion.';
    } else if (events.length < 5) {
      baselineStatus = `Insufficient baseline data (N = ${events.length} < 5 events). Analysis relying on static heuristic signatures.`;
    } else {
      baselineStatus = `Dynamic operational baseline active (${events.length} application events analyzed across ${timeSpanSeconds}s observation window).`;
    }

    return {
      singleEvents,
      endpointActivity,
      sourceIpActivity,
      userActivity,
      totalEvents: events.length,
      webRequestsCount,
      apiRequestsCount,
      authEventsCount,
      statusCodeCounts,
      methodCounts,
      uniqueEndpoints,
      uniqueSourceIps,
      uniqueUsers,
      baselineStatus,
      timeSpanSeconds
    };
  }
}

export const applicationFeatureExtractor = new ApplicationFeatureExtractor();
