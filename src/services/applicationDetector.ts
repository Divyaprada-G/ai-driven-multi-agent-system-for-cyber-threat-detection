import {
  ApplicationAgentResult,
  ApplicationThreatType,
  ApplicationAgentClassification,
  SingleAppEventFields
} from '../types/application';
import { SeverityLevel } from '../types';
import { ApplicationAggregatedFeatures } from './applicationFeatureExtractor';

export interface IApplicationAnomalyDetector {
  detectAnomalies(features: ApplicationAggregatedFeatures): ApplicationAgentResult[];
}

export class ApplicationAnomalyDetector implements IApplicationAnomalyDetector {
  /**
   * Evaluates aggregated application features and single-event features
   * to produce structured, explainable ApplicationAgentResult objects.
   */
  public detectAnomalies(features: ApplicationAggregatedFeatures): ApplicationAgentResult[] {
    const results: ApplicationAgentResult[] = [];
    const { singleEvents, sourceIpActivity, userActivity } = features;

    if (singleEvents.length === 0) {
      return [];
    }

    // Pre-calculate per-IP and per-user sequences for temporal correlation
    const ipEvents = new Map<string, SingleAppEventFields[]>();
    const userEvents = new Map<string, SingleAppEventFields[]>();

    for (const evt of singleEvents) {
      if (evt.sourceIp) {
        const list = ipEvents.get(evt.sourceIp) || [];
        list.push(evt);
        ipEvents.set(evt.sourceIp, list);
      }
      if (evt.username) {
        const list = userEvents.get(evt.username) || [];
        list.push(evt);
        userEvents.set(evt.username, list);
      }
    }

    // Track which event IDs have been assigned a high-priority threat
    const evaluatedEventIds = new Set<string>();

    // -------------------------------------------------------------
    // RULE 1: Web Attack Indicators (SQLi, Traversal, XSS, JNDI, Known Scanners)
    // -------------------------------------------------------------
    for (const evt of singleEvents) {
      const payload = `${evt.endpoint} ${evt.url || ''} ${evt.payloadSnippet || ''} ${evt.message} ${evt.userAgent || ''}`;
      const lowerPayload = payload.toLowerCase();

      const attacksDetected: { name: string; signature: string; severity: SeverityLevel; confidence: number }[] = [];

      // SQL Injection signatures
      if (
        /(?:union(?:\s+all)?\s+select|select\s+.*?\s+from\s+information_schema|'\s*or\s*1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|;\s*drop\s+table|exec(?:\s+xp_cmdshell)?|\bbenchmark\([0-9]+,[0-9]+\)|\bsleep\([0-9]+\))/i.test(payload) ||
        lowerPayload.includes('union select') ||
        lowerPayload.includes('1=1--') ||
        lowerPayload.includes('information_schema')
      ) {
        attacksDetected.push({
          name: 'SQL Injection Payload',
          signature: 'SQL syntax keywords (UNION SELECT / OR 1=1 / information_schema)',
          severity: 'HIGH',
          confidence: 0.96
        });
      }

      // Path Traversal signatures
      if (
        /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i.test(payload) ||
        lowerPayload.includes('../') ||
        lowerPayload.includes('%2e%2e%2f') ||
        lowerPayload.includes('/etc/passwd')
      ) {
        attacksDetected.push({
          name: 'Directory / Path Traversal Indicator',
          signature: 'Relative dot-dot-slash sequence or sensitive system file target (/etc/passwd)',
          severity: 'HIGH',
          confidence: 0.94
        });
      }

      // Cross-Site Scripting (XSS) signatures
      if (
        /(?:<script[\s>].*?<\/script>|javascript:|onerror\s*=|onload\s*=|alert\(document\.cookie\)|%3cscript%3e)/i.test(payload) ||
        lowerPayload.includes('<script>') ||
        lowerPayload.includes('%3cscript%3e') ||
        lowerPayload.includes('alert(document.cookie)')
      ) {
        attacksDetected.push({
          name: 'Cross-Site Scripting (XSS) Indicator',
          signature: 'Script tag injection or cookie retrieval attempt',
          severity: 'MEDIUM',
          confidence: 0.90
        });
      }

      // Log4Shell / JNDI injection
      if (lowerPayload.includes('${jndi:') || lowerPayload.includes('${lower:') || lowerPayload.includes('${upper:')) {
        attacksDetected.push({
          name: 'JNDI / Log4Shell Remote Code Execution Indicator',
          signature: 'JNDI lookup expression syntax in HTTP headers/payload',
          severity: 'CRITICAL',
          confidence: 0.98
        });
      }

      // Scanner User-Agent identification
      const userAgentLower = (evt.userAgent || '').toLowerCase();
      let scannerName = '';
      if (userAgentLower.includes('sqlmap')) scannerName = 'sqlmap';
      else if (userAgentLower.includes('nikto')) scannerName = 'Nikto Web Scanner';
      else if (userAgentLower.includes('nmap')) scannerName = 'Nmap NSE';
      else if (userAgentLower.includes('masscan')) scannerName = 'Masscan';
      else if (userAgentLower.includes('dirbuster') || userAgentLower.includes('gobuster')) scannerName = 'GoBuster / DirBuster Fuzzer';

      if (scannerName) {
        attacksDetected.push({
          name: `Automated Reconnaissance Tool (${scannerName})`,
          signature: `Client User-Agent identifying security scanner tool: ${evt.userAgent}`,
          severity: 'HIGH',
          confidence: 0.95
        });
      }

      if (attacksDetected.length > 0) {
        evaluatedEventIds.add(evt.id);

        const primary = attacksDetected[0];
        const isCritical = attacksDetected.some(a => a.severity === 'CRITICAL') || attacksDetected.length > 1;
        const finalSeverity: SeverityLevel = isCritical ? 'CRITICAL' : primary.severity;
        const maxConfidence = Math.max(...attacksDetected.map(a => a.confidence));

        results.push({
          id: `APP-RES-${evt.id}`,
          agentId: 'APPLICATION_AGENT',
          eventId: evt.id,
          timestamp: evt.timestamp,
          source: evt.source,
          threatDetected: true,
          threatType: 'WEB_ATTACK_INDICATOR',
          severity: finalSeverity,
          confidence: Number(maxConfidence.toFixed(2)),
          classification: 'THREAT',
          detection: `Potential Web Attack Indicator: ${attacksDetected.map(a => a.name).join(' & ')}`,
          sourceIp: evt.sourceIp,
          username: evt.username,
          host: evt.host,
          method: evt.method,
          endpoint: evt.endpoint,
          statusCode: evt.statusCode,
          userAgent: evt.userAgent,
          observedActivity: `Observed HTTP ${evt.method || 'REQ'} targeting ${evt.endpoint} (Status: ${evt.statusCode}) from ${evt.sourceIp || 'unknown IP'}. User-Agent: "${evt.userAgent || 'none'}".`,
          detectedPattern: `Request contained ${attacksDetected.length} malicious injection / scanner signatures: ${attacksDetected.map(a => a.signature).join('; ')}.`,
          securityFinding: `Potential Web Attack Indicator: Malicious input sequence intercepted at application gateway.`,
          evidence: [
            `Target endpoint: ${evt.endpoint}`,
            `HTTP status returned: ${evt.statusCode}`,
            ...attacksDetected.map(a => `Detected pattern: ${a.name} (${a.signature})`),
            evt.payloadSnippet ? `Payload snippet: "${evt.payloadSnippet}"` : `Event message: "${evt.message}"`
          ],
          indicators: [
            'Web Attack Indicator',
            ...attacksDetected.map(a => a.name.split(' ')[0]),
            evt.method || 'HTTP',
            `Status ${evt.statusCode}`
          ],
          recommendedAction: `Informational Advisory: Verify application firewall (WAF) filtering on endpoint ${evt.endpoint}. Inspect upstream proxy logs for client IP ${evt.sourceIp || 'origin'} to confirm containment.`,
          status: 'NEW',
          rawEvent: evt.rawEvent
        });
      }
    }

    // -------------------------------------------------------------
    // RULE 2: Suspicious Authentication Patterns & Brute Force
    // -------------------------------------------------------------
    // Group auth events by source IP and by user to detect velocity
    for (const [ip, eventsList] of ipEvents.entries()) {
      const authFailures = eventsList.filter(
        e => e.statusCode === 401 || (e.endpoint.includes('auth') && e.statusCode >= 400) || /auth.*fail/i.test(e.message)
      );

      // Check for successive auth failures
      if (authFailures.length >= 3) {
        // Mark these events
        for (const evt of authFailures) {
          if (evaluatedEventIds.has(evt.id)) continue;
          evaluatedEventIds.add(evt.id);

          const timeSpan = Math.max(1, Math.round(
            (new Date(authFailures[authFailures.length - 1].timestamp).getTime() - new Date(authFailures[0].timestamp).getTime()) / 1000
          ));

          // Check if there was a subsequent successful login
          const subsequentSuccess = eventsList.find(
            e => new Date(e.timestamp).getTime() > new Date(evt.timestamp).getTime() && (e.statusCode === 200 || e.statusCode === 204) && e.endpoint.includes('login')
          );

          const isHigh = authFailures.length >= 5 || subsequentSuccess !== undefined;
          const confidence = Math.min(0.95, 0.80 + (authFailures.length * 0.03));

          results.push({
            id: `APP-RES-${evt.id}`,
            agentId: 'APPLICATION_AGENT',
            eventId: evt.id,
            timestamp: evt.timestamp,
            source: evt.source,
            threatDetected: true,
            threatType: 'SUSPICIOUS_AUTH_PATTERN',
            severity: isHigh ? 'HIGH' : 'MEDIUM',
            confidence: Number(confidence.toFixed(2)),
            classification: 'THREAT',
            detection: subsequentSuccess
              ? 'Suspicious Authentication Pattern: Account Access After Multiple Failures'
              : 'Suspicious Application Authentication Pattern: Repeated Login Failures',
            sourceIp: evt.sourceIp,
            username: evt.username,
            host: evt.host,
            method: evt.method,
            endpoint: evt.endpoint,
            statusCode: evt.statusCode,
            userAgent: evt.userAgent,
            observedActivity: `${authFailures.length} failed authentication attempts recorded from IP ${ip} across ${timeSpan} seconds targeting endpoint ${evt.endpoint}${evt.username ? ` for user "${evt.username}"` : ''}.`,
            detectedPattern: subsequentSuccess
              ? `High-velocity authentication failures followed by a successful login at ${subsequentSuccess.timestamp}. Indicates potential password guessing or credential validation.`
              : `Repeated HTTP 401 Unauthorized responses exceeding threshold of 3 attempts from a single source address.`,
            securityFinding: `Suspicious Application Authentication Pattern: Potential credential stuffing or brute force against application identity gateway.`,
            evidence: [
              `Failed authentication count from IP ${ip}: ${authFailures.length}`,
              `Time window: ${timeSpan} seconds`,
              `Target endpoint: ${evt.endpoint}`,
              evt.username ? `Target username: ${evt.username}` : 'No username disclosed in request header',
              subsequentSuccess ? `Subsequent successful login observed at: ${subsequentSuccess.timestamp}` : 'All observed attempts resulted in HTTP 401/403'
            ],
            indicators: [
              'Authentication Failure Velocity',
              'HTTP 401',
              'Credential Guessing',
              evt.username ? `User:${evt.username}` : 'Anonymous Source'
            ],
            recommendedAction: `Informational Advisory: Review authentication rate-limiting on ${evt.endpoint}. If user account ${evt.username || 'target'} is valid, monitor for anomalous session token activity.`,
            status: 'NEW',
            rawEvent: evt.rawEvent
          });
        }
      }
    }

    // -------------------------------------------------------------
    // RULE 3: Unauthorized Access to Restricted Resources (403, /admin, /.env)
    // -------------------------------------------------------------
    for (const evt of singleEvents) {
      if (evaluatedEventIds.has(evt.id)) continue;

      const endpointLower = (evt.endpoint || '').toLowerCase();
      const isRestrictedTarget =
        endpointLower.includes('/admin') ||
        endpointLower.includes('/actuator') ||
        endpointLower.includes('/internal') ||
        endpointLower.includes('/.env') ||
        endpointLower.includes('/config') ||
        endpointLower.includes('/wp-admin') ||
        endpointLower.includes('/phpmyadmin') ||
        endpointLower.includes('/.git');

      const isAccessDenied = evt.statusCode === 403 || (evt.statusCode === 401 && isRestrictedTarget);

      if (isAccessDenied || (isRestrictedTarget && (evt.statusCode === 404 || evt.statusCode === 200))) {
        evaluatedEventIds.add(evt.id);

        const isThreat = evt.statusCode === 403 || evt.statusCode === 200;
        const confidence = isThreat ? 0.88 : 0.80;

        results.push({
          id: `APP-RES-${evt.id}`,
          agentId: 'APPLICATION_AGENT',
          eventId: evt.id,
          timestamp: evt.timestamp,
          source: evt.source,
          threatDetected: isThreat,
          threatType: 'UNAUTHORIZED_ACCESS',
          severity: isThreat ? 'HIGH' : 'MEDIUM',
          confidence: Number(confidence.toFixed(2)),
          classification: isThreat ? 'THREAT' : 'SUSPICIOUS',
          detection: `Potential Unauthorized Access: Restricted Resource Probe (${evt.endpoint})`,
          sourceIp: evt.sourceIp,
          username: evt.username,
          host: evt.host,
          method: evt.method,
          endpoint: evt.endpoint,
          statusCode: evt.statusCode,
          userAgent: evt.userAgent,
          observedActivity: `HTTP ${evt.method || 'GET'} request targeting protected administrative resource ${evt.endpoint} resulted in HTTP ${evt.statusCode} from ${evt.sourceIp || 'client'}.`,
          detectedPattern: `Probing access to restricted administrative or internal system route without verified privileges.`,
          securityFinding: `Potential Unauthorized Access: Request intercepted targeting restricted application configuration or administrative portal.`,
          evidence: [
            `Target URI: ${evt.endpoint}`,
            `HTTP Status Code: ${evt.statusCode}`,
            `Client Source IP: ${evt.sourceIp || 'Not provided'}`,
            evt.username ? `Authenticated User: ${evt.username}` : 'Unauthenticated access attempt',
            `User-Agent: ${evt.userAgent || 'Standard'}`
          ],
          indicators: ['Restricted Resource Probe', 'Unauthorized Access Attempt', `Status ${evt.statusCode}`],
          recommendedAction: `Informational Advisory: Verify RBAC permissions and IP allowlists restricting access to ${evt.endpoint}. Ensure sensitive configuration files are not exposed to external clients.`,
          status: 'NEW',
          rawEvent: evt.rawEvent
        });
      }
    }

    // -------------------------------------------------------------
    // RULE 4: API Misuse & Excessive Rate Limit Violations (429, High Velocity)
    // -------------------------------------------------------------
    for (const [ip, eventsList] of ipEvents.entries()) {
      const apiCalls = eventsList.filter(e => e.endpoint.startsWith('/api') || e.endpoint.startsWith('/v1') || e.endpoint.startsWith('/v2'));
      const rateLimitHits = eventsList.filter(e => e.statusCode === 429);

      if (rateLimitHits.length >= 2 || apiCalls.length >= 10) {
        for (const evt of eventsList) {
          if (evaluatedEventIds.has(evt.id)) continue;
          if (evt.statusCode === 429 || (apiCalls.length >= 10 && evt.endpoint.startsWith('/api'))) {
            evaluatedEventIds.add(evt.id);

            const confidence = rateLimitHits.length >= 2 ? 0.89 : 0.82;
            const severity: SeverityLevel = rateLimitHits.length >= 3 ? 'HIGH' : 'MEDIUM';

            results.push({
              id: `APP-RES-${evt.id}`,
              agentId: 'APPLICATION_AGENT',
              eventId: evt.id,
              timestamp: evt.timestamp,
              source: evt.source,
              threatDetected: true,
              threatType: 'API_MISUSE',
              severity,
              confidence: Number(confidence.toFixed(2)),
              classification: 'THREAT',
              detection: rateLimitHits.length > 0
                ? 'Potential API Misuse: HTTP 429 Rate Limit Exhaustion'
                : 'Potential API Misuse: High Request Frequency on API Routes',
              sourceIp: evt.sourceIp,
              username: evt.username,
              host: evt.host,
              method: evt.method,
              endpoint: evt.endpoint,
              statusCode: evt.statusCode,
              userAgent: evt.userAgent,
              observedActivity: `Client ${ip} dispatched ${apiCalls.length} API requests with ${rateLimitHits.length} rate-limiting responses (HTTP 429) across observation window.`,
              detectedPattern: `API request volume and rate-limit triggers exceed standard client operational profile.`,
              securityFinding: `Potential API Misuse: Aggressive endpoint query velocity targeting API service ${evt.endpoint}.`,
              evidence: [
                `Total API requests from IP ${ip}: ${apiCalls.length}`,
                `HTTP 429 Rate-Limit Exceeded events: ${rateLimitHits.length}`,
                `Target endpoint: ${evt.endpoint}`,
                `HTTP Method: ${evt.method || 'GET'}`
              ],
              indicators: ['API Misuse', 'Rate Limit Violation', 'High Velocity API', `HTTP ${evt.statusCode}`],
              recommendedAction: `Informational Advisory: Review token quota or client API keys assigned to IP ${ip}. Implement progressive back-off throttles on endpoint ${evt.endpoint}.`,
              status: 'NEW',
              rawEvent: evt.rawEvent
            });
          }
        }
      }
    }

    // -------------------------------------------------------------
    // RULE 5: Abnormal Endpoint Enumeration (404 Fuzzing / Scanning)
    // -------------------------------------------------------------
    for (const [ip, eventsList] of ipEvents.entries()) {
      const notFounds = eventsList.filter(e => e.statusCode === 404);
      if (notFounds.length >= 3) {
        for (const evt of notFounds) {
          if (evaluatedEventIds.has(evt.id)) continue;
          evaluatedEventIds.add(evt.id);

          results.push({
            id: `APP-RES-${evt.id}`,
            agentId: 'APPLICATION_AGENT',
            eventId: evt.id,
            timestamp: evt.timestamp,
            source: evt.source,
            threatDetected: true,
            threatType: 'ABNORMAL_WEB_REQUEST',
            severity: 'MEDIUM',
            confidence: 0.84,
            classification: 'SUSPICIOUS',
            detection: 'Abnormal Web Request Pattern: Automated Directory / Endpoint Enumeration',
            sourceIp: evt.sourceIp,
            username: evt.username,
            host: evt.host,
            method: evt.method,
            endpoint: evt.endpoint,
            statusCode: evt.statusCode,
            userAgent: evt.userAgent,
            observedActivity: `${notFounds.length} HTTP 404 Not Found responses received by source IP ${ip} across various non-existent application routes.`,
            detectedPattern: `Pattern indicates automated URL fuzzing or dictionary scanning attempting to discover unindexed application endpoints.`,
            securityFinding: `Abnormal Web Request Pattern: Reconnaissance scanner or directory fuzzing detected.`,
            evidence: [
              `Consecutive 404 count: ${notFounds.length}`,
              `Sample missing route: ${evt.endpoint}`,
              `Source IP: ${ip}`,
              `User-Agent: ${evt.userAgent || 'Unknown'}`
            ],
            indicators: ['Endpoint Enumeration', 'HTTP 404 Fuzzing', 'Reconnaissance'],
            recommendedAction: `Informational Advisory: Review edge reverse-proxy configuration. Consider tarpitting or rate-limiting clients generating repetitive 404 errors.`,
            status: 'NEW',
            rawEvent: evt.rawEvent
          });
        }
      }
    }

    // -------------------------------------------------------------
    // RULE 6: Application Anomaly & Repeated Server Errors (500, 502, 503)
    // -------------------------------------------------------------
    for (const evt of singleEvents) {
      if (evaluatedEventIds.has(evt.id)) continue;
      if (evt.statusCode !== undefined && evt.statusCode >= 500) {
        evaluatedEventIds.add(evt.id);

        results.push({
          id: `APP-RES-${evt.id}`,
          agentId: 'APPLICATION_AGENT',
          eventId: evt.id,
          timestamp: evt.timestamp,
          source: evt.source,
          threatDetected: true,
          threatType: 'APPLICATION_ANOMALY',
          severity: 'MEDIUM',
          confidence: 0.81,
          classification: 'SUSPICIOUS',
          detection: `Application Anomaly: Abnormal Server Error Response (${evt.statusCode})`,
          sourceIp: evt.sourceIp,
          username: evt.username,
          host: evt.host,
          method: evt.method,
          endpoint: evt.endpoint,
          statusCode: evt.statusCode,
          userAgent: evt.userAgent,
          observedActivity: `HTTP ${evt.method || 'POST'} request targeting ${evt.endpoint} provoked an unhandled server error HTTP ${evt.statusCode}.`,
          detectedPattern: `Unhandled internal server fault triggered by client request input or downstream microservice instability.`,
          securityFinding: `Application Anomaly / Abnormal Error Pattern: Potential application fault or error condition triggered by input.`,
          evidence: [
            `Target endpoint: ${evt.endpoint}`,
            `Status code: HTTP ${evt.statusCode}`,
            `Client IP: ${evt.sourceIp || 'Not provided'}`,
            evt.payloadSnippet ? `Payload snippet: ${evt.payloadSnippet}` : `Message: ${evt.message}`
          ],
          indicators: ['Server Error', `HTTP ${evt.statusCode}`, 'Application Instability'],
          recommendedAction: `Informational Advisory: Inspect application error logs and stack traces for ${evt.endpoint} around ${evt.timestamp} to identify unhandled exception root cause.`,
          status: 'NEW',
          rawEvent: evt.rawEvent
        });
      }
    }

    // -------------------------------------------------------------
    // RULE 7: Abnormal User Behavior (Rapid diversity of endpoints or high failures for authenticated user)
    // -------------------------------------------------------------
    for (const [user, eventsList] of userActivity.entries()) {
      if (eventsList.suspiciousEvents > 0 || eventsList.failedRequests >= 4) {
        for (const evt of singleEvents.filter(e => e.username === user)) {
          if (evaluatedEventIds.has(evt.id)) continue;
          if (evt.statusCode && evt.statusCode >= 400) {
            evaluatedEventIds.add(evt.id);

            results.push({
              id: `APP-RES-${evt.id}`,
              agentId: 'APPLICATION_AGENT',
              eventId: evt.id,
              timestamp: evt.timestamp,
              source: evt.source,
              threatDetected: true,
              threatType: 'ABNORMAL_USER_BEHAVIOR',
              severity: 'MEDIUM',
              confidence: 0.78,
              classification: 'SUSPICIOUS',
              detection: `Abnormal Application User Behavior: User "${user}" Access Irregularity`,
              sourceIp: evt.sourceIp,
              username: user,
              host: evt.host,
              method: evt.method,
              endpoint: evt.endpoint,
              statusCode: evt.statusCode,
              userAgent: evt.userAgent,
              observedActivity: `User account "${user}" generated ${eventsList.failedRequests} failed requests across ${eventsList.uniqueEndpoints} unique application endpoints.`,
              detectedPattern: `Elevated error rate and anomalous navigation flow associated with authenticated user account.`,
              securityFinding: `Abnormal Application User Behavior: User account exhibits atypical request patterns.`,
              evidence: [
                `User identity: ${user}`,
                `Total user requests: ${eventsList.requestCount}`,
                `Failed requests: ${eventsList.failedRequests}`,
                `Last endpoint accessed: ${evt.endpoint}`
              ],
              indicators: ['Abnormal User Activity', `User:${user}`, 'Elevated Failure Ratio'],
              recommendedAction: `Informational Advisory: Verify recent activity for user "${user}" with account owner to confirm valid business access.`,
              status: 'NEW',
              rawEvent: evt.rawEvent
            });
          }
        }
      }
    }

    // -------------------------------------------------------------
    // RULE 8: Standard Benign Application Events
    // -------------------------------------------------------------
    for (const evt of singleEvents) {
      if (evaluatedEventIds.has(evt.id)) continue;

      results.push({
        id: `APP-RES-${evt.id}`,
        agentId: 'APPLICATION_AGENT',
        eventId: evt.id,
        timestamp: evt.timestamp,
        source: evt.source,
        threatDetected: false,
        threatType: 'NONE',
        severity: 'LOW',
        confidence: 0.95,
        classification: 'BENIGN',
        detection: `Normal Application Request: ${evt.method || 'GET'} ${evt.endpoint}`,
        sourceIp: evt.sourceIp,
        username: evt.username,
        host: evt.host,
        method: evt.method,
        endpoint: evt.endpoint,
        statusCode: evt.statusCode,
        userAgent: evt.userAgent,
        observedActivity: `Standard HTTP ${evt.method || 'GET'} request targeting ${evt.endpoint} (Status ${evt.statusCode}) from ${evt.sourceIp || 'client'}.`,
        detectedPattern: `Conforms to nominal application web and API access patterns. No malicious signatures or rate violations observed.`,
        securityFinding: `Benign Application Event: Standard operational traffic.`,
        evidence: [
          `Endpoint: ${evt.endpoint}`,
          `Status: HTTP ${evt.statusCode}`,
          `Method: ${evt.method || 'GET'}`,
          `Client: ${evt.sourceIp || 'internal'}`
        ],
        indicators: ['Benign Request', 'Normal Traffic', `HTTP ${evt.statusCode}`],
        recommendedAction: 'No action required. Nominal application telemetry event.',
        status: 'REVIEWED',
        rawEvent: evt.rawEvent
      });
    }

    // Sort results chronologically descending (newest first)
    return results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }
}

export const applicationAnomalyDetector = new ApplicationAnomalyDetector();
