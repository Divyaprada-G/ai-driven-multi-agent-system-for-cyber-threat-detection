import {
  LogEvent,
  NetworkFeatures,
  NetworkAgentResult,
  SeverityLevel,
  NetworkThreatType,
  NetworkAgentClassification
} from '../types';
import { NetworkFeatureExtractor } from './networkFeatureExtractor';
import { StatisticalNetworkAnomalyDetector, INetworkAnomalyDetector } from './networkAnomalyDetector';

const SUSPICIOUS_PORT_MAP: Record<number, { service: string; severity: SeverityLevel; reason: string }> = {
  4444: { service: 'Metasploit / Meterpreter', severity: 'HIGH', reason: 'Common default reverse shell listener port used by penetration tools' },
  1337: { service: 'Elite / Backdoor Listener', severity: 'HIGH', reason: 'Common backdoor port associated with unauthorized remote access shells' },
  31337: { service: 'Back Orifice Trojan', severity: 'CRITICAL', reason: 'Legacy Trojan remote administration tool default listen port' },
  6667: { service: 'IRC / Botnet C2', severity: 'HIGH', reason: 'Plaintext IRC protocol frequently repurposed for distributed botnet command & control' },
  5555: { service: 'Android ADB Remote', severity: 'MEDIUM', reason: 'Exposed remote debugging port susceptible to unauthorized device takeover' },
  4443: { service: 'Alternative HTTPS / Cobalt Strike', severity: 'HIGH', reason: 'Non-standard TLS port frequently observed in C2 malleable HTTP profiles' },
  23: { service: 'Telnet Insecure Admin', severity: 'MEDIUM', reason: 'Unencrypted remote management protocol transmitting credentials in cleartext' },
  445: { service: 'SMB Direct Hosting', severity: 'MEDIUM', reason: 'SMB file sharing port susceptible to lateral movement exploits (EternalBlue / PsExec)' },
  65535: { service: 'Max Port Boundary', severity: 'LOW', reason: 'Unusual endpoint listening on top boundary port of TCP address space' }
};

const COMMON_SERVICES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  135: 'MS RPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MS SQL',
  1521: 'Oracle DB',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  8080: 'HTTP Proxy/Alt',
  8443: 'HTTPS Alt'
};

export class NetworkDetector {
  private anomalyDetector: INetworkAnomalyDetector;

  constructor(anomalyDetector?: INetworkAnomalyDetector) {
    this.anomalyDetector = anomalyDetector || new StatisticalNetworkAnomalyDetector();
  }

  /**
   * Main detection pipeline.
   * Consumes normalized LogEvents, extracts features, evaluates heuristics & anomaly baselines,
   * and produces explainable NetworkAgentResult records.
   */
  public analyze(events: LogEvent[]): NetworkAgentResult[] {
    if (!events || events.length === 0) {
      return [];
    }

    // 1. Train statistical baseline on input events
    this.anomalyDetector.trainBaseline(events);

    // 2. Extract aggregated features
    const sourceFeaturesMap = NetworkFeatureExtractor.extractSourceFeatures(events);
    const flowFeaturesMap = NetworkFeatureExtractor.extractServiceFlowFeatures(events);

    const results: NetworkAgentResult[] = [];
    const processedKeys = new Set<string>();

    // -------------------------------------------------------------
    // RULE A: PORT SCANNING DETECTION
    // One source IP contacting many destination ports on same host/subnet
    // -------------------------------------------------------------
    for (const [sourceIp, feat] of sourceFeaturesMap.entries()) {
      if (feat.uniqueDestinationPorts >= 3) {
        const ports = feat.destinationPortsList;
        const count = feat.uniqueDestinationPorts;
        const targetIp = feat.destinationIp || 'Multiple Targets';

        // Severity evaluation based on port diversity
        let severity: SeverityLevel = 'MEDIUM';
        if (count >= 15) {
          severity = 'CRITICAL';
        } else if (count >= 6) {
          severity = 'HIGH';
        }

        // Mathematical confidence calculation based on port count and time window
        const baseConf = 0.70;
        const portBonus = Math.min(0.20, (count - 3) * 0.02);
        const windowBonus = feat.timeSpanSeconds <= 60 ? 0.06 : 0.02;
        const confidence = Number(Math.min(0.98, baseConf + portBonus + windowBonus).toFixed(2));

        const portsPreview = ports.slice(0, 8).join(', ') + (ports.length > 8 ? ` (+${ports.length - 8} more)` : '');
        const findingKey = `PORTSCAN-${sourceIp}`;
        processedKeys.add(findingKey);

        const primaryEventId = feat.rawEventIds[0] || `NET-SCAN-${Date.now()}`;
        const matchedEvent = events.find(e => e.id === primaryEventId);

        results.push({
          id: `NET-RES-${results.length + 1}`,
          agentId: 'NETWORK_AGENT',
          eventId: primaryEventId,
          timestamp: feat.timestamp,
          detection: count >= 10 ? 'Port Scan Suspected (Broad Sweep)' : 'Potential Port Scan',
          threatDetected: true,
          threatType: 'PORT_SCAN',
          severity,
          confidence,
          classification: 'THREAT',
          sourceIp,
          destinationIp: targetIp,
          ports,
          protocol: feat.protocol || 'TCP',
          evidence: [
            `Source host ${sourceIp} probed ${count} unique destination ports on target ${targetIp}.`,
            `Observed target ports: [${portsPreview}].`,
            `Activity captured within an observation window of ${feat.timeSpanSeconds} second(s).`,
            `Calculated probe frequency: ${feat.connectionFrequency.toFixed(1)} connection attempts per second.`
          ],
          indicators: [
            'Sequential or multi-port TCP connection sweep',
            `${count} unique destination ports targeted`,
            `Connection attempt frequency: ${feat.connectionFrequency.toFixed(1)} req/s`
          ],
          observedActivity: `Host ${sourceIp} dispatched connection requests across ${count} ports on ${targetIp}.`,
          detectedPattern: `Systematic multi-port discovery scan conforming to reconnaissance heuristics.`,
          securityFinding: `Potential Port Scan targeting host ${targetIp}.`,
          recommendedAction: `Recommend reviewing perimeter firewall drop tables for ${sourceIp}, validating whether host is an authorized vulnerability scanner, and isolating source if unauthorized.`,
          status: 'DISPATCHED_TO_CORRELATION',
          rawEvent: matchedEvent
        });
      }
    }

    // -------------------------------------------------------------
    // RULE B: BRUTE FORCE / REPEATED CONNECTION ATTEMPTS
    // High repetition from same source to same destination and port
    // -------------------------------------------------------------
    for (const [flowKey, flowFeat] of flowFeaturesMap.entries()) {
      if (flowFeat.connectionCount >= 5 && flowFeat.destinationPort !== undefined) {
        const port = flowFeat.destinationPort;
        const serviceName = COMMON_SERVICES[port] || `Port ${port}`;
        const isSensitivePort = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080].includes(port);

        let severity: SeverityLevel = 'LOW';
        if (flowFeat.connectionCount >= 20 || (flowFeat.connectionCount >= 10 && isSensitivePort)) {
          severity = 'HIGH';
        } else if (flowFeat.connectionCount >= 8 || isSensitivePort) {
          severity = 'MEDIUM';
        }

        const failRatio = flowFeat.connectionCount > 0 ? flowFeat.failedConnectionCount / flowFeat.connectionCount : 0;
        const baseConf = 0.68;
        const countBonus = Math.min(0.18, (flowFeat.connectionCount - 5) * 0.015);
        const failBonus = failRatio > 0.4 ? 0.08 : 0.02;
        const confidence = Number(Math.min(0.95, baseConf + countBonus + failBonus).toFixed(2));

        const primaryEventId = flowFeat.rawEventIds[0] || `NET-BF-${Date.now()}`;
        const matchedEvent = events.find(e => e.id === primaryEventId);

        results.push({
          id: `NET-RES-${results.length + 1}`,
          agentId: 'NETWORK_AGENT',
          eventId: primaryEventId,
          timestamp: flowFeat.timestamp,
          detection: flowFeat.connectionCount >= 12 ? 'Repeated Connection Attempts (High Frequency)' : 'Repeated Connection Attempts',
          threatDetected: true,
          threatType: 'REPEATED_CONNECTIONS',
          severity,
          confidence,
          classification: severity === 'HIGH' ? 'THREAT' : 'SUSPICIOUS',
          sourceIp: flowFeat.sourceIp || 'Unknown',
          destinationIp: flowFeat.destinationIp || 'Unknown',
          destinationPort: port,
          ports: [port],
          protocol: flowFeat.protocol || 'TCP',
          evidence: [
            `Source ${flowFeat.sourceIp} generated ${flowFeat.connectionCount} consecutive connection attempts to ${flowFeat.destinationIp}:${port} (${serviceName}).`,
            `Time span: ${flowFeat.timeSpanSeconds} second(s) at ${flowFeat.connectionFrequency.toFixed(1)} attempts/sec.`,
            `Failed/unacknowledged handshake count: ${flowFeat.failedConnectionCount} (${(failRatio * 100).toFixed(0)}%).`,
            `Target service: ${serviceName} (standard port ${port}).`
          ],
          indicators: [
            `Repeated connection threshold exceeded (${flowFeat.connectionCount} attempts)`,
            `Targeting authentication service: ${serviceName}`,
            `Elevated handshake failure rate: ${(failRatio * 100).toFixed(0)}%`
          ],
          observedActivity: `${flowFeat.connectionCount} connection attempts directed to ${serviceName} on ${flowFeat.destinationIp}.`,
          detectedPattern: `Repeated connection pattern matching credential guessing or service exhaustion attempt.`,
          securityFinding: `Potential Brute-Force / Repeated Connection Attempts targeting ${serviceName}.`,
          recommendedAction: `Recommend reviewing authentication logs on ${flowFeat.destinationIp} for failed logon bursts, enforcing connection rate limits, and checking for successful logins post-burst.`,
          status: 'DISPATCHED_TO_CORRELATION',
          rawEvent: matchedEvent
        });
      }
    }

    // -------------------------------------------------------------
    // RULE C: SUSPICIOUS DESTINATION PORTS / UNUSUAL TRAFFIC
    // Non-standard ports (e.g. 4444 Metasploit, 1337, 31337, 6667)
    // -------------------------------------------------------------
    for (const evt of events) {
      const single = NetworkFeatureExtractor.extractSingleEventFields(evt);
      if (single.destinationPort && SUSPICIOUS_PORT_MAP[single.destinationPort]) {
        const suspiciousInfo = SUSPICIOUS_PORT_MAP[single.destinationPort];
        const key = `SUSP-PORT-${single.sourceIp}-${single.destinationPort}`;

        if (!processedKeys.has(key)) {
          processedKeys.add(key);

          results.push({
            id: `NET-RES-${results.length + 1}`,
            agentId: 'NETWORK_AGENT',
            eventId: evt.id,
            timestamp: evt.timestamp,
            detection: `Unusual Port Activity (${suspiciousInfo.service})`,
            threatDetected: true,
            threatType: 'SUSPICIOUS_PORT',
            severity: suspiciousInfo.severity,
            confidence: 0.88,
            classification: 'THREAT',
            sourceIp: single.sourceIp || 'Unknown',
            destinationIp: single.destinationIp || 'Unknown',
            destinationPort: single.destinationPort,
            sourcePort: single.sourcePort,
            protocol: single.protocol || 'TCP',
            ports: [single.destinationPort],
            evidence: [
              `Outbound connection to destination port ${single.destinationPort} (${suspiciousInfo.service}).`,
              `Security context: ${suspiciousInfo.reason}.`,
              `Source endpoint: ${single.sourceIp || 'Internal host'}. Destination endpoint: ${single.destinationIp || 'External IP'}.`,
              `Protocol: ${single.protocol || 'TCP'}.`
            ],
            indicators: [
              `Target port ${single.destinationPort} associated with ${suspiciousInfo.service}`,
              `Non-standard service port communication`
            ],
            observedActivity: `Outbound connection attempt to port ${single.destinationPort}.`,
            detectedPattern: `Traffic directed to known backdoor or unauthorized remote listener port.`,
            securityFinding: `Suspicious Network Traffic directed to ${suspiciousInfo.service} (Port ${single.destinationPort}).`,
            recommendedAction: `Recommend verifying process associated with port ${single.destinationPort} on source host ${single.sourceIp}, capturing packet payloads, and blocking unauthorized external egress.`,
            status: 'DISPATCHED_TO_CORRELATION',
            rawEvent: evt
          });
        }
      }
    }

    // -------------------------------------------------------------
    // RULE D: NETWORK ANOMALY DETECTION (STATISTICAL OUTLIERS)
    // -------------------------------------------------------------
    for (const [sourceIp, feat] of sourceFeaturesMap.entries()) {
      // Check if we already flagged a severe port scan for this source
      const alreadyFlaggedScan = results.some(r => r.sourceIp === sourceIp && r.threatType === 'PORT_SCAN');
      if (alreadyFlaggedScan) continue;

      const anomaly = this.anomalyDetector.evaluateFlow(feat);
      if (anomaly && anomaly.isAnomaly) {
        const findingKey = `ANOMALY-${sourceIp}-${anomaly.metric}`;
        if (!processedKeys.has(findingKey)) {
          processedKeys.add(findingKey);

          const matchedEvent = events.find(e => feat.rawEventIds.includes(e.id));
          const primaryEventId = matchedEvent ? matchedEvent.id : `NET-ANOM-${Date.now()}`;

          results.push({
            id: `NET-RES-${results.length + 1}`,
            agentId: 'NETWORK_AGENT',
            eventId: primaryEventId,
            timestamp: feat.timestamp,
            detection: `Network Anomaly Detected (${anomaly.metric.replace(/_/g, ' ')})`,
            threatDetected: true,
            threatType: 'ANOMALY',
            severity: anomaly.deviationMultiplier >= 3.0 ? 'HIGH' : 'MEDIUM',
            confidence: anomaly.score,
            classification: 'SUSPICIOUS',
            sourceIp,
            destinationIp: feat.destinationIp || 'Network Subnet',
            ports: feat.destinationPortsList,
            protocol: feat.protocol || 'TCP',
            evidence: [
              anomaly.reason,
              `Observed metric value: ${anomaly.observedValue.toFixed(1)} against baseline mean ${anomaly.baselineMean}.`,
              `Statistical standard deviation multiplier: ${anomaly.deviationMultiplier}x.`,
              `Host initiated ${feat.connectionCount} events across ${feat.uniqueDestinationPorts} ports.`
            ],
            indicators: [
              `Statistical baseline deviation: ${anomaly.metric}`,
              `${anomaly.deviationMultiplier}x standard deviations from baseline`,
              `Confidence score: ${(anomaly.score * 100).toFixed(0)}%`
            ],
            observedActivity: `Host ${sourceIp} exhibited volume or frequency characteristics deviating from baseline.`,
            detectedPattern: `Statistical anomaly exceeding standard deviation thresholds.`,
            securityFinding: `Traffic Anomaly: ${anomaly.metric.replace(/_/g, ' ')}.`,
            recommendedAction: `Recommend monitoring host ${sourceIp} for unauthorized background processes, unusual automated batch transfers, or data staging.`,
            status: 'NEW',
            rawEvent: matchedEvent
          });
        }
      }
    }

    // -------------------------------------------------------------
    // RULE E: BENIGN BASELINE RECORD (False Positive Separation)
    // If no threats are found for legitimate low-volume DNS/NTP/HTTPS
    // -------------------------------------------------------------
    if (results.length === 0 && events.length > 0) {
      const firstEvt = events[0];
      const single = NetworkFeatureExtractor.extractSingleEventFields(firstEvt);
      results.push({
        id: `NET-RES-BENIGN-1`,
        agentId: 'NETWORK_AGENT',
        eventId: firstEvt.id,
        timestamp: firstEvt.timestamp,
        detection: 'Standard Network Telemetry (Baseline)',
        threatDetected: false,
        threatType: 'NONE',
        severity: 'LOW',
        confidence: 0.95,
        classification: 'BENIGN',
        sourceIp: single.sourceIp || '10.0.0.10',
        destinationIp: single.destinationIp || 'Standard Gateway',
        destinationPort: single.destinationPort || 443,
        protocol: single.protocol || 'TCP',
        evidence: [
          'Traffic patterns match expected baseline parameters.',
          'No rapid port scanning, repeated brute-force handshakes, or unauthorized port targets detected.',
          'Connection frequencies remain within standard operating limits.'
        ],
        indicators: ['Standard operating baseline', 'No signature matches', 'Low connection frequency'],
        observedActivity: 'Normal authenticated or service communication flow.',
        detectedPattern: 'Conforms to standard production network behavior.',
        securityFinding: 'No malicious network behavior detected.',
        recommendedAction: 'No defensive action necessary. Continue standard SOC baseline monitoring.',
        status: 'NEW',
        rawEvent: firstEvt
      });
    }

    return results;
  }
}
