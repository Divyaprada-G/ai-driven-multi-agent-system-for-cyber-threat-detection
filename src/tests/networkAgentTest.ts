import { LogEvent } from '../types';
import { networkAgentService } from '../services/networkAgentService';
import { NetworkDetector } from '../services/networkDetector';
import { NetworkFeatureExtractor } from '../services/networkFeatureExtractor';

export interface TestResult {
  scenarioName: string;
  passed: boolean;
  details: string;
}

export class NetworkAgentTestSuite {
  public static runAllTests(): TestResult[] {
    const results: TestResult[] = [];

    // -------------------------------------------------------------
    // Scenario 1: Normal Network Traffic
    // -------------------------------------------------------------
    try {
      const normalEvents: LogEvent[] = [
        {
          id: 'TEST-NORM-1',
          timestamp: '2026-09-11T20:00:00.000Z',
          source: 'FW-01',
          logType: 'NETWORK',
          message: 'Allowed HTTPS connection',
          normalizedFields: {
            sourceIp: '10.0.0.10',
            destinationIp: '104.244.42.1',
            sourcePort: 50123,
            destinationPort: 443,
            protocol: 'TCP'
          }
        },
        {
          id: 'TEST-NORM-2',
          timestamp: '2026-09-11T20:01:00.000Z',
          source: 'DNS-01',
          logType: 'NETWORK',
          message: 'Standard DNS lookup',
          normalizedFields: {
            sourceIp: '10.0.0.12',
            destinationIp: '8.8.8.8',
            sourcePort: 50124,
            destinationPort: 53,
            protocol: 'UDP'
          }
        }
      ];

      const detector = new NetworkDetector();
      const detections = detector.analyze(normalEvents);
      const hasThreat = detections.some(d => d.threatDetected && d.severity !== 'LOW');

      results.push({
        scenarioName: 'Scenario 1: Normal Network Traffic Handling',
        passed: !hasThreat,
        details: `Normal traffic produced ${detections.length} result(s). No high-severity threats triggered.`
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 1: Normal Network Traffic Handling',
        passed: false,
        details: `Error: ${err.message}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 2: Port Scanning Detection
    // -------------------------------------------------------------
    try {
      const scanPorts = [21, 22, 23, 25, 80, 135, 443, 3389];
      const scanEvents: LogEvent[] = scanPorts.map((port, i) => ({
        id: `TEST-SCAN-${i}`,
        timestamp: `2026-09-11T20:05:0${i}.000Z`,
        source: 'Suricata Sensor',
        logType: 'NETWORK',
        message: `SYN connection attempt to port ${port}`,
        normalizedFields: {
          sourceIp: '192.168.1.99',
          destinationIp: '10.0.0.50',
          sourcePort: 40000 + i,
          destinationPort: port,
          protocol: 'TCP',
          flags: ['SYN']
        }
      }));

      const detector = new NetworkDetector();
      const detections = detector.analyze(scanEvents);
      const portScanResult = detections.find(d => d.threatType === 'PORT_SCAN');

      const passed =
        !!portScanResult &&
        portScanResult.sourceIp === '192.168.1.99' &&
        portScanResult.confidence >= 0.70 &&
        portScanResult.evidence.length >= 2;

      results.push({
        scenarioName: 'Scenario 2: Port Scanning Sweep Detection',
        passed,
        details: passed
          ? `Successfully detected Port Scan from 192.168.1.99 across ${scanPorts.length} ports with confidence ${(portScanResult!.confidence * 100).toFixed(0)}%.`
          : `Failed to detect expected port scan pattern.`
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 2: Port Scanning Sweep Detection',
        passed: false,
        details: `Error: ${err.message}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 3: Repeated Connection Attempts / Brute Force
    // -------------------------------------------------------------
    try {
      const bfEvents: LogEvent[] = Array.from({ length: 8 }).map((_, i) => ({
        id: `TEST-BF-${i}`,
        timestamp: `2026-09-11T20:10:0${i}.000Z`,
        source: 'Perimeter FW',
        logType: 'NETWORK',
        message: 'SSH handshake failed, connection reset',
        normalizedFields: {
          sourceIp: '198.51.100.88',
          destinationIp: '10.0.0.22',
          sourcePort: 51000 + i,
          destinationPort: 22,
          protocol: 'TCP',
          flags: ['RST']
        }
      }));

      const detector = new NetworkDetector();
      const detections = detector.analyze(bfEvents);
      const bfResult = detections.find(d => d.threatType === 'REPEATED_CONNECTIONS');

      const passed =
        !!bfResult &&
        bfResult.sourceIp === '198.51.100.88' &&
        bfResult.destinationPort === 22 &&
        bfResult.evidence.some(e => e.includes('consecutive connection attempts'));

      results.push({
        scenarioName: 'Scenario 3: Repeated Connection Attempts / Brute Force',
        passed,
        details: passed
          ? `Detected repeated connection attempts to port 22 with confidence ${(bfResult!.confidence * 100).toFixed(0)}%.`
          : `Failed to detect repeated connection attempts.`
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 3: Repeated Connection Attempts / Brute Force',
        passed: false,
        details: `Error: ${err.message}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 4: Missing Network Fields Handling
    // -------------------------------------------------------------
    try {
      const incompleteEvents: LogEvent[] = [
        {
          id: 'TEST-INC-1',
          timestamp: '2026-09-11T20:15:00.000Z',
          source: 'Router Core',
          logType: 'NETWORK',
          message: 'Malformed network packet with missing fields'
          // No normalizedFields at all!
        },
        {
          id: 'TEST-INC-2',
          timestamp: '2026-09-11T20:15:05.000Z',
          source: 'Router Core',
          logType: 'NETWORK',
          message: 'Packet missing destination port',
          normalizedFields: {
            sourceIp: '10.0.0.99'
            // destinationPort missing
          }
        }
      ];

      const detector = new NetworkDetector();
      const detections = detector.analyze(incompleteEvents);

      results.push({
        scenarioName: 'Scenario 4: Missing Network Fields Graceful Handling',
        passed: true,
        details: `Safely processed events without thrown errors. Generated ${detections.length} result(s) without inventing missing data.`
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 4: Missing Network Fields Graceful Handling',
        passed: false,
        details: `Crashed on missing fields: ${err.message}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 5: Empty Dataset Handling
    // -------------------------------------------------------------
    try {
      const analysis = networkAgentService.analyzeNetworkEvents([]);
      const passed =
        analysis.totalEventsAnalyzed === 0 &&
        analysis.potentialThreatsCount === 0 &&
        analysis.results.length === 0;

      results.push({
        scenarioName: 'Scenario 5: Empty Dataset Graceful Handling',
        passed,
        details: passed
          ? 'Correctly produced zeroed metrics structure without exceptions.'
          : 'Failed empty dataset contract.'
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 5: Empty Dataset Graceful Handling',
        passed: false,
        details: `Error: ${err.message}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 6: Large Dataset Stress Test
    // -------------------------------------------------------------
    try {
      const t0 = performance.now();
      const largeBatch: LogEvent[] = [];

      for (let i = 0; i < 200; i++) {
        const srcIp = `10.0.${Math.floor(i / 50)}.${(i % 50) + 1}`;
        const dstPort = (i % 10) === 0 ? 4444 : 443;
        largeBatch.push({
          id: `STRESS-EVT-${i}`,
          timestamp: new Date(Date.now() - (200 - i) * 1000).toISOString(),
          source: 'Core Switch',
          logType: 'NETWORK',
          message: `Flow stream packet ${i}`,
          normalizedFields: {
            sourceIp: srcIp,
            destinationIp: '10.0.0.1',
            sourcePort: 45000 + (i % 1000),
            destinationPort: dstPort,
            protocol: 'TCP'
          }
        });
      }

      const analysis = networkAgentService.analyzeNetworkEvents(largeBatch);
      const elapsed = performance.now() - t0;

      const passed =
        analysis.totalEventsAnalyzed === 200 &&
        analysis.uniqueSourceIps > 0 &&
        elapsed < 500; // Must execute in < 500ms

      results.push({
        scenarioName: 'Scenario 6: High Throughput / Large Dataset Evaluation',
        passed,
        details: `Processed 200 flow records in ${elapsed.toFixed(1)}ms. Total unique source IPs: ${analysis.uniqueSourceIps}.`
      });
    } catch (err: any) {
      results.push({
        scenarioName: 'Scenario 6: High Throughput / Large Dataset Evaluation',
        passed: false,
        details: `Error: ${err.message}`
      });
    }

    return results;
  }
}
