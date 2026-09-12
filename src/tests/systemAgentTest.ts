import { LogEvent } from '../types';
import { systemAgentService } from '../services/systemAgentService';
import { SystemDetector } from '../services/systemDetector';
import { SystemFeatureExtractor } from '../services/systemFeatureExtractor';

export interface TestResult {
  scenarioName: string;
  passed: boolean;
  details: string;
}

export class SystemAgentTestSuite {
  public static runAllTests(): TestResult[] {
    const results: TestResult[] = [];

    // -------------------------------------------------------------
    // Scenario 1: Normal Login (Benign Activity)
    // -------------------------------------------------------------
    try {
      const normalEvents: LogEvent[] = [
        {
          id: 'TEST-NORM-1',
          timestamp: '2026-09-11T12:00:00.000Z',
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'sshd: Accepted publickey for alice from 10.0.1.25 port 54122 ssh2',
          normalizedFields: {
            hostName: 'web-srv-01',
            userName: 'alice',
            sourceIp: '10.0.1.25',
            processName: 'sshd'
          }
        },
        {
          id: 'TEST-NORM-2',
          timestamp: '2026-09-11T12:01:00.000Z',
          source: 'syslog',
          logType: 'SYSTEM',
          message: 'systemd: Started user session for alice',
          normalizedFields: {
            hostName: 'web-srv-01',
            userName: 'alice',
            processName: 'systemd'
          }
        }
      ];

      const detector = new SystemDetector();
      const detections = detector.analyze(normalEvents);
      const hasThreat = detections.some(d => d.threatDetected);

      results.push({
        scenarioName: 'Scenario 1: Normal Login Handling (Benign)',
        passed: !hasThreat,
        details: `Normal activity yielded ${detections.length} threat(s). Correctly classified without false positives.`
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 1: Normal Login Handling (Benign)',
        passed: false,
        details: `Exception thrown: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 2: Single Isolated Failed Login (Typo handling)
    // -------------------------------------------------------------
    try {
      const singleFailEvents: LogEvent[] = [
        {
          id: 'TEST-FAIL-1',
          timestamp: '2026-09-11T12:05:00.000Z',
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'sshd: Failed password for bob from 10.0.1.30 port 51234 ssh2',
          normalizedFields: {
            hostName: 'web-srv-01',
            userName: 'bob',
            sourceIp: '10.0.1.30',
            processName: 'sshd'
          }
        }
      ];

      const detector = new SystemDetector();
      const detections = detector.analyze(singleFailEvents);
      const isBruteForce = detections.some(d => d.threatType === 'BRUTE_FORCE');

      results.push({
        scenarioName: 'Scenario 2: Single Isolated Failed Login',
        passed: !isBruteForce,
        details: `Single failure correctly handled. No brute-force threat triggered.`
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 2: Single Isolated Failed Login',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 3: Repeated Failed Logins / Brute Force
    // -------------------------------------------------------------
    try {
      const bruteForceEvents: LogEvent[] = [];
      for (let i = 0; i < 6; i++) {
        bruteForceEvents.push({
          id: `TEST-BF-${i}`,
          timestamp: new Date(Date.now() - (6 - i) * 10000).toISOString(),
          source: 'Security.evtx',
          logType: 'SYSTEM',
          message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01',
          normalizedFields: {
            hostName: 'DC01',
            userName: 'admin',
            sourceIp: '198.51.100.22',
            processName: 'lsass.exe'
          }
        });
      }

      const detector = new SystemDetector();
      const detections = detector.analyze(bruteForceEvents);
      const bfDetection = detections.find(d => d.threatType === 'BRUTE_FORCE' || d.threatType === 'REPEATED_AUTH_FAILURES');

      results.push({
        scenarioName: 'Scenario 3: Repeated Failed Login / Brute Force Detection',
        passed: Boolean(bfDetection && bfDetection.confidence >= 0.75),
        details: bfDetection
          ? `Detected "${bfDetection.detection}" with confidence ${(bfDetection.confidence * 100).toFixed(0)}%.`
          : 'Failed to flag repeated authentication failures.'
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 3: Repeated Failed Login / Brute Force Detection',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 4: Successful Login After Repeated Failures
    // -------------------------------------------------------------
    try {
      const baseTime = Date.now() - 300000;
      const sequenceEvents: LogEvent[] = [
        {
          id: 'TEST-SEQ-1',
          timestamp: new Date(baseTime).toISOString(),
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.19 user=analyst_dave',
          normalizedFields: {
            hostName: 'app-node-02',
            userName: 'analyst_dave',
            sourceIp: '203.0.113.19',
            processName: 'sshd'
          }
        },
        {
          id: 'TEST-SEQ-2',
          timestamp: new Date(baseTime + 15000).toISOString(),
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.19 user=analyst_dave',
          normalizedFields: {
            hostName: 'app-node-02',
            userName: 'analyst_dave',
            sourceIp: '203.0.113.19',
            processName: 'sshd'
          }
        },
        {
          id: 'TEST-SEQ-3',
          timestamp: new Date(baseTime + 30000).toISOString(),
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.19 user=analyst_dave',
          normalizedFields: {
            hostName: 'app-node-02',
            userName: 'analyst_dave',
            sourceIp: '203.0.113.19',
            processName: 'sshd'
          }
        },
        {
          id: 'TEST-SEQ-4',
          timestamp: new Date(baseTime + 60000).toISOString(),
          source: 'auth.log',
          logType: 'SYSTEM',
          message: 'sshd: Accepted password for analyst_dave from 203.0.113.19 port 52102 ssh2',
          normalizedFields: {
            hostName: 'app-node-02',
            userName: 'analyst_dave',
            sourceIp: '203.0.113.19',
            processName: 'sshd'
          }
        }
      ];

      const detector = new SystemDetector();
      const detections = detector.analyze(sequenceEvents);
      const seqDetection = detections.find(d => d.threatType === 'SUSPICIOUS_AUTH_SEQUENCE');

      results.push({
        scenarioName: 'Scenario 4: Successful Login After Multiple Failures',
        passed: Boolean(seqDetection && seqDetection.confidence >= 0.8),
        details: seqDetection
          ? `Detected "${seqDetection.detection}" with confidence ${(seqDetection.confidence * 100).toFixed(0)}%. Sequence: 3 failures -> success.`
          : 'Failed to flag suspicious auth sequence.'
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 4: Successful Login After Multiple Failures',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 5: Privilege Escalation Indicator
    // -------------------------------------------------------------
    try {
      const privEscEvents: LogEvent[] = [
        {
          id: 'TEST-PRIV-1',
          timestamp: new Date().toISOString(),
          source: 'Security.evtx',
          logType: 'SYSTEM',
          message: 'Event ID 4732: A member was added to a security-enabled local group. TargetUserName: Administrators, MemberName: evil_user',
          normalizedFields: {
            hostName: 'DC01.corp.internal',
            userName: 'evil_user',
            commandLine: 'net localgroup administrators evil_user /add',
            processName: 'cmd.exe'
          }
        }
      ];

      const detector = new SystemDetector();
      const detections = detector.analyze(privEscEvents);
      const privDetection = detections.find(d => d.threatType === 'PRIVILEGE_ESCALATION');

      results.push({
        scenarioName: 'Scenario 5: Privilege Escalation Indicator Detection',
        passed: Boolean(privDetection && (privDetection.severity === 'HIGH' || privDetection.severity === 'CRITICAL')),
        details: privDetection
          ? `Detected "${privDetection.detection}" (${privDetection.severity} severity, confidence: ${(privDetection.confidence * 100).toFixed(0)}%).`
          : 'Failed to detect privilege escalation attempt.'
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 5: Privilege Escalation Indicator Detection',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 6: Suspicious Process Activity (Mimikatz / Encoded PS)
    // -------------------------------------------------------------
    try {
      const procEvents: LogEvent[] = [
        {
          id: 'TEST-PROC-1',
          timestamp: new Date().toISOString(),
          source: 'Sysmon.evtx',
          logType: 'SYSTEM',
          message: 'Event ID 1: Process Creation. Image: C:\\Temp\\mimikatz.exe, CommandLine: mimikatz.exe privilege::debug sekurlsa::logonpasswords',
          normalizedFields: {
            hostName: 'WS-01',
            userName: 'attacker',
            processName: 'mimikatz.exe',
            commandLine: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords'
          }
        }
      ];

      const detector = new SystemDetector();
      const detections = detector.analyze(procEvents);
      const procDetection = detections.find(d => d.threatType === 'SUSPICIOUS_PROCESS');

      results.push({
        scenarioName: 'Scenario 6: Suspicious Process Activity (Credential Dumping)',
        passed: Boolean(procDetection && procDetection.confidence >= 0.9),
        details: procDetection
          ? `Detected "${procDetection.detection}" with confidence ${(procDetection.confidence * 100).toFixed(0)}%.`
          : 'Failed to detect suspicious process execution.'
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 6: Suspicious Process Activity (Credential Dumping)',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    // -------------------------------------------------------------
    // Scenario 7: Unusual Host Activity (High Failure Concentration)
    // -------------------------------------------------------------
    try {
      const hostAnomEvents: LogEvent[] = [];
      for (let i = 0; i < 10; i++) {
        hostAnomEvents.push({
          id: `TEST-HOST-ANOM-${i}`,
          timestamp: new Date(Date.now() - (10 - i) * 5000).toISOString(),
          source: 'auth.log',
          logType: 'SYSTEM',
          message: `pam_unix: authentication failure for testuser_${i} from 10.0.0.99`,
          normalizedFields: {
            hostName: 'compromised-gateway-01',
            userName: `testuser_${i}`,
            sourceIp: '10.0.0.99',
            processName: 'sshd'
          }
        });
      }

      const detector = new SystemDetector();
      const detections = detector.analyze(hostAnomEvents);
      const hostDetection = detections.find(d => d.threatType === 'UNUSUAL_HOST_ACTIVITY');

      results.push({
        scenarioName: 'Scenario 7: Unusual Host Activity (Statistical Anomaly)',
        passed: Boolean(hostDetection),
        details: hostDetection
          ? `Detected "${hostDetection.detection}" with confidence ${(hostDetection.confidence * 100).toFixed(0)}%.`
          : 'Failed to detect host anomaly.'
      });
    } catch (err: unknown) {
      results.push({
        scenarioName: 'Scenario 7: Unusual Host Activity (Statistical Anomaly)',
        passed: false,
        details: `Exception: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    return results;
  }
}
