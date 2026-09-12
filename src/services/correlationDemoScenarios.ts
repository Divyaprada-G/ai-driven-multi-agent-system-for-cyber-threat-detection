import { CorrelationDemoScenario } from '../types/correlation';

/**
 * 4 Canonical Academic Testing & Demo Scenarios
 * Grounded in explicit simulation data for consistent demonstration.
 */
export const CORRELATION_DEMO_SCENARIOS: Record<string, CorrelationDemoScenario> = {
  DEMO_1: {
    id: 'DEMO_1',
    name: 'DEMO 1: Cross-Agent Correlated Intrusion (Triad)',
    description: 'Network Port Scan + System Repeated Login Failures + Application Suspicious Web Request sharing Source IP 192.168.1.105',
    expectedOutcome: 'Cross-Agent Correlated Activity (Potential Multi-Stage Intrusion Sequence)',
    findings: [
      {
        id: 'find-demo1-net-01',
        agentId: 'NETWORK_AGENT',
        eventId: 'EVT-9042',
        timestamp: '2026-09-11 22:50:15',
        source: '192.168.1.105 (DMZ Gateway)',
        sourceIp: '192.168.1.105',
        destinationIp: '10.0.0.5',
        host: 'perimeter-dmz-gw',
        eventType: 'Potential Port Scan',
        threatType: 'Port Scan / Reconnaissance',
        severity: 'HIGH',
        confidence: 0.92,
        evidence: [
          'Rapid SYN sweep across 48 target ports within 450ms',
          'T1046 Network Service Scanning signature ET SCAN'
        ],
        indicators: ['192.168.1.105', 'TCP SYN Sweep', 'Port 443/80/22'],
        classification: 'THREAT',
        metadata: {
          observedActivity: 'Inbound reconnaissance port sweep across web and management ports',
          detectedPattern: 'Automated nmap/masscan fingerprint signature'
        }
      },
      {
        id: 'find-demo1-sys-02',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-9041',
        timestamp: '2026-09-11 22:50:48',
        source: 'workstation-fin-04',
        sourceIp: '192.168.1.105',
        host: 'workstation-fin-04',
        username: 'admin_dev',
        eventType: 'Repeated Authentication Failures',
        threatType: 'Brute Force / Credential Abuse',
        severity: 'HIGH',
        confidence: 0.88,
        evidence: [
          '18 consecutive PAM authentication failures for account "admin_dev" in 30 seconds',
          'Originating IP matches inbound scanner 192.168.1.105'
        ],
        indicators: ['admin_dev', '192.168.1.105', 'PAM Auth Burst'],
        classification: 'THREAT',
        metadata: {
          observedActivity: 'Repeated SSH login rejections under rapid dictionary timing',
          detectedPattern: 'Hydra SSH brute-force credential stuffing'
        }
      },
      {
        id: 'find-demo1-app-03',
        agentId: 'APPLICATION_AGENT',
        eventId: 'EVT-9040',
        timestamp: '2026-09-11 22:51:30',
        source: 'api.corp.internal/v2/checkout',
        sourceIp: '192.168.1.105',
        host: 'workstation-fin-04',
        username: 'admin_dev',
        eventType: 'Suspicious Web Request',
        threatType: 'SQL Injection / Web Exploit',
        severity: 'HIGH',
        confidence: 0.94,
        evidence: [
          'GET /api/v2/checkout with payload parameter "UNION SELECT null, password FROM users"',
          'HTTP 403 Forbidden generated following automated payload delivery'
        ],
        indicators: ['192.168.1.105', 'UNION SELECT', '/api/v2/checkout'],
        classification: 'THREAT',
        metadata: {
          observedActivity: 'Nested database enumeration payload in HTTP query string',
          detectedPattern: 'sqlmap automated exploit payload injection'
        }
      }
    ]
  },

  DEMO_2: {
    id: 'DEMO_2',
    name: 'DEMO 2: Suspicious Authentication & Privilege Sequence',
    description: 'System Agent observing: Failed Login -> Failed Login -> Successful Login -> Privilege Escalation on Host workstation-fin-04',
    expectedOutcome: 'Suspicious Authentication and Privilege Sequence',
    findings: [
      {
        id: 'find-demo2-sys-01',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-8801',
        timestamp: '2026-09-11 22:40:02',
        source: 'workstation-fin-04',
        host: 'workstation-fin-04',
        username: 'svc_backup',
        eventType: 'Failed Login Attempt',
        threatType: 'Authentication Failure',
        severity: 'LOW',
        confidence: 0.80,
        evidence: ['pam_unix auth failure: invalid password for svc_backup'],
        indicators: ['svc_backup', 'workstation-fin-04'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo2-sys-02',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-8802',
        timestamp: '2026-09-11 22:40:24',
        source: 'workstation-fin-04',
        host: 'workstation-fin-04',
        username: 'svc_backup',
        eventType: 'Failed Login Attempt',
        threatType: 'Authentication Failure',
        severity: 'MEDIUM',
        confidence: 0.85,
        evidence: ['pam_unix auth failure: second retry failed for svc_backup'],
        indicators: ['svc_backup', 'workstation-fin-04'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo2-sys-03',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-8803',
        timestamp: '2026-09-11 22:40:55',
        source: 'workstation-fin-04',
        host: 'workstation-fin-04',
        username: 'svc_backup',
        eventType: 'Successful Login',
        threatType: 'Suspicious Logon',
        severity: 'MEDIUM',
        confidence: 0.78,
        evidence: ['Interactive session 482 opened for svc_backup following failed attempts'],
        indicators: ['svc_backup', 'workstation-fin-04', 'Interactive Session'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo2-sys-04',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-8804',
        timestamp: '2026-09-11 22:41:40',
        source: 'workstation-fin-04',
        host: 'workstation-fin-04',
        username: 'svc_backup',
        eventType: 'Privilege Escalation Attempt',
        threatType: 'Privilege Escalation',
        severity: 'CRITICAL',
        confidence: 0.95,
        evidence: [
          'SeImpersonatePrivilege abused via spoolsv token duplication (T1068)',
          'Process spawned cmd.exe with NT AUTHORITY\\SYSTEM integrity'
        ],
        indicators: ['svc_backup', 'workstation-fin-04', 'SeImpersonatePrivilege', 'T1068'],
        classification: 'THREAT'
      }
    ]
  },

  DEMO_3: {
    id: 'DEMO_3',
    name: 'DEMO 3: Potential Coordinated Activity (Web & Network)',
    description: 'Application Agent high request frequencyburst + Network Agent abnormal ingress volume targeting api-cluster-01',
    expectedOutcome: 'Potential Coordinated Activity',
    findings: [
      {
        id: 'find-demo3-app-01',
        agentId: 'APPLICATION_AGENT',
        eventId: 'EVT-7701',
        timestamp: '2026-09-11 22:30:10',
        source: 'api.gateway.internal',
        sourceIp: '198.51.100.42',
        host: 'api-cluster-01',
        eventType: 'High Request Frequency',
        threatType: 'Rate Limit Exhaustion / API Scrape',
        severity: 'MEDIUM',
        confidence: 0.86,
        evidence: [
          '340 HTTP requests delivered within 12 seconds from single client IP',
          'Persistent HTTP 429 Too Many Requests responses generated'
        ],
        indicators: ['198.51.100.42', 'HTTP 429 Burst', 'API Cluster'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo3-net-02',
        agentId: 'NETWORK_AGENT',
        eventId: 'EVT-7702',
        timestamp: '2026-09-11 22:30:45',
        source: 'edge-border-router',
        sourceIp: '198.51.100.42',
        destinationIp: '10.200.5.1',
        host: 'api-cluster-01',
        eventType: 'Abnormal Network Traffic',
        threatType: 'Traffic Anomaly / Ingress Flood',
        severity: 'HIGH',
        confidence: 0.89,
        evidence: [
          'Ingress connection rate exceeded baseline threshold by 420%',
          'Asymmetric TCP SYN flow without payload completion'
        ],
        indicators: ['198.51.100.42', '10.200.5.1', 'Ingress SYN Spike'],
        classification: 'THREAT'
      }
    ]
  },

  DEMO_4: {
    id: 'DEMO_4',
    name: 'DEMO 4: Unrelated Security Events (No Correlation)',
    description: 'Three unrelated events occurring at different times, from different source IPs, on different hosts and accounts',
    expectedOutcome: 'No correlation (Events remain separate to prevent false positives)',
    findings: [
      {
        id: 'find-demo4-net-01',
        agentId: 'NETWORK_AGENT',
        eventId: 'EVT-6601',
        timestamp: '2026-09-11 18:12:00',
        source: '172.16.50.4',
        sourceIp: '172.16.50.4',
        host: 'branch-office-router',
        eventType: 'DNS Lookup Failure',
        threatType: 'Network Anomaly',
        severity: 'LOW',
        confidence: 0.55,
        evidence: ['Single isolated NXDOMAIN lookup for typo domain'],
        indicators: ['172.16.50.4'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo4-sys-02',
        agentId: 'SYSTEM_AGENT',
        eventId: 'EVT-6602',
        timestamp: '2026-09-11 20:45:30',
        source: 'print-server-02',
        host: 'print-server-02',
        username: 'john_doe',
        eventType: 'Single Bad Password',
        threatType: 'Authentication Failure',
        severity: 'LOW',
        confidence: 0.40,
        evidence: ['Normal user mistyped credentials once before successful logon'],
        indicators: ['john_doe', 'print-server-02'],
        classification: 'SUSPICIOUS'
      },
      {
        id: 'find-demo4-app-03',
        agentId: 'APPLICATION_AGENT',
        eventId: 'EVT-6603',
        timestamp: '2026-09-11 22:59:10',
        source: 'cdn-cache-west',
        sourceIp: '203.0.113.88',
        host: 'cdn-proxy-node',
        username: 'guest_shopper',
        eventType: 'Invalid HTTP Header Format',
        threatType: 'Web Request Anomaly',
        severity: 'LOW',
        confidence: 0.45,
        evidence: ['Malformed Accept-Language header rejected by nginx'],
        indicators: ['203.0.113.88'],
        classification: 'SUSPICIOUS'
      }
    ]
  }
};
