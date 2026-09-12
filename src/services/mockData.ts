import {
  AgentStatusInfo,
  CorrelatedEvent,
  DashboardMetrics,
  Incident,
  LogEvent,
  LogFileRecord,
  RiskAssessment,
  SecurityAlert,
  ThreatDetectionResult,
  TimeSeriesPoint,
  SeverityDistributionPoint,
  SourceDistributionPoint,
  AgentActivityPoint,
  ThreatCategoryPoint
} from '../types';

export const INITIAL_METRICS: DashboardMetrics = {
  totalEvents: 428950,
  suspiciousEvents: 1428,
  activeThreats: 37,
  criticalIncidents: 4,
  networkEvents: 248100,
  systemEvents: 119420,
  applicationEvents: 61430,
  lastUpdated: new Date().toISOString()
};

export const INITIAL_AGENTS: AgentStatusInfo[] = [
  {
    agentId: 'NETWORK_AGENT',
    name: 'Network Agent',
    status: 'READY',
    eventsProcessed: 248100,
    threatsDetected: 19,
    lastActivity: '3 seconds ago',
    detectionConfidence: 96.4,
    description: 'Deep packet inspection, anomalous traffic flow detection, port scan heuristics, and C2 beacon recognition.',
    activeRulesCount: 142,
    uptime: '99.98%'
  },
  {
    agentId: 'SYSTEM_AGENT',
    name: 'System Agent',
    status: 'READY',
    eventsProcessed: 119420,
    threatsDetected: 11,
    lastActivity: '12 seconds ago',
    detectionConfidence: 94.2,
    description: 'Host telemetry, privilege escalation signatures, unquoted service path execution, and process memory injection analysis.',
    activeRulesCount: 98,
    uptime: '99.95%'
  },
  {
    agentId: 'APPLICATION_AGENT',
    name: 'Application Agent',
    status: 'READY',
    eventsProcessed: 61430,
    threatsDetected: 7,
    lastActivity: '45 seconds ago',
    detectionConfidence: 91.8,
    description: 'OWASP Top 10 telemetry, SQL injection parsing, cross-site scripting detection, and auth API brute-force monitoring.',
    activeRulesCount: 76,
    uptime: '99.99%'
  }
];

export const INITIAL_RECENT_EVENTS = [
  {
    id: 'EVT-9042',
    timestamp: '2026-09-11 22:58:14',
    source: '192.168.1.105 (VLAN-DMZ)',
    agent: 'Network Agent',
    eventType: 'Port Scan Detected',
    severity: 'HIGH' as const,
    riskScore: 82,
    status: 'Flagged',
    action: 'Simulated Ingress Block',
    detail: 'Syn flood / sequential TCP port scan targeting ports 22, 80, 443, 3389, 8080 from single MAC within 450ms window.'
  },
  {
    id: 'EVT-9041',
    timestamp: '2026-09-11 22:55:02',
    source: 'auth-gateway-srv-02',
    agent: 'Application Agent',
    eventType: 'Multiple Failed Login Attempts',
    severity: 'MEDIUM' as const,
    riskScore: 68,
    status: 'Investigating',
    action: 'MFA Step-up Enforced',
    detail: '48 authentication failures against user identity "admin_dev" across 3 rotating proxy IP headers.'
  },
  {
    id: 'EVT-9040',
    timestamp: '2026-09-11 22:51:30',
    source: 'api.corp.internal/v2/checkout',
    agent: 'Application Agent',
    eventType: 'Suspicious Web Request',
    severity: 'HIGH' as const,
    riskScore: 88,
    status: 'Flagged',
    action: 'WAF Rule Queued',
    detail: 'Nested SQL injection vector identified in header X-Forwarded-Host with stacked query union select payloads.'
  },
  {
    id: 'EVT-9039',
    timestamp: '2026-09-11 22:47:19',
    source: 'workstation-fin-04',
    agent: 'System Agent',
    eventType: 'Privilege Escalation Attempt',
    severity: 'CRITICAL' as const,
    riskScore: 96,
    status: 'Correlating',
    action: 'Host Quarantine Recommended',
    detail: 'Token impersonation attempted by non-privileged service account via SeImpersonatePrivilege spoolsv.exe exploit.'
  },
  {
    id: 'EVT-9038',
    timestamp: '2026-09-11 22:42:05',
    source: '10.240.12.88 (Core Router)',
    agent: 'Network Agent',
    eventType: 'Abnormal Network Traffic',
    severity: 'MEDIUM' as const,
    riskScore: 64,
    status: 'Monitoring',
    action: 'NetFlow Sampling Increased',
    detail: 'Unusual outbound DNS tunneling pattern transmitting 14MB base64 encoded chunks to unregistered .xyz domain.'
  },
  {
    id: 'EVT-9037',
    timestamp: '2026-09-11 22:36:51',
    source: 'vpn-concentrator-east',
    agent: 'System Agent',
    eventType: 'Possible Brute Force Activity',
    severity: 'HIGH' as const,
    riskScore: 84,
    status: 'Flagged',
    action: 'Geo-Rate Limiter Applied',
    detail: 'Over 210 credential spraying attempts on IKEv2 handshake using leaked credential dump signatures.'
  }
];

export const INITIAL_LOG_FILES: LogFileRecord[] = [
  {
    id: 'FILE-101',
    filename: 'suricata_eve_network_20260911.json',
    logType: 'NETWORK',
    fileSize: '48.6 MB',
    uploadTime: '2026-09-11 21:30:12',
    processingStatus: 'COMPLETED',
    numberOfEvents: 184500,
    parsedPreview: [
      '{"timestamp":"2026-09-11T21:29:45.102Z","event_type":"alert","src_ip":"192.168.1.105","dest_ip":"10.0.0.5","alert":{"signature":"ET SCAN Potential SSH Scan"}}',
      '{"timestamp":"2026-09-11T21:29:48.441Z","event_type":"flow","src_ip":"10.0.0.5","dest_ip":"104.244.42.1","proto":"TCP","app_proto":"tls"}'
    ]
  },
  {
    id: 'FILE-102',
    filename: 'wazuh_host_syslog_auth.log',
    logType: 'SYSTEM',
    fileSize: '18.2 MB',
    uploadTime: '2026-09-11 22:04:45',
    processingStatus: 'COMPLETED',
    numberOfEvents: 94200,
    parsedPreview: [
      'Sep 11 22:04:12 workstation-fin-04 sudo: pam_unix(sudo:auth): authentication failure; logname=uid=1000',
      'Sep 11 22:04:20 workstation-fin-04 auditd[1420]: USER_CMD pid=4120 cmd="sudo su - root" res=failed'
    ]
  },
  {
    id: 'FILE-103',
    filename: 'nginx_access_web_api.log',
    logType: 'APPLICATION',
    fileSize: '12.4 MB',
    uploadTime: '2026-09-11 22:20:00',
    processingStatus: 'COMPLETED',
    numberOfEvents: 52100,
    parsedPreview: [
      '192.168.1.105 - - [11/Sep/2026:22:19:58 +0000] "GET /api/v2/checkout?id=1%20UNION%20SELECT%20null,password%20FROM%20users HTTP/1.1" 403 521',
      '10.240.12.88 - - [11/Sep/2026:22:20:01 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128'
    ]
  }
];

export const INITIAL_CORRELATIONS: CorrelatedEvent[] = [
  {
    id: 'CORR-2026-081',
    correlationId: 'CORR-2026-081',
    timestamp: '2026-09-11 22:58:30',
    createdAt: '2026-09-11 22:58:30',
    startTime: '2026-09-11 22:50:15',
    endTime: '2026-09-11 22:51:30',
    duration: '1m 15s',
    findingIds: ['find-081-1', 'find-081-2', 'find-081-3'],
    eventIds: ['EVT-9042', 'EVT-9040', 'EVT-9039'],
    eventsCount: 3,
    participatingAgents: ['NETWORK_AGENT', 'APPLICATION_AGENT', 'SYSTEM_AGENT'],
    sources: ['192.168.1.105', 'api.corp.internal', 'workstation-fin-04'],
    sourceIps: ['192.168.1.105'],
    destinationIps: ['10.0.0.5'],
    hosts: ['workstation-fin-04'],
    users: ['admin_dev'],
    eventTypes: ['Port Scan', 'SQL Injection', 'Privilege Escalation'],
    threatTypes: ['Reconnaissance', 'Web Exploit', 'Privilege Escalation'],
    correlationStrength: 'HIGH',
    correlationConfidence: 0.94,
    confidence: 94,
    severity: 'CRITICAL',
    title: 'Potential Multi-Stage Intrusion Sequence',
    attackPattern: 'Multi-Stage Infiltration & Lateral Elevation (T1046 -> T1190 -> T1068)',
    summary: 'Ingress reconnaissance scan correlated directly with an exploitation payload on the web API and subsequent privileged escalation token tampering on the internal finance host.',
    description: 'Ingress reconnaissance scan correlated directly with an exploitation payload on the web API and subsequent privileged escalation token tampering on the internal finance host.',
    evidence: ['SYN sweep across 48 target ports', 'UNION SELECT payload', 'SeImpersonate token duplication'],
    indicators: ['192.168.1.105', 'UNION SELECT', 'spoolsv.exe'],
    explanation: '1. Shared Source IP 192.168.1.105.\n2. Multi-domain cross-agent findings.\n3. Chronological progression from scan to exploit to privilege escalation.',
    status: 'ESCALATED',
    mitreTechniqueId: 'T1068 / T1190',
    agentContributions: {
      network: 'Identified reconnaissance port scan originating from target subnet.',
      application: 'Intercepted SQL injection payload aiming at API metadata enumeration.',
      system: 'Detected execution of token elevation script immediately following HTTP exploit.'
    }
  },
  {
    id: 'CORR-2026-080',
    correlationId: 'CORR-2026-080',
    timestamp: '2026-09-11 22:45:10',
    createdAt: '2026-09-11 22:45:10',
    startTime: '2026-09-11 22:43:00',
    endTime: '2026-09-11 22:45:10',
    duration: '2m 10s',
    findingIds: ['find-080-1', 'find-080-2'],
    eventIds: ['EVT-9041', 'EVT-9037'],
    eventsCount: 2,
    participatingAgents: ['NETWORK_AGENT', 'APPLICATION_AGENT'],
    sources: ['auth-gateway-srv-02', 'vpn-concentrator-east'],
    sourceIps: ['198.51.100.42'],
    destinationIps: ['10.200.5.1'],
    hosts: ['auth-gateway-srv-02'],
    users: ['dev_user'],
    eventTypes: ['Burst Traffic', 'Auth Rejections'],
    threatTypes: ['Traffic Anomaly', 'Credential Stuffing'],
    correlationStrength: 'MEDIUM',
    correlationConfidence: 0.89,
    confidence: 89,
    severity: 'HIGH',
    title: 'Potential Web-to-Account Attack Sequence',
    attackPattern: 'Distributed Credential Stuffing & VPN Pivoting (T1110.003)',
    summary: 'Synchronized credential brute-force observed simultaneously on single-sign-on web identity service and enterprise perimeter VPN.',
    description: 'Synchronized credential brute-force observed simultaneously on single-sign-on web identity service and enterprise perimeter VPN.',
    evidence: ['48 repeated auth rejections', 'UDP burst traffic on VPN'],
    indicators: ['auth-gateway-srv-02', '198.51.100.42'],
    explanation: '1. Shared target authentication gateway.\n2. Coinciding network traffic burst and application auth failures.',
    status: 'CORRELATED',
    mitreTechniqueId: 'T1110',
    agentContributions: {
      network: 'Correlated anomalous burst traffic across VPN UDP handshakes.',
      application: 'Flagged 48 repeated auth rejections across high-privilege usernames.'
    }
  },
  {
    id: 'CORR-2026-079',
    correlationId: 'CORR-2026-079',
    timestamp: '2026-09-11 21:50:22',
    createdAt: '2026-09-11 21:50:22',
    startTime: '2026-09-11 21:48:00',
    endTime: '2026-09-11 21:50:22',
    duration: '2m 22s',
    findingIds: ['find-079-1'],
    eventIds: ['EVT-9038'],
    eventsCount: 1,
    participatingAgents: ['NETWORK_AGENT'],
    sources: ['10.240.12.88'],
    sourceIps: ['10.240.12.88'],
    destinationIps: ['8.8.8.8'],
    hosts: ['dns-cache-01'],
    users: [],
    eventTypes: ['High Entropy DNS'],
    threatTypes: ['Data Exfiltration'],
    correlationStrength: 'LOW',
    correlationConfidence: 0.86,
    confidence: 86,
    severity: 'MEDIUM',
    title: 'Potential Encrypted DNS Tunneling',
    attackPattern: 'Data Exfiltration via Encrypted DNS Tunneling (T1071.004)',
    summary: 'Repetitive high-frequency TXT record lookups with high Shannon entropy payload indicating active staging or data beaconing.',
    description: 'Repetitive high-frequency TXT record lookups with high Shannon entropy payload indicating active staging or data beaconing.',
    evidence: ['Shannon entropy > 4.5 in DNS labels', 'Regular beacon intervals'],
    indicators: ['10.240.12.88', 'TXT records'],
    explanation: 'Repetitive DNS TXT record lookups with high entropy.',
    status: 'PENDING',
    mitreTechniqueId: 'T1071.004',
    agentContributions: {
      network: 'Detected beacon interval regularity and high-entropy DNS subdomain labels.'
    }
  }
];

export const INITIAL_THREAT_DETECTIONS: ThreatDetectionResult[] = [
  {
    id: 'TD-401',
    correlationId: 'CORR-2026-077',
    timestamp: '2026-09-11 22:58:30',
    threatDetected: true,
    threatType: 'Privilege Escalation via Service Exploitation',
    category: 'Privilege Escalation',
    classification: 'PRIVILEGE_ESCALATION',
    confidence: 0.962,
    confidenceType: 'DEMO_DERIVED',
    anomalyScore: 0.94,
    anomalyScoreLabel: 'DEMO ANOMALY SCORE',
    model: 'Rule-Based Demo Engine (Heuristic Simulator)',
    modelType: 'RULE_BASED_DEMO',
    modelStatus: 'DEMO',
    severity: 'CRITICAL',
    status: 'DETECTED',
    evidence: [
      'Unusual token impersonation by SYSTEM thread',
      'Execution of non-standard binary from C:\\Windows\\Temp',
      'Correlated parent process was w3wp.exe web service'
    ],
    features: {
      findingCount: 3,
      participatingAgentsCount: 3,
      correlationConfidence: 0.94,
      correlationStrengthScore: 3,
      eventDurationSeconds: 150,
      uniqueSourceIpsCount: 1,
      uniqueDestIpsCount: 1,
      affectedHostsCount: 1,
      affectedUsersCount: 1,
      threatTypesCount: 3,
      suspiciousEventsCount: 1,
      highSeverityCount: 1,
      criticalSeverityCount: 1,
      networkInvolvement: 1,
      systemInvolvement: 1,
      applicationInvolvement: 1,
      sequenceLength: 3,
      timeSpanSeconds: 150
    },
    explanation: {
      whyAnalyzed: 'Correlated event sequence spanned Network ingress, Web API exploit, and System token elevation.',
      contributingFeatures: [
        { feature: 'Participating Agents', value: '3 Agents', impact: 'HIGH' },
        { feature: 'Critical Severity Findings', value: 1, impact: 'HIGH' }
      ],
      participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'],
      supportingEvidence: [
        'Unusual token impersonation by SYSTEM thread',
        'Execution of non-standard binary from C:\\Windows\\Temp'
      ],
      recommendedAction: 'Isolate host workstation-fin-04 and terminate spoolsv child process.'
    },
    recommendedAction: 'Isolate host workstation-fin-04 and terminate spoolsv child process.',
    baselineDeviation: 4.8,
    predictedImpact: 'CATASTROPHIC'
  },
  {
    id: 'TD-402',
    correlationId: 'CORR-2026-078',
    timestamp: '2026-09-11 22:51:30',
    threatDetected: true,
    threatType: 'Blind SQL Injection via Union Query',
    category: 'Initial Access',
    classification: 'WEB_THREAT',
    confidence: 0.925,
    confidenceType: 'DEMO_DERIVED',
    anomalyScore: 0.89,
    anomalyScoreLabel: 'DEMO ANOMALY SCORE',
    model: 'Rule-Based Demo Engine (Heuristic Simulator)',
    modelType: 'RULE_BASED_DEMO',
    modelStatus: 'DEMO',
    severity: 'HIGH',
    status: 'DETECTED',
    evidence: [
      'Hex-encoded byte payloads in HTTP query string',
      'SQL syntax tokens: UNION, SELECT, INFORMATION_SCHEMA',
      'Web application returned 500 error code before sanitization'
    ],
    features: {
      findingCount: 2,
      participatingAgentsCount: 2,
      correlationConfidence: 0.89,
      correlationStrengthScore: 2,
      eventDurationSeconds: 45,
      uniqueSourceIpsCount: 1,
      uniqueDestIpsCount: 1,
      affectedHostsCount: 1,
      affectedUsersCount: 1,
      threatTypesCount: 2,
      suspiciousEventsCount: 1,
      highSeverityCount: 1,
      criticalSeverityCount: 0,
      networkInvolvement: 1,
      systemInvolvement: 0,
      applicationInvolvement: 1,
      sequenceLength: 2,
      timeSpanSeconds: 45
    },
    explanation: {
      whyAnalyzed: 'Correlated HTTP injection query coincident with network traffic burst.',
      contributingFeatures: [
        { feature: 'Application Involvement', value: 1, impact: 'HIGH' },
        { feature: 'Correlation Strength', value: 'MEDIUM', impact: 'MEDIUM' }
      ],
      participatingAgents: ['NETWORK_AGENT', 'APPLICATION_AGENT'],
      supportingEvidence: [
        'Hex-encoded byte payloads in HTTP query string',
        'SQL syntax tokens: UNION, SELECT'
      ],
      recommendedAction: 'Block offending IP on WAF and inspect database logs.'
    },
    recommendedAction: 'Block offending IP on WAF and inspect database logs.',
    baselineDeviation: 3.9,
    predictedImpact: 'HIGH'
  },
  {
    id: 'TD-403',
    correlationId: 'CORR-2026-079',
    timestamp: '2026-09-11 22:42:05',
    threatDetected: true,
    threatType: 'DNS Tunneling C2 Beaconing',
    category: 'Command and Control',
    classification: 'NETWORK_THREAT',
    confidence: 0.88,
    confidenceType: 'DEMO_DERIVED',
    anomalyScore: 0.86,
    anomalyScoreLabel: 'DEMO ANOMALY SCORE',
    model: 'Rule-Based Demo Engine (Heuristic Simulator)',
    modelType: 'RULE_BASED_DEMO',
    modelStatus: 'DEMO',
    severity: 'MEDIUM',
    status: 'DETECTED',
    evidence: [
      'Entropy score > 4.75 on TXT resource queries',
      'Query cadence matched jittered 30-second interval',
      'Domain created < 48 hours ago according to WHOIS cache'
    ],
    features: {
      findingCount: 1,
      participatingAgentsCount: 1,
      correlationConfidence: 0.86,
      correlationStrengthScore: 1,
      eventDurationSeconds: 142,
      uniqueSourceIpsCount: 1,
      uniqueDestIpsCount: 1,
      affectedHostsCount: 1,
      affectedUsersCount: 0,
      threatTypesCount: 1,
      suspiciousEventsCount: 1,
      highSeverityCount: 0,
      criticalSeverityCount: 0,
      networkInvolvement: 1,
      systemInvolvement: 0,
      applicationInvolvement: 0,
      sequenceLength: 1,
      timeSpanSeconds: 142
    },
    explanation: {
      whyAnalyzed: 'Repetitive high entropy DNS TXT record queries.',
      contributingFeatures: [
        { feature: 'Network Involvement', value: 1, impact: 'HIGH' }
      ],
      participatingAgents: ['NETWORK_AGENT'],
      supportingEvidence: [
        'Entropy score > 4.75 on TXT resource queries',
        'Query cadence matched jittered interval'
      ],
      recommendedAction: 'Sinkhole suspicious domain at internal DNS resolver.'
    },
    recommendedAction: 'Sinkhole suspicious domain at internal DNS resolver.',
    baselineDeviation: 3.2,
    predictedImpact: 'MEDIUM'
  }
];

export const INITIAL_RISK_ASSESSMENTS: RiskAssessment[] = [
  {
    id: 'RISK-501',
    threatDetectionId: 'TD-401',
    correlationId: 'CORR-301',
    timestamp: '2026-09-11 22:59:00',
    riskScore: 96,
    score: 96,
    severity: 'CRITICAL',
    priority: 'P1',
    riskBand: 'CRITICAL',
    confidence: 95,
    threatClassification: 'MULTI_STAGE_THREAT',
    threatCategory: 'Privilege Escalation / Lateral Movement',
    affectedSource: 'workstation-fin-04 (Finance Subnet)',
    recommendedAction: 'Immediate host isolation from network segment; revoke active Kerberos TGT tickets for admin_dev.',
    explanation: 'Multi-stage lateral sequence observed from perimeter scan through privilege escalation on finance workstation.',
    status: 'NEW',
    participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'],
    evidenceVolume: 8,
    affectedEntitiesCount: 4,
    riskFactors: [
      { name: 'threatSeverity', label: 'Threat Severity', rawScore: 100, weight: 0.30, weightedScore: 30.0, maxPossibleWeightedScore: 30, description: 'CRITICAL severity baseline', evidence: ['CRITICAL impact potential'] },
      { name: 'mlConfidence', label: 'ML Model Confidence', rawScore: 95, weight: 0.20, weightedScore: 19.0, maxPossibleWeightedScore: 20, description: 'High model confidence', evidence: ['Confidence: 95%'] },
      { name: 'correlationStrength', label: 'Correlation Strength', rawScore: 95, weight: 0.15, weightedScore: 14.2, maxPossibleWeightedScore: 15, description: 'Cross-agent cluster', evidence: ['Cluster CORR-301'] },
      { name: 'attackComplexity', label: 'Attack Complexity', rawScore: 95, weight: 0.15, weightedScore: 14.2, maxPossibleWeightedScore: 15, description: 'Multi-stage chain', evidence: ['3 agents involved'] },
      { name: 'agentInvolvement', label: 'Agent Diversity', rawScore: 100, weight: 0.10, weightedScore: 10.0, maxPossibleWeightedScore: 10, description: 'All 3 security agents', evidence: ['Network, System, App'] },
      { name: 'evidenceVolume', label: 'Evidence Volume', rawScore: 80, weight: 0.05, weightedScore: 4.0, maxPossibleWeightedScore: 5, description: '8 correlated artifacts', evidence: ['8 events'] },
      { name: 'affectedEntities', label: 'Impacted Entities Scope', rawScore: 95, weight: 0.05, weightedScore: 4.8, maxPossibleWeightedScore: 5, description: '4 critical assets', evidence: ['4 assets'] }
    ],
    auditTrail: {
      calculatedAt: '2026-09-11T22:59:00.000Z',
      modelUsed: 'Configurable Academic/Demo Risk Engine v1.0',
      correlationStrength: 95,
      mlAnomalyScore: 92,
      weightsConfigVersion: '1.0.0'
    },
    factors: {
      assetCriticality: 98,
      exploitability: 94,
      lateralMovementPotential: 97,
      dataLossExposure: 95
    },
    remediationPlan: [
      'Step 1: Execute simulated network quarantine on workstation-fin-04',
      'Step 2: Terminate PID 4120 and purge temporary executable binaries',
      'Step 3: Invalidate user session tokens and force credential rotation',
      'Step 4: Dispatch forensic capture trigger to Wazuh agent'
    ]
  },
  {
    id: 'RISK-502',
    threatDetectionId: 'TD-402',
    correlationId: 'CORR-302',
    timestamp: '2026-09-11 22:52:00',
    riskScore: 85,
    score: 85,
    severity: 'HIGH',
    priority: 'P1',
    riskBand: 'CRITICAL',
    confidence: 91,
    threatClassification: 'WEB_THREAT',
    threatCategory: 'Web Application Exploitation',
    affectedSource: 'api.corp.internal/v2/checkout',
    recommendedAction: 'Deploy edge WAF filter rule blocking UNION/SELECT signatures; verify database query parameterization.',
    explanation: 'Repetitive SQL injection vectors directed at checkout gateway with elevated volume.',
    status: 'REVIEWING',
    participatingAgents: ['APPLICATION_AGENT', 'NETWORK_AGENT'],
    evidenceVolume: 6,
    affectedEntitiesCount: 2,
    riskFactors: [
      { name: 'threatSeverity', label: 'Threat Severity', rawScore: 80, weight: 0.30, weightedScore: 24.0, maxPossibleWeightedScore: 30, description: 'HIGH severity baseline', evidence: ['HIGH potential'] },
      { name: 'mlConfidence', label: 'ML Model Confidence', rawScore: 91, weight: 0.20, weightedScore: 18.2, maxPossibleWeightedScore: 20, description: 'Elevated confidence', evidence: ['Confidence: 91%'] },
      { name: 'correlationStrength', label: 'Correlation Strength', rawScore: 85, weight: 0.15, weightedScore: 12.8, maxPossibleWeightedScore: 15, description: 'Application correlation', evidence: ['Cluster CORR-302'] },
      { name: 'attackComplexity', label: 'Attack Complexity', rawScore: 75, weight: 0.15, weightedScore: 11.3, maxPossibleWeightedScore: 15, description: 'Injection sequence', evidence: ['2 agents involved'] },
      { name: 'agentInvolvement', label: 'Agent Diversity', rawScore: 70, weight: 0.10, weightedScore: 7.0, maxPossibleWeightedScore: 10, description: '2 security agents', evidence: ['Network, App'] },
      { name: 'evidenceVolume', label: 'Evidence Volume', rawScore: 70, weight: 0.05, weightedScore: 3.5, maxPossibleWeightedScore: 5, description: '6 events', evidence: ['6 events'] },
      { name: 'affectedEntities', label: 'Impacted Entities Scope', rawScore: 65, weight: 0.05, weightedScore: 3.3, maxPossibleWeightedScore: 5, description: '2 assets', evidence: ['2 assets'] }
    ],
    auditTrail: {
      calculatedAt: '2026-09-11T22:52:00.000Z',
      modelUsed: 'Configurable Academic/Demo Risk Engine v1.0',
      correlationStrength: 85,
      mlAnomalyScore: 78,
      weightsConfigVersion: '1.0.0'
    },
    factors: {
      assetCriticality: 90,
      exploitability: 88,
      lateralMovementPotential: 75,
      dataLossExposure: 87
    },
    remediationPlan: [
      'Step 1: Enable strict modsecurity blocking rule 942100 on API ingress',
      'Step 2: Inspect backend DB audit log for successful query executions',
      'Step 3: Alert application development team to audit checkout endpoint'
    ]
  },
  {
    id: 'RISK-503',
    threatDetectionId: 'TD-403',
    correlationId: 'CORR-303',
    timestamp: '2026-09-11 22:45:00',
    riskScore: 68,
    score: 68,
    severity: 'MEDIUM',
    priority: 'P2',
    riskBand: 'HIGH',
    confidence: 88,
    threatClassification: 'AUTHENTICATION_THREAT',
    threatCategory: 'Credential Abuse / Brute Force',
    affectedSource: 'auth-gateway-srv-02',
    recommendedAction: 'Apply progressive delay throttle on IP CIDR 192.168.1.0/24; mandate biometric MFA prompt.',
    explanation: 'Substantial burst of failed authentication attempts against single PAM service.',
    status: 'ACKNOWLEDGED',
    participatingAgents: ['SYSTEM_AGENT', 'APPLICATION_AGENT'],
    evidenceVolume: 5,
    affectedEntitiesCount: 2,
    riskFactors: [
      { name: 'threatSeverity', label: 'Threat Severity', rawScore: 50, weight: 0.30, weightedScore: 15.0, maxPossibleWeightedScore: 30, description: 'MEDIUM severity baseline', evidence: ['MEDIUM potential'] },
      { name: 'mlConfidence', label: 'ML Model Confidence', rawScore: 88, weight: 0.20, weightedScore: 17.6, maxPossibleWeightedScore: 20, description: 'Auth anomaly confidence', evidence: ['Confidence: 88%'] },
      { name: 'correlationStrength', label: 'Correlation Strength', rawScore: 75, weight: 0.15, weightedScore: 11.2, maxPossibleWeightedScore: 15, description: 'Time-window correlation', evidence: ['Cluster CORR-303'] },
      { name: 'attackComplexity', label: 'Attack Complexity', rawScore: 60, weight: 0.15, weightedScore: 9.0, maxPossibleWeightedScore: 15, description: 'Credential burst', evidence: ['Repeated brute force'] },
      { name: 'agentInvolvement', label: 'Agent Diversity', rawScore: 70, weight: 0.10, weightedScore: 7.0, maxPossibleWeightedScore: 10, description: '2 agents', evidence: ['System, App'] },
      { name: 'evidenceVolume', label: 'Evidence Volume', rawScore: 50, weight: 0.05, weightedScore: 2.5, maxPossibleWeightedScore: 5, description: '5 events', evidence: ['5 events'] },
      { name: 'affectedEntities', label: 'Impacted Entities Scope', rawScore: 65, weight: 0.05, weightedScore: 3.3, maxPossibleWeightedScore: 5, description: '2 assets', evidence: ['2 assets'] }
    ],
    auditTrail: {
      calculatedAt: '2026-09-11T22:45:00.000Z',
      modelUsed: 'Configurable Academic/Demo Risk Engine v1.0',
      correlationStrength: 75,
      mlAnomalyScore: 65,
      weightsConfigVersion: '1.0.0'
    },
    factors: {
      assetCriticality: 82,
      exploitability: 60,
      lateralMovementPotential: 58,
      dataLossExposure: 72
    },
    remediationPlan: [
      'Step 1: Impose 15-minute lock on accounts with > 10 failed attempts',
      'Step 2: Require step-up authenticator push notification'
    ]
  },
  {
    id: 'RISK-504',
    threatDetectionId: 'TD-404',
    correlationId: 'CORR-304',
    timestamp: '2026-09-11 22:15:00',
    riskScore: 32,
    score: 32,
    severity: 'LOW',
    priority: 'P3',
    riskBand: 'MEDIUM',
    confidence: 82,
    threatClassification: 'NETWORK_THREAT',
    threatCategory: 'Perimeter Reconnaissance',
    affectedSource: '192.168.1.105',
    recommendedAction: 'Log IP address into threat intelligence watch list; no active intervention required.',
    explanation: 'Low-rate horizontal port probing detected by Network Agent on external perimeter.',
    status: 'NEW',
    participatingAgents: ['NETWORK_AGENT'],
    evidenceVolume: 3,
    affectedEntitiesCount: 1,
    riskFactors: [
      { name: 'threatSeverity', label: 'Threat Severity', rawScore: 20, weight: 0.30, weightedScore: 6.0, maxPossibleWeightedScore: 30, description: 'LOW severity baseline', evidence: ['LOW potential'] },
      { name: 'mlConfidence', label: 'ML Model Confidence', rawScore: 82, weight: 0.20, weightedScore: 16.4, maxPossibleWeightedScore: 20, description: 'Recon classification', evidence: ['Confidence: 82%'] },
      { name: 'correlationStrength', label: 'Correlation Strength', rawScore: 40, weight: 0.15, weightedScore: 6.0, maxPossibleWeightedScore: 15, description: 'Isolated scan', evidence: ['Cluster CORR-304'] },
      { name: 'attackComplexity', label: 'Attack Complexity', rawScore: 25, weight: 0.15, weightedScore: 3.8, maxPossibleWeightedScore: 15, description: 'Single probe', evidence: ['1 agent involved'] },
      { name: 'agentInvolvement', label: 'Agent Diversity', rawScore: 30, weight: 0.10, weightedScore: 3.0, maxPossibleWeightedScore: 10, description: '1 agent', evidence: ['Network'] },
      { name: 'evidenceVolume', label: 'Evidence Volume', rawScore: 30, weight: 0.05, weightedScore: 1.5, maxPossibleWeightedScore: 5, description: '3 events', evidence: ['3 events'] },
      { name: 'affectedEntities', label: 'Impacted Entities Scope', rawScore: 35, weight: 0.05, weightedScore: 1.8, maxPossibleWeightedScore: 5, description: '1 asset', evidence: ['1 asset'] }
    ],
    auditTrail: {
      calculatedAt: '2026-09-11T22:15:00.000Z',
      modelUsed: 'Configurable Academic/Demo Risk Engine v1.0',
      correlationStrength: 40,
      mlAnomalyScore: 28,
      weightsConfigVersion: '1.0.0'
    },
    factors: {
      assetCriticality: 40,
      exploitability: 35,
      lateralMovementPotential: 25,
      dataLossExposure: 28
    },
    remediationPlan: [
      'Step 1: Add IP to Suricata drop list if scan continues over 60s window'
    ]
  }
];

export interface InitialAlertRecord {
  alertId: string;
  timestamp: string;
  threat: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  source: string;
  riskScore: number;
  status: string;
  notificationStatus: string;
  targetChannels: string[];
  n8nWorkflowId?: string;
  ruleTriggered: string;
}

export const INITIAL_INCIDENTS: Incident[] = [
  {
    incidentId: 'INC-2026-0042',
    detectedAt: '2026-09-11 22:58:30',
    threatType: 'Targeted Multi-Stage Lateral Compromise',
    severity: 'CRITICAL',
    riskScore: 96,
    affectedSource: 'workstation-fin-04 & api.corp.internal',
    status: 'INVESTIGATING',
    assignedTo: 'Senior SOC Analyst (StudyCafe)',
    summary: 'Correlated event sequence starting with port scanning, followed by web API SQL injection injection attempt and local host token impersonation.',
    timeline: [
      { id: 'tl-42-1', time: '22:58:14', description: 'Port scan detected on DMZ boundary (Network Agent)', actor: 'External Attacker (192.168.1.105)' },
      { id: 'tl-42-2', time: '22:51:30', description: 'SQL injection payload on checkout API (Application Agent)', actor: 'External Attacker' },
      { id: 'tl-42-3', time: '22:47:19', description: 'Privilege escalation attempt via token impersonation (System Agent)', actor: 'Internal Service Account' },
      { id: 'tl-42-4', time: '22:58:30', description: 'Event Correlation Engine elevated sequence to Critical Incident', actor: 'Correlation Engine' }
    ],
    mitreTactic: 'TA0004 - Privilege Escalation',
    mitreTechnique: 'T1068 - Exploitation for Privilege Escalation',
    containmentRecommendation: 'Isolate host workstation-fin-04 via EDR; patch checkout API endpoint query parsing; revoke service credentials.'
  },
  {
    incidentId: 'INC-2026-0041',
    detectedAt: '2026-09-11 22:45:10',
    threatType: 'Coordinated Brute Force & Credential Stuffing',
    severity: 'HIGH',
    riskScore: 85,
    affectedSource: 'auth-gateway-srv-02',
    status: 'CONTAINED',
    assignedTo: 'Tier 2 SOC Incident Team',
    summary: 'High volume of credential spraying across corporate SSO and VPN gateway from rotating botnet exit nodes.',
    timeline: [
      { id: 'tl-41-1', time: '22:36:51', description: 'IKEv2 handshake brute force spike on VPN (Network Agent)', actor: 'Botnet Cluster' },
      { id: 'tl-41-2', time: '22:42:00', description: 'SSO login failures exceeded 500 threshold (Application Agent)', actor: 'Botnet Cluster' },
      { id: 'tl-41-3', time: '22:45:10', description: 'Adaptive rate-limiting triggered automatically', actor: 'Security Gateway' }
    ],
    mitreTactic: 'TA0006 - Credential Access',
    mitreTechnique: 'T1110 - Brute Force',
    containmentRecommendation: 'Enforce geo-fencing on non-essential regions and mandate hardware token verification.'
  },
  {
    incidentId: 'INC-2026-0040',
    detectedAt: '2026-09-11 21:30:00',
    threatType: 'Anomalous Data Staging & DNS Exfiltration',
    severity: 'MEDIUM',
    riskScore: 68,
    affectedSource: '10.240.12.88 (Core Router)',
    status: 'RESOLVED',
    assignedTo: 'Network Defense Unit',
    summary: 'Periodic DNS TXT record tunneling transmitting high-entropy payload data to unclassified external domain.',
    timeline: [
      { id: 'tl-40-1', time: '21:15:00', description: 'Initial entropy spike observed in DNS resolver logs', actor: 'Host 10.240.12.88' },
      { id: 'tl-40-2', time: '21:30:00', description: 'Pattern classified as DNS beaconing by Network Agent', actor: 'Network Agent' },
      { id: 'tl-40-3', time: '21:45:00', description: 'Sinkholed domain at corporate DNS resolver', actor: 'Tier 1 Analyst' }
    ],
    mitreTactic: 'TA0010 - Exfiltration',
    mitreTechnique: 'T1071.004 - DNS Tunneling',
    containmentRecommendation: 'Inspect host for persistent background staging service.'
  }
];

export const INITIAL_ALERTS: InitialAlertRecord[] = [
  {
    alertId: 'ALT-1099',
    timestamp: '2026-09-11 22:58:30',
    threat: 'Critical Multi-Agent Correlated Infiltration Incident',
    severity: 'CRITICAL',
    source: 'workstation-fin-04',
    riskScore: 96,
    status: 'UNACKNOWLEDGED',
    notificationStatus: 'DISPATCHED_N8N',
    targetChannels: ['#soc-tier1-alerts', 'PagerDuty On-Call', 'n8n Incident Automation'],
    n8nWorkflowId: 'wf_soc_containment_pipeline_v1',
    ruleTriggered: 'CORR_RULE_MULTI_STAGE_LATERAL_09'
  },
  {
    alertId: 'ALT-1098',
    timestamp: '2026-09-11 22:51:30',
    threat: 'SQL Injection Exploitation Pattern Detected',
    severity: 'HIGH',
    source: 'api.corp.internal/v2/checkout',
    riskScore: 88,
    status: 'ACKNOWLEDGED',
    notificationStatus: 'SENT',
    targetChannels: ['#soc-appsec', 'Slack Webhook'],
    n8nWorkflowId: 'wf_waf_ticket_sync',
    ruleTriggered: 'APP_RULE_SQLI_UNION_STACK'
  },
  {
    alertId: 'ALT-1097',
    timestamp: '2026-09-11 22:42:05',
    threat: 'High Shannon Entropy DNS Tunneling Activity',
    severity: 'MEDIUM',
    source: '10.240.12.88',
    riskScore: 64,
    status: 'ACKNOWLEDGED',
    notificationStatus: 'SENT',
    targetChannels: ['#soc-netflow'],
    ruleTriggered: 'NET_RULE_DNS_ENTROPY_HIGH'
  },
  {
    alertId: 'ALT-1096',
    timestamp: '2026-09-11 22:36:51',
    threat: 'Perimeter Credential Spraying Wave',
    severity: 'HIGH',
    source: 'vpn-concentrator-east',
    riskScore: 84,
    status: 'RESOLVED',
    notificationStatus: 'SENT',
    targetChannels: ['#soc-iam'],
    ruleTriggered: 'NET_RULE_VPN_SPRAY_BURST'
  }
];

export const CHART_EVENTS_OVER_TIME: TimeSeriesPoint[] = [
  { time: '18:00', networkEvents: 18400, systemEvents: 8200, applicationEvents: 4100, threats: 2 },
  { time: '19:00', networkEvents: 22100, systemEvents: 9400, applicationEvents: 4900, threats: 4 },
  { time: '20:00', networkEvents: 28300, systemEvents: 12100, applicationEvents: 6200, threats: 5 },
  { time: '21:00', networkEvents: 34200, systemEvents: 16800, applicationEvents: 8500, threats: 9 },
  { time: '22:00', networkEvents: 49800, systemEvents: 24500, applicationEvents: 13200, threats: 17 }
];

export const CHART_SEVERITY_DISTRIBUTION: SeverityDistributionPoint[] = [
  { severity: 'LOW', count: 1042, color: '#3b82f6' },
  { severity: 'MEDIUM', count: 284, color: '#f59e0b' },
  { severity: 'HIGH', count: 86, color: '#f97316' },
  { severity: 'CRITICAL', count: 16, color: '#ef4444' }
];

export const CHART_EVENTS_BY_SOURCE: SourceDistributionPoint[] = [
  { source: 'Network (Suricata/Bro)', count: 248100, threats: 19 },
  { source: 'System (Wazuh/Sysmon)', count: 119420, threats: 11 },
  { source: 'App Gateway (Nginx/API)', count: 61430, threats: 7 }
];

export const CHART_AGENT_ACTIVITY: AgentActivityPoint[] = [
  { time: '18:00', networkAgent: 840, systemAgent: 420, applicationAgent: 210 },
  { time: '19:00', networkAgent: 980, systemAgent: 510, applicationAgent: 280 },
  { time: '20:00', networkAgent: 1150, systemAgent: 640, applicationAgent: 340 },
  { time: '21:00', networkAgent: 1420, systemAgent: 820, applicationAgent: 490 },
  { time: '22:00', networkAgent: 1950, systemAgent: 1180, applicationAgent: 690 }
];

export const CHART_THREAT_CATEGORIES: ThreatCategoryPoint[] = [
  { category: 'Privilege Escalation', count: 11, riskAvg: 92 },
  { category: 'Initial Access / SQLi', count: 8, riskAvg: 85 },
  { category: 'Command & Control', count: 7, riskAvg: 78 },
  { category: 'Credential Access', count: 6, riskAvg: 74 },
  { category: 'Reconnaissance', count: 5, riskAvg: 58 }
];
