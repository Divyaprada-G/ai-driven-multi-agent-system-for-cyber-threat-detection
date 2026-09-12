/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Demo Scenario Service
 *
 * Provides safe, deterministic, non-destructive project demonstration scenarios:
 * Scenario 1: Normal Activity
 * Scenario 2: Suspicious Network Activity
 * Scenario 3: Authentication Threat
 * Scenario 4: Privilege Escalation
 * Scenario 5: Web/Application Threat
 * Scenario 6: Multi-Stage Threat
 * Scenario 7: High-Risk Incident
 *
 * Each scenario models the end-to-end pipeline:
 * Event -> Agent Finding -> Correlation -> ML Detection -> Risk Assessment -> Alert -> Incident
 */

import { DemoScenarioDefinition, TraceabilityChain } from '../types/analytics';
import { auditService } from './auditService';
import { alertManager } from './alertIncident/alertManager';
import { incidentManager } from './alertIncident/incidentManager';
import { riskService } from './riskService';
import { correlationService } from './correlationService';

export const DEMO_SCENARIOS: DemoScenarioDefinition[] = [
  {
    id: 'DEMO-SCENARIO-1',
    scenarioNumber: 1,
    name: 'Normal Baseline Activity',
    category: 'BENIGN_TELEMETRY',
    description: 'Routine network telemetry, nominal SSH administrator sessions, and standard HTTP 200 health check queries. Validates zero false alarms during baseline operations.',
    expectedFlow: [
      'Normal TLS 1.3 handshake on port 443',
      'System Agent validates signed systemd daemon startup',
      'Correlation Engine scores nominal baseline (< 0.15 threshold)',
      'Threat Detection evaluates classification as BENIGN',
      'Risk Score: 12/100 (Low / P4)',
      'Alert suppressed per baseline policy (No escalation)'
    ],
    threatClassification: 'BENIGN',
    severity: 'LOW',
    expectedRiskScore: 12,
    priority: 'P4',
    participatingAgents: ['NETWORK_AGENT', 'APPLICATION_AGENT'],
    deterministicEntities: {
      sourceIp: '10.0.10.45',
      targetHost: 'gateway-lb-01.corp.internal',
      user: 'svc_healthcheck',
      endpoint: '/healthz'
    }
  },
  {
    id: 'DEMO-SCENARIO-2',
    scenarioNumber: 2,
    name: 'Suspicious Network Activity (Reconnaissance)',
    category: 'NETWORK_RECON',
    description: 'Rapid sequential SYN packet scanning across 128 reserved management ports from an untrusted external perimeter IP.',
    expectedFlow: [
      'Raw Suricata flow log records 128 SYN packets without ACK completion',
      'Network Security Agent detects horizontal port scan heuristic',
      'Correlation Engine aggregates network burst with source IP 198.51.100.77',
      'Threat Detection model flags ANOMALY / NETWORK_THREAT with 88% confidence',
      'Risk Score: 58/100 (Medium / P3)',
      'Alert ALT-2002 generated for SOC triage'
    ],
    threatClassification: 'NETWORK_THREAT',
    severity: 'MEDIUM',
    expectedRiskScore: 58,
    priority: 'P3',
    participatingAgents: ['NETWORK_AGENT'],
    deterministicEntities: {
      sourceIp: '198.51.100.77',
      targetHost: 'dmz-firewall-ext.corp.internal',
      user: 'unknown',
      endpoint: 'TCP/Multiple'
    }
  },
  {
    id: 'DEMO-SCENARIO-3',
    scenarioNumber: 3,
    name: 'Authentication Threat (Credential Stuffing)',
    category: 'AUTH_ATTACK',
    description: 'Distributed credential brute-force attempts targeting internal administrative portals resulting in repeated PAM auth failures.',
    expectedFlow: [
      'Application auth gateway logs 42 failed logins within a 30-second window',
      'System Agent observes repeated pam_unix authentication failures on sshd',
      'Correlation Engine associates shared target user "admin_ops"',
      'Threat Detection model classifies AUTHENTICATION_THREAT with 92% confidence',
      'Risk Score: 78/100 (High / P2)',
      'Alert ALT-2003 generated; Escalated to Incident INC-2026-0045'
    ],
    threatClassification: 'AUTHENTICATION_THREAT',
    severity: 'HIGH',
    expectedRiskScore: 78,
    priority: 'P2',
    participatingAgents: ['APPLICATION_AGENT', 'SYSTEM_AGENT'],
    deterministicEntities: {
      sourceIp: '203.0.113.15',
      targetHost: 'auth-gateway-srv-02',
      user: 'admin_ops',
      endpoint: '/api/v1/auth/login'
    }
  },
  {
    id: 'DEMO-SCENARIO-4',
    scenarioNumber: 4,
    name: 'Host Privilege Escalation (Token Impersonation)',
    category: 'PRIV_ESCALATION',
    description: 'Suspicious child process cmd.exe spawned by background spoolsv.exe service followed by SeImpersonate privilege token elevation.',
    expectedFlow: [
      'Sysmon Event ID 1 captures unquoted service cmd execution from spoolsv.exe',
      'System Security Agent matches privilege elevation signature',
      'Correlation Engine links process hierarchy with local service account',
      'Threat Detection model flags PRIVILEGE_ESCALATION with 95% confidence',
      'Risk Score: 86/100 (High / P2)',
      'Alert ALT-2004 generated; containment recommendation formulated'
    ],
    threatClassification: 'PRIVILEGE_ESCALATION',
    severity: 'HIGH',
    expectedRiskScore: 86,
    priority: 'P2',
    participatingAgents: ['SYSTEM_AGENT'],
    deterministicEntities: {
      sourceIp: '192.168.1.105',
      targetHost: 'workstation-fin-04',
      user: 'SYSTEM_SVC',
      endpoint: 'C:\\Windows\\System32\\spoolsv.exe'
    }
  },
  {
    id: 'DEMO-SCENARIO-5',
    scenarioNumber: 5,
    name: 'Web / Application Threat (SQLi & Path Traversal)',
    category: 'WEB_EXPLOIT',
    description: 'Malicious payload injection exploiting input sanitization vulnerabilities on customer checkout and document download endpoints.',
    expectedFlow: [
      'Nginx access log intercepts UNION SELECT and directory traversal sequences',
      'Application Security Agent detects SQL injection pattern and OWASP Top 10 rule',
      'Correlation Engine connects web exploit to remote client session',
      'Threat Detection model flags WEB_THREAT with 91% confidence',
      'Risk Score: 74/100 (High / P2)',
      'Alert ALT-2005 generated with WAF mitigation proposal'
    ],
    threatClassification: 'WEB_THREAT',
    severity: 'HIGH',
    expectedRiskScore: 74,
    priority: 'P2',
    participatingAgents: ['APPLICATION_AGENT'],
    deterministicEntities: {
      sourceIp: '198.51.100.89',
      targetHost: 'app-ecommerce-node-03',
      user: 'guest_session_881',
      endpoint: '/api/v2/orders/receipt?id=1+UNION+SELECT'
    }
  },
  {
    id: 'DEMO-SCENARIO-6',
    scenarioNumber: 6,
    name: 'Multi-Stage Threat (APT Attack Killchain)',
    category: 'MULTI_STAGE_APT',
    description: 'Coordinated multi-agent attack: External port reconnaissance -> Web API SQL injection -> Host token escalation -> Internal database enumeration.',
    expectedFlow: [
      'Phase 1: Network Agent detects perimeter scanning from 192.168.1.105',
      'Phase 2: Application Agent intercepts UNION SELECT on internal API endpoint',
      'Phase 3: System Agent captures token elevation on workstation-fin-04',
      'Phase 4: Correlation Engine synthesizes 3-agent chain into CORR-2026-001',
      'Phase 5: Threat Detection model classifies MULTI_STAGE_THREAT (94% confidence)',
      'Phase 6: Risk Scoring Engine assigns 94/100 Critical P1 priority',
      'Phase 7: Alert ALT-1099 created and linked to Incident INC-2026-0042'
    ],
    threatClassification: 'MULTI_STAGE_THREAT',
    severity: 'CRITICAL',
    expectedRiskScore: 94,
    priority: 'P1',
    participatingAgents: ['NETWORK_AGENT', 'APPLICATION_AGENT', 'SYSTEM_AGENT'],
    deterministicEntities: {
      sourceIp: '192.168.1.105',
      targetHost: 'workstation-fin-04 & api.corp.internal',
      user: 'admin_dev',
      endpoint: 'Multi-Stage Ingress & Internal Pivot'
    }
  },
  {
    id: 'DEMO-SCENARIO-7',
    scenarioNumber: 7,
    name: 'High-Risk Incident (Lateral Movement & Exfiltration)',
    category: 'CRITICAL_BREACH',
    description: 'Confirmed breach scenario with cross-subnet SMB lateral movement, staging of compressed archives, and DNS tunneling beaconing.',
    expectedFlow: [
      'Network Agent flags abnormal DNS query lengths indicative of data tunneling',
      'System Agent records archive compression of sensitive directories',
      'Correlation Engine identifies active lateral movement between DMZ and finance subnets',
      'Threat Detection model confirms high-severity breach with 97% confidence',
      'Risk Score: 98/100 (Critical / P1)',
      'Immediate escalation to Critical Incident INC-2026-0046 with containment simulation'
    ],
    threatClassification: 'MULTI_STAGE_THREAT',
    severity: 'CRITICAL',
    expectedRiskScore: 98,
    priority: 'P1',
    participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'],
    deterministicEntities: {
      sourceIp: '10.200.5.12',
      targetHost: 'core-db-cluster-p01',
      user: 'domain_admin_compromised',
      endpoint: 'Internal RPC / DNS Tunnel'
    }
  }
];

class DemoScenarioService {
  private activeScenario: DemoScenarioDefinition | null = null;
  private isDemoMode = true; // Flag for clear labeling
  private listeners: Array<() => void> = [];

  public subscribe(callback: () => void): () => void {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(cb => cb !== callback);
    };
  }

  private notify(): void {
    this.listeners.forEach(cb => {
      try {
        cb();
      } catch (err) {
        console.error('DemoScenarioService listener error:', err);
      }
    });
  }

  public getScenarios(): DemoScenarioDefinition[] {
    return DEMO_SCENARIOS;
  }

  public getActiveScenario(): DemoScenarioDefinition | null {
    return this.activeScenario;
  }

  public getActiveScenarioId(): string | null {
    return this.activeScenario?.id || null;
  }

  public isDemoActive(): boolean {
    return this.isDemoMode;
  }

  public async loadScenario(scenarioId: string): Promise<{ success: boolean; message: string }> {
    const res = await this.executeScenario(scenarioId);
    return {
      success: true,
      message: `Scenario ${res.scenario.scenarioNumber} (${res.scenario.name}) loaded successfully with safe deterministic pipeline telemetry.`
    };
  }

  public async resetToCleanState(): Promise<{ success: boolean; message: string }> {
    this.resetDemo();
    return {
      success: true,
      message: 'Demo environment reset safely to initial baseline state. User logs preserved.'
    };
  }

  /**
   * Safely execute a deterministic demonstration scenario
   */
  public async executeScenario(scenarioId: string): Promise<{
    scenario: DemoScenarioDefinition;
    traceabilityChain: TraceabilityChain;
  }> {
    const scenario = DEMO_SCENARIOS.find(s => s.id === scenarioId) || DEMO_SCENARIOS[5]; // Default to multi-stage
    this.activeScenario = scenario;

    // Log the execution to audit trail
    auditService.recordAction({
      action: 'DEMO_SCENARIO_STARTED',
      entityType: 'DEMO',
      entityId: scenario.id,
      actor: 'Demonstrator / Viva Evaluator',
      details: `[SAFE SIMULATION] Started Scenario ${scenario.scenarioNumber}: ${scenario.name}. Deterministic data flow initiated.`,
      metadata: {
        threatClassification: scenario.threatClassification,
        expectedRiskScore: scenario.expectedRiskScore,
        severity: scenario.severity,
        agents: scenario.participatingAgents
      }
    });

    // Build deterministic Traceability Chain for the academic presentation
    const traceId = `TRACE-${scenario.id.replace('DEMO-SCENARIO-', 'S')}`;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);

    const traceabilityChain: TraceabilityChain = {
      id: traceId,
      title: scenario.name,
      classification: scenario.threatClassification,
      overallSeverity: scenario.severity,
      overallRiskScore: scenario.expectedRiskScore,
      steps: [
        {
          stage: 'Original Event',
          id: `EVT-${scenario.scenarioNumber}01`,
          label: `Raw Telemetry Ingestion from ${scenario.deterministicEntities.sourceIp}`,
          timestamp,
          status: 'Normalized & Validated',
          details: `Source: ${scenario.deterministicEntities.sourceIp} targeting ${scenario.deterministicEntities.targetHost}`,
          severity: scenario.severity
        },
        {
          stage: 'Agent Finding',
          id: `${scenario.participatingAgents[0].substring(0, 3)}-FINDING-${scenario.scenarioNumber}`,
          label: `${scenario.participatingAgents.join(' & ')} Rule Evaluation`,
          timestamp,
          status: 'Finding Flagged',
          agent: scenario.participatingAgents[0],
          details: scenario.expectedFlow[1] || 'Agent matched heuristic detection signature',
          severity: scenario.severity
        },
        {
          stage: 'Correlated Event',
          id: `CORR-DEMO-${scenario.scenarioNumber.toString().padStart(2, '0')}`,
          label: `Cross-Agent Temporal & Entity Correlation`,
          timestamp,
          status: 'Correlation Synthesized',
          details: `Aggregated ${scenario.participatingAgents.length} agents on entity ${scenario.deterministicEntities.sourceIp}`,
          severity: scenario.severity,
          score: Math.round(scenario.expectedRiskScore * 0.95)
        },
        {
          stage: 'Threat Detection',
          id: `TD-DEMO-${scenario.scenarioNumber.toString().padStart(2, '0')}`,
          label: `AI/ML Classifier Evaluation`,
          timestamp,
          status: 'Classified',
          details: `Classification: ${scenario.threatClassification} (Confidence: 94.2%, Model: Deterministic Heuristic Engine)`,
          severity: scenario.severity,
          score: scenario.expectedRiskScore
        },
        {
          stage: 'Risk Assessment',
          id: `RISK-DEMO-${scenario.scenarioNumber.toString().padStart(2, '0')}`,
          label: `7-Factor Weighted Quantitative Scoring`,
          timestamp,
          status: 'Risk Evaluated',
          details: `Calculated Risk Score: ${scenario.expectedRiskScore}/100 | Priority: ${scenario.priority}`,
          severity: scenario.severity,
          score: scenario.expectedRiskScore
        },
        {
          stage: 'Alert',
          id: `ALT-DEMO-${scenario.scenarioNumber.toString().padStart(2, '0')}`,
          label: `Security Alert Dispatch`,
          timestamp,
          status: 'NEW',
          details: `Alert dispatched to SOC Queue. Mitigation recommendation: Review entity ${scenario.deterministicEntities.sourceIp}`,
          severity: scenario.severity,
          score: scenario.expectedRiskScore
        },
        {
          stage: 'Incident',
          id: `INC-DEMO-${scenario.scenarioNumber.toString().padStart(2, '0')}`,
          label: `Security Incident Aggregation`,
          timestamp,
          status: 'INVESTIGATING',
          details: `Formal incident dossier opened. Assigned to Tier-2 SOC Analyst.`,
          severity: scenario.severity,
          score: scenario.expectedRiskScore
        }
      ]
    };

    this.notify();
    return { scenario, traceabilityChain };
  }

  /**
   * Reset demonstration environment safely without affecting user uploaded log files
   */
  public resetDemo(): void {
    this.activeScenario = null;
    auditService.resetDemoAudit();
    this.notify();
  }
}

export const demoScenarioService = new DemoScenarioService();
