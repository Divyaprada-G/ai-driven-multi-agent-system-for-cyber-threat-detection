import {
  CorrelatedEvent,
  SecurityFinding,
  CorrelationConfig,
  CorrelationMetrics,
  CorrelationScenarioId,
  Incident
} from '../types';
import { CorrelationEngine } from './correlationEngine';
import { CorrelationNormalizer } from './correlationNormalizer';
import { CORRELATION_DEMO_SCENARIOS } from './correlationDemoScenarios';
import { networkAgentService } from './networkAgentService';
import { systemAgentService } from './systemAgentService';
import { applicationAgentService } from './applicationAgentService';
import { logRepository } from './logRepository';
import { incidentService } from './incidentService';

export interface ICorrelationService {
  correlateSecurityFindings(findings: SecurityFinding[]): Promise<CorrelatedEvent[]>;
  getCorrelatedEvents(): Promise<CorrelatedEvent[]>;
  getCorrelationById(id: string): Promise<CorrelatedEvent | undefined>;
  triggerManualCorrelation(eventIds: string[]): Promise<CorrelatedEvent>;
  escalateToIncident(correlationId: string): Promise<boolean>;
  createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident>;
  getConfig(): CorrelationConfig;
  updateConfig(config: Partial<CorrelationConfig>): void;
  getMetrics(): Promise<CorrelationMetrics>;
  getAllFindings(): Promise<SecurityFinding[]>;
  loadDemoScenario(scenarioId: CorrelationScenarioId): Promise<CorrelatedEvent[]>;
  isRealDataActive(): boolean;
  getCurrentScenarioId(): CorrelationScenarioId | null;
  resetToDefaultDataSource(): Promise<void>;
  subscribe(listener: () => void): () => void;
}

const DEFAULT_CONFIG: CorrelationConfig = {
  timeWindowSeconds: 300, // 5 minutes default
  minFindings: 2,
  crossAgentRequired: false,
  minCorrelationStrength: 'LOW',
  autoCorrelationEnabled: true
};

class CorrelationServiceImpl implements ICorrelationService {
  private config: CorrelationConfig = { ...DEFAULT_CONFIG };
  private activeScenarioId: CorrelationScenarioId | null = null;
  private cachedCorrelations: CorrelatedEvent[] = [];
  private cachedFindings: SecurityFinding[] = [];
  private listeners: Set<() => void> = new Set();
  private isInitialized = false;

  constructor() {
    // Listen to log repository changes to invalidate and re-run correlation automatically
    logRepository.subscribe(() => {
      this.activeScenarioId = null;
      this.refreshCorrelation();
    });
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    this.listeners.forEach(cb => {
      try {
        cb();
      } catch (err) {
        console.error('Correlation subscriber error:', err);
      }
    });
  }

  public getConfig(): CorrelationConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<CorrelationConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.refreshCorrelation();
  }

  public isRealDataActive(): boolean {
    return logRepository.hasRealData() && this.activeScenarioId === null;
  }

  public getCurrentScenarioId(): CorrelationScenarioId | null {
    return this.activeScenarioId;
  }

  public async resetToDefaultDataSource(): Promise<void> {
    this.activeScenarioId = null;
    await this.refreshCorrelation();
  }

  public async loadDemoScenario(scenarioId: CorrelationScenarioId): Promise<CorrelatedEvent[]> {
    this.activeScenarioId = scenarioId;
    const scenario = CORRELATION_DEMO_SCENARIOS[scenarioId];
    if (!scenario) {
      return this.getCorrelatedEvents();
    }

    this.cachedFindings = [...scenario.findings];
    this.cachedCorrelations = CorrelationEngine.correlate(this.cachedFindings, this.config);
    this.notify();
    return [...this.cachedCorrelations];
  }

  /**
   * Main service function: Takes raw findings, normalizes, and runs the correlation engine.
   */
  public async correlateSecurityFindings(findings: SecurityFinding[]): Promise<CorrelatedEvent[]> {
    const normalized = CorrelationNormalizer.normalizeBatch(findings);
    return CorrelationEngine.correlate(normalized, this.config);
  }

  public async getAllFindings(): Promise<SecurityFinding[]> {
    if (!this.isInitialized) {
      await this.refreshCorrelation();
    }
    return [...this.cachedFindings];
  }

  public async getCorrelatedEvents(): Promise<CorrelatedEvent[]> {
    if (!this.isInitialized || this.cachedCorrelations.length === 0) {
      await this.refreshCorrelation();
    }
    return [...this.cachedCorrelations];
  }

  public async getCorrelationById(id: string): Promise<CorrelatedEvent | undefined> {
    const events = await this.getCorrelatedEvents();
    return events.find(c => c.id === id || c.correlationId === id);
  }

  public async triggerManualCorrelation(eventIds: string[]): Promise<CorrelatedEvent> {
    const allFindings = await this.getAllFindings();
    const matchedFindings = allFindings.filter(f => eventIds.includes(f.id) || eventIds.includes(f.eventId));

    const findingsToCorrelate = matchedFindings.length >= 2 ? matchedFindings : allFindings.slice(0, 2);
    const correlated = CorrelationEngine.correlate(findingsToCorrelate, this.config);

    if (correlated.length > 0) {
      const top = correlated[0];
      this.cachedCorrelations.unshift(top);
      this.notify();
      return top;
    }

    // Fallback manual representation
    const fallbackId = `CORR-2026-${Math.floor(Math.random() * 900 + 100)}`;
    const manualEvent: CorrelatedEvent = {
      id: fallbackId,
      correlationId: fallbackId,
      createdAt: new Date().toISOString(),
      startTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
      endTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
      duration: '0s',
      findingIds: findingsToCorrelate.map(f => f.id),
      eventIds,
      eventsCount: eventIds.length,
      participatingAgents: Array.from(new Set(findingsToCorrelate.map(f => f.agentId))),
      sources: ['Manual Analyst Submission'],
      sourceIps: Array.from(new Set(findingsToCorrelate.map(f => f.sourceIp).filter((ip): ip is string => Boolean(ip)))),
      destinationIps: [],
      hosts: Array.from(new Set(findingsToCorrelate.map(f => f.host).filter((h): h is string => Boolean(h)))),
      users: Array.from(new Set(findingsToCorrelate.map(f => f.username).filter((u): u is string => Boolean(u)))),
      eventTypes: findingsToCorrelate.map(f => f.eventType),
      threatTypes: findingsToCorrelate.map(f => f.threatType),
      correlationStrength: 'MEDIUM',
      correlationConfidence: 0.75,
      confidence: 75,
      severity: 'MEDIUM',
      title: 'Manual Analyst Correlated Group',
      attackPattern: 'Custom Correlated Threat Chain',
      summary: `Manual multi-event correlation initiated across ${eventIds.length} flagged events.`,
      description: `Manual multi-event correlation initiated across ${eventIds.length} flagged events.`,
      evidence: ['Manual analyst selection'],
      indicators: [],
      explanation: 'Analyst manually selected findings to correlate into a unified review cluster.',
      status: 'CORRELATED',
      agentContributions: {
        network: 'Correlated anomalous network indicators',
        system: 'Correlated anomalous host execution logs'
      }
    };

    this.cachedCorrelations.unshift(manualEvent);
    this.notify();
    return manualEvent;
  }

  public async escalateToIncident(correlationId: string): Promise<boolean> {
    const item = this.cachedCorrelations.find(c => c.id === correlationId || c.correlationId === correlationId);
    if (item) {
      item.status = 'ESCALATED';
      await this.createIncidentFromCorrelation(item);
      this.notify();
      return true;
    }
    return false;
  }

  public async createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident> {
    return incidentService.createIncidentFromCorrelation(correlatedEvent);
  }

  public async getMetrics(): Promise<CorrelationMetrics> {
    const events = await this.getCorrelatedEvents();
    const findings = await this.getAllFindings();

    const crossAgentCount = events.filter(e => (e.participatingAgents?.length || 0) >= 2).length;
    const highStrengthCount = events.filter(e => e.correlationStrength === 'HIGH').length;

    const sourceIps = new Set<string>();
    const hosts = new Set<string>();
    const users = new Set<string>();

    for (const e of events) {
      (e.sourceIps || []).forEach(ip => sourceIps.add(ip));
      (e.hosts || []).forEach(h => hosts.add(h));
      (e.users || []).forEach(u => users.add(u));
    }

    return {
      totalFindings: findings.length,
      correlatedEventsCount: events.length,
      crossAgentCorrelationsCount: crossAgentCount,
      highStrengthCorrelationsCount: highStrengthCount,
      uniqueSourceIpsCount: sourceIps.size,
      affectedHostsCount: hosts.size,
      affectedUsersCount: users.size,
      engineStatus: 'READY',
      dataSource: this.isRealDataActive() ? 'UPLOADED_DATA' : 'DEMO_DATA'
    };
  }

  /**
   * Internal pipeline refresher
   */
  private async refreshCorrelation(): Promise<void> {
    this.isInitialized = true;

    // Check if user has explicitly pinned a demo scenario
    if (this.activeScenarioId && CORRELATION_DEMO_SCENARIOS[this.activeScenarioId]) {
      this.cachedFindings = [...CORRELATION_DEMO_SCENARIOS[this.activeScenarioId].findings];
      this.cachedCorrelations = CorrelationEngine.correlate(this.cachedFindings, this.config);
      this.notify();
      return;
    }

    // Check if real data exists in logRepository
    const hasReal = logRepository.hasRealData();

    if (hasReal) {
      const [netAnalysis, sysAnalysis, appAnalysis] = await Promise.all([
        networkAgentService.getAnalysis(),
        systemAgentService.getAnalysis(),
        applicationAgentService.getAnalysis()
      ]);

      const allAgentResults = [
        ...netAnalysis.results,
        ...sysAnalysis.results,
        ...appAnalysis.results
      ];

      this.cachedFindings = CorrelationNormalizer.normalizeBatch(allAgentResults);
      this.cachedCorrelations = CorrelationEngine.correlate(this.cachedFindings, this.config);
    } else {
      // Default to DEMO_1 scenario for rich academic showcase
      this.cachedFindings = [...CORRELATION_DEMO_SCENARIOS.DEMO_1.findings];
      this.cachedCorrelations = CorrelationEngine.correlate(this.cachedFindings, this.config);
    }

    this.notify();
  }
}

export const correlationService: ICorrelationService = new CorrelationServiceImpl();
