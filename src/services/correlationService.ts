import { CorrelatedEvent } from '../types';
import { INITIAL_CORRELATIONS } from './mockData';

export interface ICorrelationService {
  getCorrelatedEvents(): Promise<CorrelatedEvent[]>;
  getCorrelationById(id: string): Promise<CorrelatedEvent | undefined>;
  triggerManualCorrelation(eventIds: string[]): Promise<CorrelatedEvent>;
  escalateToIncident(correlationId: string): Promise<boolean>;
}

class CorrelationServiceImpl implements ICorrelationService {
  private correlations: CorrelatedEvent[] = [...INITIAL_CORRELATIONS];

  async getCorrelatedEvents(): Promise<CorrelatedEvent[]> {
    return [...this.correlations];
  }

  async getCorrelationById(id: string): Promise<CorrelatedEvent | undefined> {
    return this.correlations.find(c => c.correlationId === id);
  }

  async triggerManualCorrelation(eventIds: string[]): Promise<CorrelatedEvent> {
    const newCorrelation: CorrelatedEvent = {
      correlationId: `CORR-2026-${Math.floor(Math.random() * 900 + 100)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      eventIds,
      eventsCount: eventIds.length,
      sources: ['Manual Analyst Submission', 'Aggregated Pipeline'],
      attackPattern: 'Custom Correlated Threat Chain',
      confidence: 91.5,
      severity: 'HIGH',
      status: 'CORRELATED',
      description: `Manual multi-event correlation executed across ${eventIds.length} flagged events.`,
      agentContributions: {
        network: 'Correlated anomalous network indicators',
        system: 'Correlated anomalous host execution logs'
      }
    };
    this.correlations.unshift(newCorrelation);
    return newCorrelation;
  }

  async escalateToIncident(correlationId: string): Promise<boolean> {
    const item = this.correlations.find(c => c.correlationId === correlationId);
    if (item) {
      item.status = 'ESCALATED';
      return true;
    }
    return false;
  }
}

export const correlationService: ICorrelationService = new CorrelationServiceImpl();
