import { Incident, IncidentStatus, CorrelatedEvent } from '../types';
import { INITIAL_INCIDENTS } from './mockData';

export interface IIncidentService {
  getIncidents(): Promise<Incident[]>;
  getIncidentById(incidentId: string): Promise<Incident | undefined>;
  updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<boolean>;
  assignIncident(incidentId: string, assignee: string): Promise<boolean>;
  addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean>;
  createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident>;
}

class IncidentServiceImpl implements IIncidentService {
  private incidents: Incident[] = [...INITIAL_INCIDENTS];

  async getIncidents(): Promise<Incident[]> {
    return [...this.incidents];
  }

  async getIncidentById(incidentId: string): Promise<Incident | undefined> {
    return this.incidents.find(i => i.incidentId === incidentId);
  }

  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<boolean> {
    const inc = this.incidents.find(i => i.incidentId === incidentId);
    if (inc) {
      inc.status = status;
      inc.timeline.push({
        time: new Date().toLocaleTimeString(),
        description: `Incident status transitioned to ${status}`,
        actor: 'Security Analyst'
      });
      return true;
    }
    return false;
  }

  async assignIncident(incidentId: string, assignee: string): Promise<boolean> {
    const inc = this.incidents.find(i => i.incidentId === incidentId);
    if (inc) {
      inc.assignedTo = assignee;
      inc.timeline.push({
        time: new Date().toLocaleTimeString(),
        description: `Assigned to ${assignee}`,
        actor: 'SOC Dispatch'
      });
      return true;
    }
    return false;
  }

  async addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean> {
    const inc = this.incidents.find(i => i.incidentId === incidentId);
    if (inc) {
      inc.timeline.push({
        time: new Date().toLocaleTimeString(),
        description: note,
        actor: author
      });
      return true;
    }
    return false;
  }

  async createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident> {
    const existing = this.incidents.find(i => i.incidentId === `INC-${correlatedEvent.correlationId}`);
    if (existing) {
      return existing;
    }

    const newIncident: Incident = {
      incidentId: `INC-${correlatedEvent.correlationId}`,
      detectedAt: correlatedEvent.startTime || new Date().toISOString(),
      threatType: correlatedEvent.title || correlatedEvent.attackPattern,
      severity: correlatedEvent.severity,
      riskScore: Math.round((correlatedEvent.correlationConfidence || 0.8) * 100),
      affectedSource: correlatedEvent.sources.join(', ') || 'Correlated Multi-Agent Network Assets',
      status: 'INVESTIGATING',
      assignedTo: 'SOC Correlation Engine',
      summary: correlatedEvent.summary || correlatedEvent.description,
      timeline: (correlatedEvent.sequence || []).map(seq => ({
        time: seq.timestamp,
        description: `[${seq.agentId}] ${seq.description}`,
        actor: seq.agentId
      })),
      mitreTactic: 'Initial Access & Lateral Movement',
      mitreTechnique: correlatedEvent.mitreTechniqueId || 'T1046 / T1190 / T1068',
      containmentRecommendation: 'Synthesized multi-stage incident created from correlation engine. Review linked telemetry findings.'
    };

    this.incidents.unshift(newIncident);
    return newIncident;
  }
}

export const incidentService: IIncidentService = new IncidentServiceImpl();
