import { Incident, IncidentStatus, CorrelatedEvent, IncidentLifecycleStatus } from '../types';
import { incidentManager } from './alertIncident/incidentManager';

export interface IIncidentService {
  getIncidents(): Promise<Incident[]>;
  getIncidentById(incidentId: string): Promise<Incident | undefined>;
  updateIncidentStatus(incidentId: string, status: IncidentStatus, resolutionNote?: string): Promise<boolean>;
  assignIncident(incidentId: string, assignee: string): Promise<boolean>;
  addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean>;
  createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident>;
}

class IncidentServiceImpl implements IIncidentService {
  async getIncidents(): Promise<Incident[]> {
    return incidentManager.getIncidents();
  }

  async getIncidentById(incidentId: string): Promise<Incident | undefined> {
    return incidentManager.getIncidentById(incidentId);
  }

  async updateIncidentStatus(incidentId: string, status: IncidentStatus, resolutionNote?: string): Promise<boolean> {
    return incidentManager.updateIncidentStatus(incidentId, status as IncidentLifecycleStatus, resolutionNote);
  }

  async assignIncident(incidentId: string, assignee: string): Promise<boolean> {
    return incidentManager.assignIncident(incidentId, assignee);
  }

  async addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean> {
    return incidentManager.addAnalystNote(incidentId, note, author);
  }

  async createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident> {
    return incidentManager.createIncidentFromCorrelation(correlatedEvent);
  }
}

export const incidentService: IIncidentService = new IncidentServiceImpl();
export { incidentManager };

