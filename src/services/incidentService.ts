import { Incident, IncidentStatus } from '../types';
import { INITIAL_INCIDENTS } from './mockData';

export interface IIncidentService {
  getIncidents(): Promise<Incident[]>;
  getIncidentById(incidentId: string): Promise<Incident | undefined>;
  updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<boolean>;
  assignIncident(incidentId: string, assignee: string): Promise<boolean>;
  addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean>;
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
}

export const incidentService: IIncidentService = new IncidentServiceImpl();
