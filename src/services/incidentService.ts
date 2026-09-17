import { Incident, IncidentStatus, CorrelatedEvent, IncidentLifecycleStatus } from '../types';
import { incidentManager } from './alertIncident/incidentManager';
import { localApiClient } from './apiClient';

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
    try {
      const dbIncs = await localApiClient.getIncidents(100);
      if (Array.isArray(dbIncs) && dbIncs.length > 0) {
        return dbIncs.map((row: any) => ({
          id: row.incidentId || row.id,
          incidentId: row.incidentId || row.id,
          title: row.title,
          summary: row.description,
          description: row.description,
          threatType: row.title,
          severity: row.severity,
          priority: row.priority,
          status: row.status as IncidentLifecycleStatus,
          riskScore: row.riskScore,
          assignee: row.assignee,
          primaryIp: row.primaryIp,
          affectedHost: row.affectedHost,
          alertIds: row.alertIds || [],
          correlationIds: row.correlationIds || [],
          mitreTechniques: row.mitreTechniques || [],
          investigationNotes: row.investigationNotes || [],
          timeline: row.timeline || [],
          detectedAt: row.createdAt,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
          history: row.history || []
        })) as unknown as Incident[];
      }
    } catch {
      // Fallback to in-memory incidentManager
    }
    return incidentManager.getIncidents();
  }

  async getIncidentById(incidentId: string): Promise<Incident | undefined> {
    try {
      const row = await localApiClient.getIncidentById(incidentId);
      if (row) {
        return {
          id: row.incidentId || row.id,
          incidentId: row.incidentId || row.id,
          title: row.title,
          summary: row.description,
          description: row.description,
          threatType: row.title,
          severity: row.severity,
          priority: row.priority,
          status: row.status as IncidentLifecycleStatus,
          riskScore: row.riskScore,
          assignee: row.assignee,
          primaryIp: row.primaryIp,
          affectedHost: row.affectedHost,
          alertIds: row.alertIds || [],
          correlationIds: row.correlationIds || [],
          mitreTechniques: row.mitreTechniques || [],
          investigationNotes: row.investigationNotes || [],
          timeline: row.timeline || [],
          detectedAt: row.createdAt,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
          history: row.history || []
        } as unknown as Incident;
      }
    } catch {
      // Fallback
    }
    return incidentManager.getIncidentById(incidentId);
  }

  async updateIncidentStatus(incidentId: string, status: IncidentStatus, resolutionNote?: string): Promise<boolean> {
    // 1. Persist to PostgreSQL with state transition history & audit record
    try {
      await localApiClient.updateIncident(incidentId, {
        status,
        resolutionSummary: resolutionNote,
        actor: 'SOC Analyst',
        reason: resolutionNote
      });
    } catch (err) {
      console.warn('[IncidentService] Failed persisting status to PostgreSQL:', err);
    }
    // 2. Keep in-memory manager synchronized
    return incidentManager.updateIncidentStatus(incidentId, status as IncidentLifecycleStatus, resolutionNote);
  }

  async assignIncident(incidentId: string, assignee: string): Promise<boolean> {
    try {
      await localApiClient.updateIncident(incidentId, {
        assignee,
        actor: 'SOC Lead',
        reason: `Reassigned to ${assignee}`
      });
    } catch (err) {
      console.warn('[IncidentService] Failed updating assignee in PostgreSQL:', err);
    }
    return incidentManager.assignIncident(incidentId, assignee);
  }

  async addTimelineNote(incidentId: string, note: string, author: string): Promise<boolean> {
    try {
      await localApiClient.updateIncident(incidentId, {
        newNote: { author, note },
        actor: author
      });
    } catch (err) {
      console.warn('[IncidentService] Failed saving investigation note to PostgreSQL:', err);
    }
    return incidentManager.addAnalystNote(incidentId, note, author);
  }

  async createIncidentFromCorrelation(correlatedEvent: CorrelatedEvent): Promise<Incident> {
    const inc = await incidentManager.createIncidentFromCorrelation(correlatedEvent);
    // Persist new incident to PostgreSQL
    try {
      await localApiClient.createIncident({
        incidentId: inc.incidentId,
        title: inc.threatType,
        description: inc.summary,
        severity: inc.severity,
        priority: inc.priority || 'P2',
        status: inc.status,
        riskScore: inc.riskScore,
        assignee: inc.assignedTo || 'Unassigned',
        primaryIp: (inc.affectedEntities && inc.affectedEntities[0]) || '192.168.1.100',
        affectedHost: inc.affectedSource || 'server01',
        alertIds: inc.alertIds || [],
        correlationIds: [correlatedEvent.id],
        mitreTechniques: inc.mitreTechnique ? [inc.mitreTechnique] : [],
        investigationNotes: inc.analystNotes || [],
        timeline: inc.timeline || []
      });
    } catch (err) {
      console.warn('[IncidentService] Failed creating incident in PostgreSQL:', err);
    }
    return inc;
  }
}

export const incidentService: IIncidentService = new IncidentServiceImpl();
export { incidentManager };
