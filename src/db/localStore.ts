import fs from 'fs';
import path from 'path';

export interface LocalDbData {
  rawEvents: any[];
  securityFindings: any[];
  detections: any[];
  correlations: any[];
  riskAssessments: any[];
  alerts: any[];
  incidents: any[];
  incidentHistory: any[];
  auditLogs: any[];
  reports: any[];
  models: any[];
}

const DEFAULT_DATA: LocalDbData = {
  rawEvents: [],
  securityFindings: [],
  detections: [],
  correlations: [],
  riskAssessments: [],
  alerts: [],
  incidents: [],
  incidentHistory: [],
  auditLogs: [],
  reports: [],
  models: []
};

class LocalStore {
  private filePath: string;
  private data: LocalDbData;
  private initialized = false;

  constructor() {
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
      } catch (err) {
        console.warn('[LocalStore] Could not create data directory:', err);
      }
    }
    this.filePath = path.join(dataDir, 'local_db.json');
    this.data = { ...DEFAULT_DATA };
    this.load();
  }

  private load(): void {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        this.data = { ...DEFAULT_DATA, ...parsed };
      } else {
        this.save();
      }
      this.initialized = true;
    } catch (err) {
      console.warn('[LocalStore] Error reading store, initializing with default data:', err);
      this.data = { ...DEFAULT_DATA };
    }
  }

  private save(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('[LocalStore] Error saving store:', err);
    }
  }

  public getData(): LocalDbData {
    return this.data;
  }

  // Raw Events
  public insertRawEvent(event: any): any {
    const existing = this.data.rawEvents.find((e) => e.contentHash === event.contentHash);
    if (existing) return existing;
    const record = {
      ...event,
      id: event.id || `EVT-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.rawEvents.unshift(record);
    this.save();
    return record;
  }

  public listRawEvents(limit = 50): any[] {
    return this.data.rawEvents.slice(0, limit);
  }

  public listEvents(limit = 50): any[] {
    return this.listRawEvents(limit);
  }

  public getRawEventById(id: string): any | null {
    return this.data.rawEvents.find((e) => e.id === id) || null;
  }

  public findRawEventByHash(contentHash: string): any | null {
    return this.data.rawEvents.find((e) => e.contentHash === contentHash) || null;
  }

  public getEventById(id: string): any | null {
    return this.getRawEventById(id);
  }

  // Findings
  public insertFinding(finding: any): any {
    const record = {
      ...finding,
      id: finding.id || `FIND-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.securityFindings.unshift(record);
    this.save();
    return record;
  }

  public listFindings(limit = 50): any[] {
    return this.data.securityFindings.slice(0, limit);
  }

  // Detections
  public insertDetection(detection: any): any {
    const record = {
      ...detection,
      id: detection.id || `DET-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.detections.unshift(record);
    this.save();
    return record;
  }

  public listDetections(limit = 50): any[] {
    return this.data.detections.slice(0, limit);
  }

  // Correlations
  public insertCorrelation(correlation: any): any {
    const record = {
      ...correlation,
      id: correlation.id || `CORR-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.correlations.unshift(record);
    this.save();
    return record;
  }

  public listCorrelations(limit = 50): any[] {
    return this.data.correlations.slice(0, limit);
  }

  // Risk Assessments
  public insertRiskAssessment(assessment: any): any {
    const record = {
      ...assessment,
      id: assessment.id || `RISK-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.riskAssessments.unshift(record);
    this.save();
    return record;
  }

  public listRiskAssessments(limit = 50): any[] {
    return this.data.riskAssessments.slice(0, limit);
  }

  // Alerts
  public insertAlert(alert: any): any {
    const record = {
      ...alert,
      id: alert.id || `ALT-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      status: alert.status || 'NEW',
      createdAt: new Date().toISOString()
    };
    this.data.alerts.unshift(record);
    this.save();
    return record;
  }

  public listAlerts(limit = 50): any[] {
    return this.data.alerts.slice(0, limit);
  }

  public updateAlertStatus(id: string, status: string, notes?: string): any | null {
    const alert = this.data.alerts.find((a) => a.id === id);
    if (!alert) return null;
    alert.status = status;
    if (notes) alert.notes = notes;
    alert.updatedAt = new Date().toISOString();
    this.save();
    return alert;
  }

  // Incidents
  public insertIncident(incident: any): any {
    const incId = incident.incidentId || incident.id || `INC-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const record = {
      ...incident,
      id: incId,
      incidentId: incId,
      status: incident.status || 'NEW',
      createdAt: new Date().toISOString()
    };
    this.data.incidents.unshift(record);
    this.save();
    return record;
  }

  public listIncidents(limit = 50): any[] {
    return this.data.incidents.slice(0, limit);
  }

  public getIncidentById(id: string): any | null {
    return this.data.incidents.find((inc) => inc.id === id || inc.incidentId === id) || null;
  }

  public updateIncidentStatus(id: string, status: string, notes?: string, changedBy = 'system'): any | null {
    const incident = this.data.incidents.find((inc) => inc.id === id || inc.incidentId === id);
    if (!incident) return null;
    const oldStatus = incident.status;
    incident.status = status;
    incident.updatedAt = new Date().toISOString();
    if (notes) incident.notes = notes;

    this.data.incidentHistory.unshift({
      id: `INCH-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      incidentId: id,
      changedBy,
      changeType: 'STATUS_UPDATE',
      previousState: { status: oldStatus },
      newState: { status },
      changeReason: notes,
      timestamp: new Date().toISOString()
    });

    this.save();
    return incident;
  }

  public addInvestigationNote(id: string, note: any): any | null {
    const incident = this.data.incidents.find((inc) => inc.id === id || inc.incidentId === id);
    if (!incident) return null;
    if (!incident.investigationNotes) {
      incident.investigationNotes = [];
    }
    incident.investigationNotes.push(note);
    incident.updatedAt = new Date().toISOString();
    this.save();
    return incident;
  }

  // Audit Logs
  public insertAuditLog(log: any): any {
    const record = {
      ...log,
      id: log.id || `AUD-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      createdAt: new Date().toISOString()
    };
    this.data.auditLogs.unshift(record);
    this.save();
    return record;
  }

  public listAuditLogs(limit = 50): any[] {
    return this.data.auditLogs.slice(0, limit);
  }

  // Reports
  public insertReport(report: any): any {
    const record = {
      ...report,
      id: report.id || `REP-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      generatedAt: new Date().toISOString()
    };
    this.data.reports.unshift(record);
    this.save();
    return record;
  }

  public getReports(limit = 50): any[] {
    return this.data.reports.slice(0, limit);
  }

  // Models
  public upsertModelRegistry(model: any): any {
    const idx = this.data.models.findIndex((m) => m.id === model.id);
    const record = {
      ...model,
      updatedAt: new Date().toISOString()
    };
    if (idx >= 0) {
      this.data.models[idx] = { ...this.data.models[idx], ...record };
    } else {
      record.createdAt = new Date().toISOString();
      this.data.models.unshift(record);
    }
    this.save();
    return record;
  }

  public getRegisteredModels(): any[] {
    return this.data.models;
  }

  public upsertModel(model: any): any {
    return this.upsertModelRegistry(model);
  }

  public listModels(): any[] {
    return this.getRegisteredModels();
  }

  // Aggregated stats helper
  public getStats(): {
    totalEvents: number;
    threatsDetected: number;
    criticalThreats: number;
    highThreats: number;
    mediumThreats: number;
    lowThreats: number;
    activeIncidents: number;
    totalAlerts: number;
  } {
    const totalEvents = this.data.rawEvents.length;
    const criticalThreats = this.data.incidents.filter((i) => i.severity === 'CRITICAL').length;
    const highThreats = this.data.incidents.filter((i) => i.severity === 'HIGH').length;
    const mediumThreats = this.data.incidents.filter((i) => i.severity === 'MEDIUM').length;
    const lowThreats = this.data.incidents.filter((i) => i.severity === 'LOW').length;
    const activeIncidents = this.data.incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED').length;
    const threatsDetected = this.data.incidents.length;
    const totalAlerts = this.data.alerts.length;

    return {
      totalEvents,
      threatsDetected,
      criticalThreats,
      highThreats,
      mediumThreats,
      lowThreats,
      activeIncidents,
      totalAlerts
    };
  }
}

export const localStore = new LocalStore();
