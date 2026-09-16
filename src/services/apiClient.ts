/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Central Local REST API Client
 * Interfaces React Frontend with Express Server & PostgreSQL Database
 */

const API_BASE_URL = '';

export interface HealthResponse {
  status: string;
  service: string;
  timestamp: string;
  version: string;
  offlineFirst: boolean;
  paidApisUsed: boolean;
}

export interface BackendStatusResult {
  isOnline: boolean;
  url: string;
  data?: any;
  error?: string;
}

export interface DatabaseHealthResult {
  status: 'DATABASE_CONNECTED' | 'DATABASE_UNAVAILABLE';
  database: string;
  error?: string;
  timestamp: string;
}

class LocalApiClient {
  private baseUrl: string = API_BASE_URL;
  private lastHealthCheck: boolean = false;
  private listeners: Array<(isOnline: boolean) => void> = [];

  constructor() {
    this.checkHealth().catch(() => {});
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setBaseUrl(url: string) {
    this.baseUrl = url;
    this.checkHealth();
  }

  public subscribe(listener: (isOnline: boolean) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify(isOnline: boolean) {
    if (this.lastHealthCheck !== isOnline) {
      this.lastHealthCheck = isOnline;
      this.listeners.forEach((cb) => {
        try {
          cb(isOnline);
        } catch (e) {
          console.error(e);
        }
      });
    }
  }

  public async checkHealth(): Promise<BackendStatusResult> {
    try {
      const res = await fetch(`${this.baseUrl}/api/health`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(2500),
      });

      if (res.ok) {
        const data = await res.json();
        this.notify(true);
        return { isOnline: true, url: this.baseUrl, data };
      }
      this.notify(false);
      return { isOnline: false, url: this.baseUrl, error: `HTTP ${res.status}: ${res.statusText}` };
    } catch (err: any) {
      this.notify(false);
      return { isOnline: false, url: this.baseUrl, error: err?.message || 'Connection refused' };
    }
  }

  // -------------------------------------------------------------
  // DATABASE HEALTH & CONNECTIVITY (Task 13)
  // -------------------------------------------------------------
  public async getDatabaseHealth(): Promise<DatabaseHealthResult> {
    try {
      const res = await fetch(`${this.baseUrl}/api/db/health`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(3000),
      });
      const data = await res.json();
      return data;
    } catch (err: any) {
      return {
        status: 'DATABASE_UNAVAILABLE',
        database: 'PostgreSQL',
        error: err.message || 'Failed connecting to database API',
        timestamp: new Date().toISOString(),
      };
    }
  }

  public async getSystemStatus(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getMlHealth(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ml/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`ML Health failed: ${res.statusText}`);
    return await res.json();
  }

  public async getMlModelStatus(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ml/model-status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`ML Model Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getModels(): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/ml/models`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const fb = await fetch(`${this.baseUrl}/api/models`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!fb.ok) throw new Error(`Get models failed: ${res.statusText}`);
      return await fb.json();
    }
    return await res.json();
  }

  public async predict(
    features: Record<string, any>,
    modelId?: string,
    rawIdentifierMeta?: Record<string, any>,
    eventId?: string
  ): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ml/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, features, rawIdentifierMeta, eventId }),
    });
    const data = await res.json();
    return data;
  }

  public async batchPredict(records: Record<string, any>[], modelId?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ml/predict/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, records, batchSize: 50 }),
    });
    if (!res.ok) {
      const fb = await fetch(`${this.baseUrl}/api/predict/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ modelId, records, batchSize: 50 }),
      });
      if (!fb.ok) throw new Error(`Batch predict failed: ${res.statusText}`);
      return await fb.json();
    }
    return await res.json();
  }

  // -------------------------------------------------------------
  // POSTGRESQL DATABASE EVENT ENDPOINTS (Task 3 & 11)
  // -------------------------------------------------------------
  public async submitSecurityEvent(event: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    });
    if (!res.ok) throw new Error(`Submit event failed: ${res.statusText}`);
    return await res.json();
  }

  public async getSecurityEvents(limit: number = 100, offset: number = 0): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/events?limit=${limit}&offset=${offset}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get events failed: ${res.statusText}`);
    return await res.json();
  }

  public async getSecurityEventById(id: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/events/${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get event failed: ${res.statusText}`);
    return await res.json();
  }

  // -------------------------------------------------------------
  // POSTGRESQL AGENT FINDINGS & DETECTIONS (Task 4, 5, 11)
  // -------------------------------------------------------------
  public async submitFinding(finding: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(finding),
    });
    if (!res.ok) throw new Error(`Submit finding failed: ${res.statusText}`);
    return await res.json();
  }

  public async submitDetection(detection: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/detections`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(detection),
    });
    if (!res.ok) throw new Error(`Submit detection failed: ${res.statusText}`);
    return await res.json();
  }

  public async getDetections(limit: number = 100): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/detections?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get detections failed: ${res.statusText}`);
    return await res.json();
  }

  // -------------------------------------------------------------
  // POSTGRESQL ALERTS APIS (Task 8 & 11)
  // -------------------------------------------------------------
  public async getAlerts(limit: number = 50): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/alerts?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get alerts failed: ${res.statusText}`);
    return await res.json();
  }

  public async createAlert(alert: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });
    if (!res.ok) throw new Error(`Create alert failed: ${res.statusText}`);
    return await res.json();
  }

  public async updateAlertStatus(alertId: string, status: string, actor = 'ANALYST', reason?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/alerts/${encodeURIComponent(alertId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, actor, reason }),
    });
    if (!res.ok) throw new Error(`Update alert failed: ${res.statusText}`);
    return await res.json();
  }

  // -------------------------------------------------------------
  // POSTGRESQL INCIDENTS APIS (Task 9 & 11)
  // -------------------------------------------------------------
  public async getIncidents(limit: number = 50): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/incidents?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get incidents failed: ${res.statusText}`);
    return await res.json();
  }

  public async getIncidentById(id: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/incidents/${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get incident failed: ${res.statusText}`);
    return await res.json();
  }

  public async createIncident(incident: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incident),
    });
    if (!res.ok) throw new Error(`Create incident failed: ${res.statusText}`);
    return await res.json();
  }

  public async updateIncident(id: string, updates: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/incidents/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) throw new Error(`Update incident failed: ${res.statusText}`);
    return await res.json();
  }

  // -------------------------------------------------------------
  // POSTGRESQL AUDIT & REPORT APIS (Task 10 & 11)
  // -------------------------------------------------------------
  public async getAuditLogs(limit: number = 100): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/audit?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get audit logs failed: ${res.statusText}`);
    return await res.json();
  }

  public async createReport(report: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(report),
    });
    if (!res.ok) throw new Error(`Create report failed: ${res.statusText}`);
    return await res.json();
  }

  public async getReports(): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/reports`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get reports failed: ${res.statusText}`);
    return await res.json();
  }

  public isOnline(): boolean {
    return this.lastHealthCheck;
  }
}

export const localApiClient = new LocalApiClient();
