/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Central Local REST API Client
 * Prompt 12 — 100% Free / Local / No Paid External API
 */

const API_BASE_URL = ((import.meta as any).env?.VITE_API_BASE_URL as string) || 'http://localhost:8000';

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

class LocalApiClient {
  private baseUrl: string = API_BASE_URL;
  private lastHealthCheck: boolean = false;
  private listeners: Array<(isOnline: boolean) => void> = [];

  constructor() {
    // Initial silent check
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
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notify(isOnline: boolean) {
    if (this.lastHealthCheck !== isOnline) {
      this.lastHealthCheck = isOnline;
      this.listeners.forEach(cb => {
        try { cb(isOnline); } catch (e) { console.error(e); }
      });
    }
  }

  public async checkHealth(): Promise<BackendStatusResult> {
    try {
      const res = await fetch(`${this.baseUrl}/api/health`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(2500)
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

  public async getSystemStatus(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getModels(): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/models`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Get models failed: ${res.statusText}`);
    return await res.json();
  }

  public async predict(features: Record<string, any>, modelId?: string, rawIdentifierMeta?: Record<string, any>): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, features, rawIdentifierMeta })
    });
    const data = await res.json();
    if (!res.ok) {
      return data; // May contain status: "MODEL_NOT_AVAILABLE"
    }
    return data;
  }

  public async batchPredict(records: Record<string, any>[], modelId?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/predict/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, records, batchSize: 50 })
    });
    if (!res.ok) throw new Error(`Batch predict failed: ${res.statusText}`);
    return await res.json();
  }

  public async submitSecurityEvent(event: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/security-events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    });
    if (!res.ok) throw new Error(`Submit event failed: ${res.statusText}`);
    return await res.json();
  }

  public async getSecurityEvents(limit: number = 100): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/security-events?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Get events failed: ${res.statusText}`);
    return await res.json();
  }

  public async getAlerts(limit: number = 50): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/alerts?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Get alerts failed: ${res.statusText}`);
    return await res.json();
  }

  public async getIncidents(limit: number = 50): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/incidents?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Get incidents failed: ${res.statusText}`);
    return await res.json();
  }

  public async getPipelineStatus(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/pipeline/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Get pipeline status failed: ${res.statusText}`);
    return await res.json();
  }

  public async startPipeline(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/pipeline/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Start pipeline failed: ${res.statusText}`);
    return await res.json();
  }

  public async stopPipeline(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/pipeline/stop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Stop pipeline failed: ${res.statusText}`);
    return await res.json();
  }

  public async startSimulator(eventRate: number = 2, mode: string = 'mixed'): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/simulator/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ eventRate, mode })
    });
    if (!res.ok) throw new Error(`Start simulator failed: ${res.statusText}`);
    return await res.json();
  }

  public async stopSimulator(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/simulator/stop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`Stop simulator failed: ${res.statusText}`);
    return await res.json();
  }

  public isOnline(): boolean {
    return this.lastHealthCheck;
  }
}

export const localApiClient = new LocalApiClient();
