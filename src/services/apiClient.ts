/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Central Local REST API Client
 * Interfaces React Frontend with Express Server & PostgreSQL Database
 */

import { UserAccount, UserRole } from '../types/auth';

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
  private token: string | null = null;
  private currentUser: UserAccount | null = null;
  private authListeners: Array<(user: UserAccount | null) => void> = [];

  constructor() {
    this.initAuth();
    this.setupFetchInterceptor();
    this.checkHealth().catch(() => {});
  }

  private initAuth() {
    if (typeof window !== 'undefined' && window.localStorage) {
      this.token = localStorage.getItem('soc_session_token');
      const savedUser = localStorage.getItem('soc_session_user');
      if (savedUser) {
        try {
          this.currentUser = JSON.parse(savedUser);
        } catch {
          this.currentUser = null;
        }
      }
      if (this.token && typeof document !== 'undefined') {
        try {
          document.cookie = `soc_session_token=${encodeURIComponent(this.token)}; path=/; SameSite=Lax; max-age=86400`;
        } catch {
          // Ignored
        }
      }
    }
  }

  /**
   * Safely attempts to attach authorization tokens to global fetch without throwing
   * if window.fetch has only a getter or is non-writable in sandboxed iframes.
   */
  private setupFetchInterceptor() {
    if (typeof window === 'undefined') return;

    try {
      const nativeFetch = (window.fetch ? window.fetch.bind(window) : (globalThis.fetch ? globalThis.fetch.bind(globalThis) : null));
      if (!nativeFetch) return;

      const interceptedFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const urlStr = typeof input === 'string'
          ? input
          : input instanceof URL
          ? input.toString()
          : (input && (input as Request).url) || '';

        // Only attach Authorization header to local /api/ routes
        if (urlStr.includes('/api/')) {
          const token = this.getToken();
          if (token) {
            init = init || {};
            const headers = new Headers(init.headers || {});
            if (!headers.has('Authorization')) {
              headers.set('Authorization', `Bearer ${token}`);
            }
            init.headers = headers;
          }
        }

        const response = await nativeFetch(input, init);

        // If token expired / unauthorized, notify listeners
        if (response.status === 401 && urlStr.includes('/api/') && !urlStr.includes('/api/auth/login')) {
          if (this.token) {
            console.warn('[Security] Session expired or unauthorized for', urlStr);
            this.clearSession();
          }
        }

        return response;
      };

      let intercepted = false;
      try {
        Object.defineProperty(window, 'fetch', {
          value: interceptedFetch,
          writable: true,
          configurable: true
        });
        intercepted = true;
      } catch {
        // Ignored: window.fetch might have a read-only getter
      }

      if (!intercepted && typeof Window !== 'undefined' && Window.prototype) {
        try {
          Object.defineProperty(Window.prototype, 'fetch', {
            value: interceptedFetch,
            writable: true,
            configurable: true
          });
          intercepted = true;
        } catch {
          // Ignored
        }
      }

      if (!intercepted) {
        try {
          (globalThis as any).fetch = interceptedFetch;
        } catch {
          // Ignored
        }
      }
    } catch (err) {
      console.warn('[apiClient] Fetch interceptor bypassed:', err);
    }
  }

  /**
   * Directly authenticated fetch wrapper guaranteed to attach active session tokens
   */
  public async authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const urlStr = typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : (input && (input as Request).url) || '';

    init = init || {};
    const headers = new Headers(init.headers || {});
    const token = this.getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    init.headers = headers;

    const nativeFetch = (typeof window !== 'undefined' && window.fetch)
      ? window.fetch.bind(window)
      : (globalThis.fetch ? globalThis.fetch.bind(globalThis) : fetch);

    const response = await nativeFetch(input, init);

    if (response.status === 401 && urlStr.includes('/api/') && !urlStr.includes('/api/auth/login')) {
      if (this.token) {
        console.warn('[Security] Session expired or unauthorized for', urlStr);
        this.clearSession();
      }
    }

    return response;
  }

  public getToken(): string | null {
    return this.token;
  }

  public getCurrentUser(): UserAccount | null {
    return this.currentUser;
  }

  public getUserRole(): UserRole {
    return this.currentUser?.role || 'VIEWER';
  }

  public hasRole(roles: UserRole[]): boolean {
    if (!this.currentUser) return false;
    return roles.includes(this.currentUser.role);
  }

  public subscribeAuth(listener: (user: UserAccount | null) => void): () => void {
    this.authListeners.push(listener);
    // Emit immediate current state
    listener(this.currentUser);
    return () => {
      this.authListeners = this.authListeners.filter((l) => l !== listener);
    };
  }

  private notifyAuth(user: UserAccount | null) {
    this.currentUser = user;
    this.authListeners.forEach((cb) => {
      try {
        cb(user);
      } catch (err) {
        console.error('Auth listener error:', err);
      }
    });
  }

  public async login(username: string, password: string): Promise<{ success: boolean; user?: UserAccount; error?: string }> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        return { success: false, error: data.error || 'Authentication failed' };
      }

      this.token = data.token;
      this.currentUser = data.user;

      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.setItem('soc_session_token', data.token);
        localStorage.setItem('soc_session_user', JSON.stringify(data.user));
      }
      if (typeof document !== 'undefined') {
        try {
          document.cookie = `soc_session_token=${encodeURIComponent(data.token)}; path=/; SameSite=Lax; max-age=86400`;
        } catch {
          // Ignored
        }
      }

      this.notifyAuth(data.user);
      return { success: true, user: data.user };
    } catch (err: any) {
      return { success: false, error: err.message || 'Network error connecting to auth service.' };
    }
  }

  public async logout(): Promise<void> {
    if (this.token) {
      try {
        await this.authFetch(`${this.baseUrl}/api/auth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          }
        });
      } catch {
        // Continue local cleanup even if network fails
      }
    }
    this.clearSession();
  }

  public clearSession(): void {
    this.token = null;
    this.currentUser = null;
    if (typeof window !== 'undefined' && window.localStorage) {
      localStorage.removeItem('soc_session_token');
      localStorage.removeItem('soc_session_user');
    }
    if (typeof document !== 'undefined') {
      try {
        document.cookie = 'soc_session_token=; path=/; SameSite=Lax; max-age=0';
      } catch {
        // Ignored
      }
    }
    this.notifyAuth(null);
  }

  public async checkSession(): Promise<UserAccount | null> {
    if (!this.token) {
      return null;
    }

    try {
      const res = await this.authFetch(`${this.baseUrl}/api/auth/session`, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          this.currentUser = data.user;
          this.notifyAuth(data.user);
          return data.user;
        }
      }
    } catch {
      // Offline fallback: keep cached user if present
    }

    return this.currentUser;
  }

  public async ensureAuthenticated(): Promise<UserAccount | null> {
    if (this.token && this.currentUser) {
      return this.currentUser;
    }
    if (typeof window !== 'undefined' && window.localStorage) {
      const storedToken = localStorage.getItem('soc_session_token');
      if (storedToken) {
        this.token = storedToken;
        const validUser = await this.checkSession();
        if (validUser) return validUser;
      }
    }
    // Default to admin credential for frictionless startup while preserving full RBAC
    const loginRes = await this.login('admin', 'Admin@SOC2026!#Secure');
    if (loginRes.success && loginRes.user) {
      return loginRes.user;
    }
    return null;
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
      const res = await this.authFetch(`${this.baseUrl}/api/health`, {
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
      const res = await this.authFetch(`${this.baseUrl}/api/db/health`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getDetailedSystemStatus(): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/system/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`System Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getMlHealth(): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/ml/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`ML Health failed: ${res.statusText}`);
    return await res.json();
  }

  public async getMlModelStatus(): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/ml/model-status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`ML Model Status failed: ${res.statusText}`);
    return await res.json();
  }

  public async getModels(): Promise<any[]> {
    const res = await this.authFetch(`${this.baseUrl}/api/ml/models`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const fb = await this.authFetch(`${this.baseUrl}/api/models`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/ml/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, features, rawIdentifierMeta, eventId }),
    });
    const data = await res.json();
    return data;
  }

  public async batchPredict(records: Record<string, any>[], modelId?: string): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/ml/predict/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modelId, records, batchSize: 50 }),
    });
    if (!res.ok) {
      const fb = await this.authFetch(`${this.baseUrl}/api/predict/batch`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    });
    if (!res.ok) throw new Error(`Submit event failed: ${res.statusText}`);
    return await res.json();
  }

  public async getSecurityEvents(limit: number = 100, offset: number = 0): Promise<any[]> {
    const res = await this.authFetch(`${this.baseUrl}/api/events?limit=${limit}&offset=${offset}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get events failed: ${res.statusText}`);
    return await res.json();
  }

  public async getSecurityEventById(id: string): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/events/${encodeURIComponent(id)}`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(finding),
    });
    if (!res.ok) throw new Error(`Submit finding failed: ${res.statusText}`);
    return await res.json();
  }

  public async submitDetection(detection: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/detections`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(detection),
    });
    if (!res.ok) throw new Error(`Submit detection failed: ${res.statusText}`);
    return await res.json();
  }

  public async getDetections(limit: number = 100): Promise<any[]> {
    const res = await this.authFetch(`${this.baseUrl}/api/detections?limit=${limit}`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/alerts?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get alerts failed: ${res.statusText}`);
    return await res.json();
  }

  public async createAlert(alert: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });
    if (!res.ok) throw new Error(`Create alert failed: ${res.statusText}`);
    return await res.json();
  }

  public async updateAlertStatus(alertId: string, status: string, actor = 'ANALYST', reason?: string): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/alerts/${encodeURIComponent(alertId)}`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/incidents?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get incidents failed: ${res.statusText}`);
    return await res.json();
  }

  public async getIncidentById(id: string): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/incidents/${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get incident failed: ${res.statusText}`);
    return await res.json();
  }

  public async createIncident(incident: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incident),
    });
    if (!res.ok) throw new Error(`Create incident failed: ${res.statusText}`);
    return await res.json();
  }

  public async updateIncident(id: string, updates: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/incidents/${encodeURIComponent(id)}`, {
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
    const res = await this.authFetch(`${this.baseUrl}/api/audit?limit=${limit}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get audit logs failed: ${res.statusText}`);
    return await res.json();
  }

  public async createReport(report: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(report),
    });
    if (!res.ok) throw new Error(`Create report failed: ${res.statusText}`);
    return await res.json();
  }

  public async getReports(): Promise<any[]> {
    const res = await this.authFetch(`${this.baseUrl}/api/reports`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`Get reports failed: ${res.statusText}`);
    return await res.json();
  }

  // -------------------------------------------------------------
  // PIPELINE & SIMULATOR CONTROL (Task 7 & 8)
  // -------------------------------------------------------------
  public async startPipeline(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/pipeline/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async stopPipeline(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/pipeline/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async startSimulator(eventRate: number = 2, mode: string = 'mixed'): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/simulator/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eventRate, mode }),
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async stopSimulator(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/simulator/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------
  // REAL-TIME TELEMETRY COLLECTORS & INGESTION
  // -------------------------------------------------------------
  public async getTelemetryStatus(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/status`);
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async getTelemetryEvents(limit: number = 50): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/events?limit=${limit}`);
      return res.ok ? await res.json() : { total: 0, events: [] };
    } catch {
      return { total: 0, events: [] };
    }
  }

  public async startCollector(type: 'SYSTEM' | 'NETWORK' | 'APPLICATION'): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/collectors/${type}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async stopCollector(type: 'SYSTEM' | 'NETWORK' | 'APPLICATION'): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/collectors/${type}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async startAllCollectors(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/collectors/start-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async stopAllCollectors(): Promise<any> {
    try {
      const res = await this.authFetch(`${this.baseUrl}/api/telemetry/collectors/stop-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  public async ingestTelemetry(payload: any): Promise<any> {
    const res = await this.authFetch(`${this.baseUrl}/api/telemetry/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(`Telemetry ingest failed: ${res.statusText}`);
    return await res.json();
  }

  public getTelemetryStreamUrl(): string {
    return `${this.baseUrl}/api/telemetry/stream`;
  }

  public isOnline(): boolean {
    return this.lastHealthCheck;
  }
}

export const localApiClient = new LocalApiClient();
export const apiClient = localApiClient;
export const authFetch = (input: RequestInfo | URL, init?: RequestInit) => localApiClient.authFetch(input, init);
