/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Real-Time Telemetry Streaming Service (Client-Side)
 * 
 * Features:
 * - Server-Sent Events (SSE) with HTTP keep-alive watchdog
 * - Exponential backoff reconnection with randomized jitter
 * - Connection timeout detection (25s heartbeat watchdog)
 * - Micro-batching & backpressure handling (50ms flush window)
 * - Strict monotonic event ordering tracking
 * - LRU duplicate event prevention (2,000 item capacity)
 * - Explicit Telemetry Status: LIVE, CONNECTING, DISCONNECTED, SIMULATION, ERROR
 * - Graceful offline mode with state caching and automatic re-sync
 */

import {
  NormalizedTelemetryEvent,
  TelemetryStreamStatus,
  TelemetryStreamEnvelope,
  StreamInitPayload,
  CollectorHealth
} from './telemetryTypes';

export interface TelemetryStreamMetrics {
  totalLiveEvents: number;
  totalSimulatedEvents: number;
  totalThreatsDetected: number;
  totalAlertsGenerated: number;
  totalIncidentsCreated: number;
  currentEps: number;
}

export type StatusChangeCallback = (status: TelemetryStreamStatus, details?: any) => void;
export type EventBatchCallback = (events: NormalizedTelemetryEvent[]) => void;
export type CompositeEventCallback = (composite: {
  event: NormalizedTelemetryEvent;
  isThreat: boolean;
  finding?: any;
  correlations?: any[];
  riskAssessment?: any;
  alert?: any;
  incident?: any;
  agentStatus?: any;
  metrics?: any;
}) => void;

class RealtimeTelemetryStream {
  private eventSource: EventSource | null = null;
  private status: TelemetryStreamStatus = 'DISCONNECTED';
  private lastStatusReason: string = '';
  private isConnecting: boolean = false;
  private shouldConnect: boolean = true;

  // Monotonic sequence and deduplication
  private lastSequence: number = 0;
  private seenEventIds: Set<string> = new Set();
  private seenEventIdQueue: string[] = [];
  private readonly maxDeduplicationCache: number = 2000;

  // Reconnection with exponential backoff & jitter
  private reconnectAttempts: number = 0;
  private reconnectTimeout: any = null;
  private readonly initialBackoffMs: number = 1000;
  private readonly maxBackoffMs: number = 15000;
  private readonly backoffMultiplier: number = 1.5;

  // Heartbeat & connection timeout watchdog
  private heartbeatWatchdogTimer: any = null;
  private readonly watchdogTimeoutMs: number = 25000;
  private lastHeartbeatTimestamp: number = 0;

  // Backpressure & Micro-batching buffer
  private eventBatchQueue: NormalizedTelemetryEvent[] = [];
  private batchFlushTimer: any = null;
  private readonly batchFlushIntervalMs: number = 60;

  // Cached state
  private latestMetrics: TelemetryStreamMetrics = {
    totalLiveEvents: 0,
    totalSimulatedEvents: 0,
    totalThreatsDetected: 0,
    totalAlertsGenerated: 0,
    totalIncidentsCreated: 0,
    currentEps: 0
  };
  private latestCollectorHealth: any = null;
  private latestDatabaseHealth: any = { status: 'UNKNOWN', connected: false };
  private latestAgentStatuses: any[] = [];
  private offlineSince: string | null = null;

  // Event Listeners
  private statusListeners: Set<StatusChangeCallback> = new Set();
  private eventBatchListeners: Set<EventBatchCallback> = new Set();
  private compositeEventListeners: Set<CompositeEventCallback> = new Set();
  private agentListeners: Set<(agent: any) => void> = new Set();
  private threatListeners: Set<(finding: any) => void> = new Set();
  private correlationListeners: Set<(correlation: any) => void> = new Set();
  private riskListeners: Set<(risk: any) => void> = new Set();
  private alertListeners: Set<(alert: any) => void> = new Set();
  private incidentListeners: Set<(incident: any) => void> = new Set();
  private collectorHealthListeners: Set<(health: any) => void> = new Set();
  private databaseHealthListeners: Set<(db: any) => void> = new Set();
  private metricsListeners: Set<(metrics: TelemetryStreamMetrics) => void> = new Set();

  constructor() {
    // Auto-connect if in browser environment
    if (typeof window !== 'undefined') {
      // Connect on window idle/load
      setTimeout(() => this.connect(), 100);
    }
  }

  /**
   * Connect to backend telemetry stream
   */
  public connect(): void {
    if (typeof window === 'undefined') return;
    if (this.eventSource && (this.eventSource.readyState === EventSource.OPEN || this.eventSource.readyState === EventSource.CONNECTING)) {
      return;
    }

    this.shouldConnect = true;
    this.setStatus('CONNECTING', 'Initiating connection to telemetry stream');
    this.cleanupCurrentConnection();

    try {
      const url = `/api/telemetry/stream?lastEventId=${this.lastSequence}`;
      const es = new EventSource(url);
      this.eventSource = es;

      es.onopen = () => {
        this.reconnectAttempts = 0;
        this.offlineSince = null;
        this.resetWatchdog();
        // Transition to LIVE if collectors active or backend verified
        if (this.status === 'CONNECTING') {
          this.setStatus('LIVE', 'Connected to real-time telemetry stream');
        }
      };

      // Raw message handler / general event fallback
      es.onmessage = (event: MessageEvent) => {
        this.resetWatchdog();
        this.handleRawMessage(event.data);
      };

      // Dedicated Named Event Listeners
      es.addEventListener('INIT_STATUS', (e: any) => {
        this.resetWatchdog();
        this.handleInitStatus(e.data);
      });

      es.addEventListener('NEW_TELEMETRY_EVENT', (e: any) => {
        this.resetWatchdog();
        this.handleNewTelemetryEvent(e.data);
      });

      es.addEventListener('AGENT_STATUS_UPDATE', (e: any) => {
        this.resetWatchdog();
        this.handleAgentStatusUpdate(e.data);
      });

      es.addEventListener('THREAT_DETECTION', (e: any) => {
        this.resetWatchdog();
        this.handleThreatDetection(e.data);
      });

      es.addEventListener('CORRELATION_EVENT', (e: any) => {
        this.resetWatchdog();
        this.handleCorrelationEvent(e.data);
      });

      es.addEventListener('RISK_ASSESSMENT', (e: any) => {
        this.resetWatchdog();
        this.handleRiskAssessment(e.data);
      });

      es.addEventListener('ALERT_GENERATED', (e: any) => {
        this.resetWatchdog();
        this.handleAlertGenerated(e.data);
      });

      es.addEventListener('INCIDENT_CREATED', (e: any) => {
        this.resetWatchdog();
        this.handleIncidentCreated(e.data);
      });

      es.addEventListener('COLLECTOR_HEALTH_UPDATE', (e: any) => {
        this.resetWatchdog();
        this.handleCollectorHealthUpdate(e.data);
      });

      es.addEventListener('DATABASE_HEALTH_UPDATE', (e: any) => {
        this.resetWatchdog();
        this.handleDatabaseHealthUpdate(e.data);
      });

      es.addEventListener('HEARTBEAT', (e: any) => {
        this.resetWatchdog();
        this.handleHeartbeat(e.data);
      });

      es.onerror = (err) => {
        this.handleConnectionError(err);
      };

      // Arm watchdog for initial connection response
      this.resetWatchdog();
    } catch (err: any) {
      this.handleConnectionError(err);
    }
  }

  /**
   * Disconnect cleanly
   */
  public disconnect(): void {
    this.shouldConnect = false;
    this.cleanupCurrentConnection();
    this.setStatus('DISCONNECTED', 'Stream disconnected by user or navigation');
  }

  /**
   * Cleans up EventSource and timers
   */
  private cleanupCurrentConnection(): void {
    if (this.heartbeatWatchdogTimer) {
      clearTimeout(this.heartbeatWatchdogTimer);
      this.heartbeatWatchdogTimer = null;
    }
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.eventSource) {
      try {
        this.eventSource.close();
      } catch {}
      this.eventSource = null;
    }
  }

  /**
   * Heartbeat Watchdog: If no message or heartbeat is received in 25s, reconnect
   */
  private resetWatchdog(): void {
    this.lastHeartbeatTimestamp = Date.now();
    if (this.heartbeatWatchdogTimer) {
      clearTimeout(this.heartbeatWatchdogTimer);
    }

    this.heartbeatWatchdogTimer = setTimeout(() => {
      console.warn('[TelemetryStream] Connection heartbeat timed out (no data for 25s). Triggering reconnect...');
      this.setStatus('DISCONNECTED', 'Connection timeout - no response from backend');
      this.attemptReconnect();
    }, this.watchdogTimeoutMs);
  }

  /**
   * Reconnection with Exponential Backoff and Randomized Jitter
   */
  private attemptReconnect(): void {
    if (!this.shouldConnect) return;
    this.cleanupCurrentConnection();

    this.reconnectAttempts++;
    // Calculate exponential delay: delay = initial * multiplier^(attempts - 1) + jitter
    const exponential = this.initialBackoffMs * Math.pow(this.backoffMultiplier, Math.min(this.reconnectAttempts - 1, 6));
    const jitter = Math.floor(Math.random() * 800);
    const delay = Math.min(this.maxBackoffMs, exponential) + jitter;

    if (!this.offlineSince) {
      this.offlineSince = new Date().toISOString();
    }

    this.reconnectTimeout = setTimeout(() => {
      this.setStatus('CONNECTING', `Reconnecting attempt ${this.reconnectAttempts}...`);
      this.connect();
    }, delay);
  }

  /**
   * Connection error handler
   */
  private handleConnectionError(err: any): void {
    console.warn('[TelemetryStream] SSE Connection error:', err);
    if (!this.offlineSince) {
      this.offlineSince = new Date().toISOString();
    }
    this.setStatus('DISCONNECTED', 'Stream offline or server unreachable');
    this.attemptReconnect();
  }

  /**
   * Sets telemetry stream status and notifies listeners
   */
  private setStatus(newStatus: TelemetryStreamStatus, reason: string = ''): void {
    const changed = this.status !== newStatus || this.lastStatusReason !== reason;
    this.status = newStatus;
    this.lastStatusReason = reason;

    if (changed) {
      this.statusListeners.forEach(listener => {
        try {
          listener(newStatus, { reason, attempts: this.reconnectAttempts, offlineSince: this.offlineSince });
        } catch (e) {
          console.error('[TelemetryStream] Error in status change listener:', e);
        }
      });
    }
  }

  /**
   * Parse incoming message envelope
   */
  private parseEnvelope(raw: string): TelemetryStreamEnvelope | null {
    try {
      if (typeof raw === 'object') return raw;
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  /**
   * Handle INIT_STATUS
   */
  private handleInitStatus(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;

    const data: StreamInitPayload = envelope.data || envelope;
    if (envelope.sequence) {
      this.lastSequence = Math.max(this.lastSequence, envelope.sequence);
    }

    // Set verified telemetry status
    if (data.telemetryState === 'LIVE') {
      this.setStatus('LIVE', 'Stream active with live host collectors');
    } else if (data.telemetryState === 'SIMULATION') {
      this.setStatus('SIMULATION', 'Stream active in simulation mode');
    } else if (data.telemetryState === 'ERROR') {
      this.setStatus('ERROR', 'Collector error detected in backend');
    } else if (data.telemetryState === 'DISCONNECTED') {
      this.setStatus('DISCONNECTED', 'No active collectors connected');
    } else {
      this.setStatus('CONNECTING', 'Connected to backend telemetry stream');
    }

    // Cache components
    if (data.metrics) {
      this.updateMetrics(data.metrics);
    }
    if (data.collectorHealth) {
      this.latestCollectorHealth = data.collectorHealth;
      this.collectorHealthListeners.forEach(cb => cb(data.collectorHealth));
    }
    if (data.databaseHealth) {
      this.latestDatabaseHealth = data.databaseHealth;
      this.databaseHealthListeners.forEach(cb => cb(data.databaseHealth));
    }
    if (data.agentStatuses) {
      this.latestAgentStatuses = data.agentStatuses;
      data.agentStatuses.forEach(agent => {
        this.agentListeners.forEach(cb => cb(agent));
      });
    }
    if (data.recentEvents && Array.isArray(data.recentEvents)) {
      this.queueEventsForBatch(data.recentEvents);
    }
  }

  /**
   * Handle NEW_TELEMETRY_EVENT with deduplication & ordering
   */
  private handleNewTelemetryEvent(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;

    if (envelope.sequence) {
      this.lastSequence = Math.max(this.lastSequence, envelope.sequence);
    }

    const payload = envelope.data || envelope;
    const event: NormalizedTelemetryEvent = payload.event;
    if (!event || !event.eventId) return;

    // Duplicate event prevention
    if (this.isDuplicate(event.eventId)) {
      return;
    }
    this.recordSeenEvent(event.eventId);

    // Enqueue event for backpressure-controlled micro-batching
    this.eventBatchQueue.push(event);
    if (!this.batchFlushTimer) {
      this.batchFlushTimer = setTimeout(() => {
        this.flushBatch();
      }, this.batchFlushIntervalMs);
    }

    // Dispatch composite event
    this.compositeEventListeners.forEach(cb => {
      try {
        cb(payload);
      } catch (e) {
        console.error('[TelemetryStream] Error in composite listener:', e);
      }
    });

    // Update metrics if included
    if (payload.metrics) {
      this.updateMetrics(payload.metrics);
    }

    // If active event is simulated vs live, reflect state
    if (event.isSimulated && this.status !== 'SIMULATION') {
      this.setStatus('SIMULATION', 'Receiving simulated test events');
    } else if (!event.isSimulated && this.status !== 'LIVE') {
      this.setStatus('LIVE', 'Receiving live host telemetry events');
    }
  }

  /**
   * Backpressure Micro-batching: flushes accumulated events at a steady rate
   */
  private queueEventsForBatch(events: NormalizedTelemetryEvent[]): void {
    for (const evt of events) {
      if (!this.isDuplicate(evt.eventId)) {
        this.recordSeenEvent(evt.eventId);
        this.eventBatchQueue.push(evt);
      }
    }

    if (!this.batchFlushTimer) {
      this.batchFlushTimer = setTimeout(() => {
        this.flushBatch();
      }, this.batchFlushIntervalMs);
    }
  }

  private flushBatch(): void {
    this.batchFlushTimer = null;
    if (this.eventBatchQueue.length === 0) return;

    const batch = [...this.eventBatchQueue];
    this.eventBatchQueue = [];

    // Sort by timestamp if multiple events in batch
    batch.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    this.eventBatchListeners.forEach(cb => {
      try {
        cb(batch);
      } catch (e) {
        console.error('[TelemetryStream] Error in event batch listener:', e);
      }
    });
  }

  /**
   * LRU Duplicate Detection
   */
  private isDuplicate(eventId: string): boolean {
    return this.seenEventIds.has(eventId);
  }

  private recordSeenEvent(eventId: string): void {
    this.seenEventIds.add(eventId);
    this.seenEventIdQueue.push(eventId);

    if (this.seenEventIdQueue.length > this.maxDeduplicationCache) {
      const oldest = this.seenEventIdQueue.shift();
      if (oldest) this.seenEventIds.delete(oldest);
    }
  }

  /**
   * Handle AGENT_STATUS_UPDATE
   */
  private handleAgentStatusUpdate(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.agentListeners.forEach(cb => cb(data));
  }

  /**
   * Handle THREAT_DETECTION
   */
  private handleThreatDetection(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.threatListeners.forEach(cb => cb(data));
  }

  /**
   * Handle CORRELATION_EVENT
   */
  private handleCorrelationEvent(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.correlationListeners.forEach(cb => cb(data));
  }

  /**
   * Handle RISK_ASSESSMENT
   */
  private handleRiskAssessment(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.riskListeners.forEach(cb => cb(data));
  }

  /**
   * Handle ALERT_GENERATED
   */
  private handleAlertGenerated(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.alertListeners.forEach(cb => cb(data));
  }

  /**
   * Handle INCIDENT_CREATED
   */
  private handleIncidentCreated(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.incidentListeners.forEach(cb => cb(data));
  }

  /**
   * Handle COLLECTOR_HEALTH_UPDATE
   */
  private handleCollectorHealthUpdate(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.latestCollectorHealth = data;
    this.collectorHealthListeners.forEach(cb => cb(data));
    if (data.metrics) {
      this.updateMetrics(data.metrics);
    }
  }

  /**
   * Handle DATABASE_HEALTH_UPDATE
   */
  private handleDatabaseHealthUpdate(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    this.latestDatabaseHealth = data;
    this.databaseHealthListeners.forEach(cb => cb(data));
  }

  /**
   * Handle HEARTBEAT
   */
  private handleHeartbeat(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;
    const data = envelope.data || envelope;
    if (data.metrics) {
      this.updateMetrics(data.metrics);
    }
    if (data.telemetryState && (this.status === 'LIVE' || this.status === 'SIMULATION')) {
      if (data.telemetryState === 'SIMULATION' && this.status !== 'SIMULATION') {
        this.setStatus('SIMULATION', 'Simulation mode verified by backend');
      } else if (data.telemetryState === 'LIVE' && this.status !== 'LIVE') {
        this.setStatus('LIVE', 'Live mode verified by backend');
      }
    }
  }

  /**
   * Handle raw message
   */
  private handleRawMessage(raw: string): void {
    const envelope = this.parseEnvelope(raw);
    if (!envelope) return;

    if (envelope.type === 'INIT_STATUS') {
      this.handleInitStatus(raw);
    } else if (envelope.type === 'NEW_TELEMETRY_EVENT') {
      this.handleNewTelemetryEvent(raw);
    } else if (envelope.type === 'COLLECTOR_HEALTH_UPDATE') {
      this.handleCollectorHealthUpdate(raw);
    }
  }

  /**
   * Update internal metrics and notify listeners
   */
  private updateMetrics(metrics: Partial<TelemetryStreamMetrics>): void {
    this.latestMetrics = {
      ...this.latestMetrics,
      ...metrics
    };
    this.metricsListeners.forEach(cb => {
      try {
        cb(this.latestMetrics);
      } catch (e) {
        console.error('[TelemetryStream] Error in metrics listener:', e);
      }
    });
  }

  // -------------------------------------------------------------
  // PUBLIC SUBSCRIPTIONS
  // -------------------------------------------------------------

  public onStatusChange(callback: StatusChangeCallback): () => void {
    this.statusListeners.add(callback);
    // Emit immediate current state
    callback(this.status, { reason: this.lastStatusReason, attempts: this.reconnectAttempts });
    return () => this.statusListeners.delete(callback);
  }

  public onEventBatch(callback: EventBatchCallback): () => void {
    this.eventBatchListeners.add(callback);
    return () => this.eventBatchListeners.delete(callback);
  }

  public onCompositeEvent(callback: CompositeEventCallback): () => void {
    this.compositeEventListeners.add(callback);
    return () => this.compositeEventListeners.delete(callback);
  }

  public onAgentStatus(callback: (agent: any) => void): () => void {
    this.agentListeners.add(callback);
    return () => this.agentListeners.delete(callback);
  }

  public onThreatDetection(callback: (finding: any) => void): () => void {
    this.threatListeners.add(callback);
    return () => this.threatListeners.delete(callback);
  }

  public onCorrelation(callback: (corr: any) => void): () => void {
    this.correlationListeners.add(callback);
    return () => this.correlationListeners.delete(callback);
  }

  public onRiskAssessment(callback: (risk: any) => void): () => void {
    this.riskListeners.add(callback);
    return () => this.riskListeners.delete(callback);
  }

  public onAlert(callback: (alert: any) => void): () => void {
    this.alertListeners.add(callback);
    return () => this.alertListeners.delete(callback);
  }

  public onIncident(callback: (incident: any) => void): () => void {
    this.incidentListeners.add(callback);
    return () => this.incidentListeners.delete(callback);
  }

  public onCollectorHealth(callback: (health: any) => void): () => void {
    this.collectorHealthListeners.add(callback);
    if (this.latestCollectorHealth) callback(this.latestCollectorHealth);
    return () => this.collectorHealthListeners.delete(callback);
  }

  public onDatabaseHealth(callback: (db: any) => void): () => void {
    this.databaseHealthListeners.add(callback);
    callback(this.latestDatabaseHealth);
    return () => this.databaseHealthListeners.delete(callback);
  }

  public onMetrics(callback: (metrics: TelemetryStreamMetrics) => void): () => void {
    this.metricsListeners.add(callback);
    callback(this.latestMetrics);
    return () => this.metricsListeners.delete(callback);
  }

  // -------------------------------------------------------------
  // GETTERS
  // -------------------------------------------------------------

  public getStatus(): TelemetryStreamStatus {
    return this.status;
  }

  public getMetrics(): TelemetryStreamMetrics {
    return { ...this.latestMetrics };
  }

  public getCollectorHealth(): any {
    return this.latestCollectorHealth;
  }

  public getDatabaseHealth(): any {
    return { ...this.latestDatabaseHealth };
  }

  public getAgentStatuses(): any[] {
    return [...this.latestAgentStatuses];
  }

  public isLive(): boolean {
    return this.status === 'LIVE';
  }

  public isOffline(): boolean {
    return this.status === 'DISCONNECTED' || this.status === 'ERROR';
  }
}

export const realtimeTelemetryStream = new RealtimeTelemetryStream();
