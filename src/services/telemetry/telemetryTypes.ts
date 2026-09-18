/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Real-Time Telemetry & Data Collection Types
 * Strict separation between LIVE telemetry, SIMULATED data, OFFLINE, and ERROR states.
 */

export type CollectorType = 'SYSTEM' | 'NETWORK' | 'APPLICATION' | 'INGESTION_API';

export type CollectorState = 'LIVE' | 'SIMULATED' | 'OFFLINE' | 'ERROR';

export type TelemetrySourceType =
  | 'HOST_SYSTEM'
  | 'NETWORK_INTERFACE'
  | 'APP_HTTP'
  | 'SYSLOG_INGEST'
  | 'EXTERNAL_AGENT'
  | 'SIMULATOR';

export interface CollectorHealth {
  type: CollectorType;
  name: string;
  state: CollectorState;
  enabled: boolean;
  samplingIntervalMs: number;
  eventsCollected: number;
  eventsDropped: number;
  errorsCount: number;
  currentEps: number;
  lastEventAt?: string;
  errorMessage?: string;
  details?: Record<string, any>;
}

export interface SystemMetricsPacket {
  hostname: string;
  platform: string;
  arch: string;
  uptimeSeconds: number;
  cpuCount: number;
  cpuUsagePercent: number;
  totalMemoryBytes: number;
  freeMemoryBytes: number;
  usedMemoryPercent: number;
  processCount: number;
  heapUsedBytes: number;
  loadAverage: number[];
  authEvents?: {
    failedLogins: number;
    acceptedLogins: number;
    sudoAttempts: number;
  };
}

export interface NetworkMetricsPacket {
  interfaces: Array<{
    name: string;
    ip: string;
    mac: string;
    internal: boolean;
    family: string;
  }>;
  activeSocketsCount: number;
  listeningPorts: number[];
  establishedConnections: number;
  bytesReceived: number;
  bytesSent: number;
  packetsPerSecond: number;
  activeConnections?: Array<{
    protocol: string;
    localIp: string;
    localPort: number;
    remoteIp: string;
    remotePort: number;
    state: string;
    pid?: string;
    processName?: string;
  }>;
  suspiciousConnections: Array<{
    remoteIp: string;
    port: number;
    state: string;
    reason?: string;
  }>;
}

export interface ApplicationMetricsPacket {
  activeRequests: number;
  totalRequestsHandled: number;
  statusCodes: {
    '2xx': number;
    '3xx': number;
    '4xx': number;
    '5xx': number;
  };
  averageResponseTimeMs: number;
  errorRatePercent: number;
  suspiciousRequestsCount: number;
  recentSecurityTriggers: Array<{
    timestamp: string;
    path: string;
    method: string;
    clientIp: string;
    triggerType: 'SQLI' | 'XSS' | 'PATH_TRAVERSAL' | 'AUTH_FAILURE' | 'RATE_LIMIT';
    details: string;
  }>;
}

export interface SourceMetadata {
  source_type: string;
  hostname: string;
  collector_name: string;
  event_id: string;
  timestamp: string;
  raw_message: string;
  collection_status: string;
  [key: string]: any;
}

export interface NormalizedTelemetryEvent {
  eventId: string;
  timestamp: string;
  source: 'network' | 'system' | 'application';
  eventType: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  host: string;
  username?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: string;
  rawPayload: string;
  contentHash: string;
  isSimulated: boolean; // Strictly false for live telemetry
  telemetrySource: TelemetrySourceType;
  collectorState: CollectorState;
  features: Record<string, number | string>;
  agentRouting: {
    assignedAgent: string;
    assignedAgentId: string;
  };
  sourceMetadata?: SourceMetadata;

  // Exact Upgrade 5 Normalized Event Schema fields
  event_id?: string;
  source_type?: string;
  hostname?: string;
  local_ip?: string;
  remote_ip?: string;
  local_port?: number;
  remote_port?: number;
  connection_state?: string;
  process_name?: string | null;
  collector_name?: string;
  collection_status?: string;
}

export interface TelemetryIngestRequest {
  source: 'network' | 'system' | 'application';
  eventType?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  rawLogs?: string;
  structuredEvents?: Array<Partial<NormalizedTelemetryEvent>>;
  host?: string;
  sourceIp?: string;
  destinationIp?: string;
  isSimulated?: boolean;
}

/**
 * Real-Time Telemetry Streaming Protocol Types
 */
export type TelemetryStreamStatus =
  | 'LIVE'
  | 'CONNECTING'
  | 'DISCONNECTED'
  | 'SIMULATION'
  | 'ERROR';

export type TelemetryStreamEventType =
  | 'INIT_STATUS'
  | 'NEW_TELEMETRY_EVENT'
  | 'AGENT_STATUS_UPDATE'
  | 'THREAT_DETECTION'
  | 'CORRELATION_EVENT'
  | 'RISK_ASSESSMENT'
  | 'ALERT_GENERATED'
  | 'INCIDENT_CREATED'
  | 'COLLECTOR_HEALTH_UPDATE'
  | 'DATABASE_HEALTH_UPDATE'
  | 'HEARTBEAT';

export interface TelemetryStreamEnvelope<T = any> {
  type: TelemetryStreamEventType;
  sequence: number;
  timestamp: string;
  data: T;
}

export interface StreamInitPayload {
  sequence: number;
  telemetryState: 'LIVE' | 'SIMULATION' | 'OFFLINE' | 'PARTIAL' | 'ERROR' | 'DISCONNECTED';
  collectorHealth: {
    overallState: string;
    activeCollectorsCount: number;
    totalCollectors: number;
    collectors: CollectorHealth[];
    externalCollectors: any[];
    metrics: {
      totalLiveEvents: number;
      totalSimulatedEvents: number;
      totalThreatsDetected: number;
      totalAlertsGenerated: number;
      totalIncidentsCreated: number;
      currentEps: number;
      connectedSseClients: number;
      uptimeSeconds: number;
    };
  };
  databaseHealth: {
    status: string;
    connected: boolean;
    mode?: string;
    details?: string;
  };
  agentStatuses: any[];
  recentEvents: NormalizedTelemetryEvent[];
  metrics: {
    totalLiveEvents: number;
    totalSimulatedEvents: number;
    totalThreatsDetected: number;
    totalAlertsGenerated: number;
    totalIncidentsCreated: number;
    currentEps: number;
  };
}

