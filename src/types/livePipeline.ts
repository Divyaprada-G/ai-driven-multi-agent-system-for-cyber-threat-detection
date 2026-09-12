/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 12: Local Real-Time Prediction API & Live Security Pipeline Types
 * 100% Free / Local / No Paid External API
 */

export type LiveEventStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
export type LiveEventSource = 'network' | 'system' | 'application';
export type LiveSimulatorMode = 'mixed' | 'normal' | 'suspicious' | 'multistage';

export interface LiveSecurityEvent {
  eventId: string;
  receivedAt: string;
  processedAt?: string;
  status: LiveEventStatus;
  source: LiveEventSource;
  eventType: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  features: Record<string, any>;
  isSimulated: boolean; // Always true for test events
  agentId: string;
  agentType: string;
  findingId?: string;
  correlationId?: string;
  threatDetectionId?: string;
  riskAssessmentId?: string;
  alertId?: string;
  incidentId?: string;
  predictedClass?: string;
  confidence?: number;
  riskScore?: number;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  latencyMs?: number;
  details?: string;
  safeRecommendedAction?: string;
  error?: string;
  predictionDetails?: any;
}

export interface LivePipelineStatus {
  status: 'RUNNING' | 'STOPPED';
  backendOnline: boolean;
  backendUrl: string;
  mlEngineStatus: string;
  activeModelId?: string;
  activeModelType?: string;
  activeModelStatus: 'TRAINED' | 'NOT_TRAINED' | 'DEMO_MODEL' | 'MODEL_NOT_AVAILABLE';
  queueLength: number;
  eventsReceived: number;
  eventsProcessed: number;
  eventsFailed: number;
  threatsDetected: number;
  alertsGenerated: number;
  incidentsCreated: number;
  averageLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  eventsPerSecond: number;
  simulatorActive: boolean;
  simulatorRate: number;
  simulatorMode: LiveSimulatorMode;
  lastEventProcessedAt?: string;
}

export interface SimulatorConfig {
  eventRate: number; // 1, 2, 5, 10
  mode: LiveSimulatorMode;
}

export interface DemoStepState {
  stepNumber: number;
  title: string;
  description: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  details?: string;
}
