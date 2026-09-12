import { SeverityLevel, LogEvent } from './index';

export type NetworkAgentClassification = 'BENIGN' | 'SUSPICIOUS' | 'THREAT';

export type NetworkThreatType =
  | 'PORT_SCAN'
  | 'REPEATED_CONNECTIONS'
  | 'SUSPICIOUS_PORT'
  | 'PROTOCOL_ANOMALY'
  | 'TRAFFIC_SPIKE'
  | 'ANOMALY'
  | 'NONE';

/**
 * Observable features extracted from normalized network events
 */
export interface NetworkFeatures {
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  connectionCount: number;
  uniqueDestinationPorts: number;
  destinationPortsList: number[];
  uniqueDestinationIps: number;
  destinationIpsList: string[];
  connectionFrequency: number; // events per second across observation window
  bytesTransferred?: number;
  packetCount?: number;
  duration?: number;
  eventType?: string;
  timestamp: string;
  failedConnectionCount: number;
  timeSpanSeconds: number;
  rawEventIds: string[];
}

/**
 * Structured output of Network Agent analysis (consumed by Event Correlation Engine)
 */
export interface NetworkAgentResult {
  id: string;
  agentId: 'NETWORK_AGENT';
  eventId: string;
  timestamp: string;
  detection: string;
  threatDetected: boolean;
  threatType: NetworkThreatType;
  severity: SeverityLevel;
  confidence: number; // 0.00 to 1.00 based on observable evidence
  classification: NetworkAgentClassification;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  ports?: number[];
  evidence: string[]; // Human-readable, explainable evidence statements
  indicators: string[];
  observedActivity: string;
  detectedPattern: string;
  securityFinding: string;
  recommendedAction: string; // Informational / advisory only
  status: 'NEW' | 'REVIEWED' | 'DISPATCHED_TO_CORRELATION';
  rawEvent?: LogEvent;
}

export interface TopTalker {
  ip: string;
  eventCount: number;
  uniqueDestinations: number;
  destinationPorts: number[];
  protocols: string[];
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
  reason: string;
}

export interface NetworkTimelineItem {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  label: string;
  details: string;
  severity: SeverityLevel;
  classification: NetworkAgentClassification;
}

export interface NetworkAgentAnalysis {
  totalEventsAnalyzed: number;
  suspiciousEventsCount: number;
  potentialThreatsCount: number;
  averageConfidence: number;
  uniqueSourceIps: number;
  uniqueDestinationIps: number;
  isRealData: boolean;
  dataSource: string;
  results: NetworkAgentResult[];
  topSourceIps: TopTalker[];
  topDestinationIps: TopTalker[];
  portDistribution: { port: number; count: number; service?: string }[];
  protocolDistribution: { protocol: string; count: number }[];
  severityDistribution: { severity: SeverityLevel; count: number; color: string }[];
  eventsOverTime: { time: string; normal: number; suspicious: number }[];
  timeline: NetworkTimelineItem[];
}
