import { SeverityLevel, LogEvent, CommonAgentResult } from './index';

export type ApplicationAgentClassification = 'BENIGN' | 'SUSPICIOUS' | 'THREAT';

export type ApplicationThreatType =
  | 'UNAUTHORIZED_ACCESS'
  | 'SUSPICIOUS_WEB_REQUEST'
  | 'WEB_ATTACK_INDICATOR'
  | 'ABNORMAL_WEB_REQUEST'
  | 'API_MISUSE'
  | 'ABNORMAL_USER_BEHAVIOR'
  | 'SUSPICIOUS_AUTH_PATTERN'
  | 'APPLICATION_ANOMALY'
  | 'NONE';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS' | 'TRACE' | 'CONNECT';

/**
 * Single event extracted application attributes
 */
export interface SingleAppEventFields {
  id: string;
  timestamp: string;
  source: string;
  host?: string;
  sourceIp?: string;
  destinationIp?: string;
  username?: string;
  eventType?: string;
  method?: string;
  url?: string;
  path?: string;
  endpoint?: string;
  statusCode?: number;
  responseCode?: number;
  userAgent?: string;
  requestSize?: number;
  responseSize?: number;
  message: string;
  application?: string;
  service?: string;
  api?: string;
  payloadSnippet?: string;
  rawEvent: LogEvent;
}

/**
 * Aggregated endpoint metrics
 */
export interface EndpointActivityItem {
  endpoint: string;
  requestCount: number;
  uniqueUsers: number;
  uniqueIps: number;
  errorCount: number; // 4xx and 5xx responses
  status4xxCount: number;
  status5xxCount: number;
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
  highestSeverity: SeverityLevel;
  methods: string[];
  sampleUserAgents: string[];
  lastSeen: string;
}

/**
 * Aggregated source IP metrics for application access
 */
export interface SourceIpAppActivityItem {
  sourceIp: string;
  requestCount: number;
  uniqueEndpoints: number;
  failedRequests: number; // 401, 403, 404, 429, 500
  authFailures: number;
  suspiciousEvents: number;
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
  highestSeverity: SeverityLevel;
  lastSeen: string;
  primaryUserAgent?: string;
}

/**
 * Aggregated user metrics for application access
 */
export interface UserAppActivityItem {
  username: string;
  requestCount: number;
  uniqueEndpoints: number;
  failedRequests: number;
  authFailures: number;
  suspiciousEvents: number;
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
  highestSeverity: SeverityLevel;
  lastSeen: string;
  associatedIps: string[];
}

/**
 * Application Chronological Timeline item
 */
export interface ApplicationTimelineItem {
  id: string;
  timestamp: string;
  endpoint: string;
  method: string;
  statusCode: number;
  sourceIp: string;
  username: string;
  detection: string;
  details: string;
  severity: SeverityLevel;
  classification: ApplicationAgentClassification;
}

/**
 * Structured output of Application Agent detection (ready for correlation engine)
 * Conforms to the Multi-Agent Output Contract
 */
export interface ApplicationAgentResult extends CommonAgentResult {
  id: string;
  agentId: 'APPLICATION_AGENT';
  eventId: string;
  timestamp: string;
  source: string;
  detection: string;
  threatDetected: boolean;
  threatType: ApplicationThreatType;
  severity: SeverityLevel;
  confidence: number; // 0.00 to 1.00 based on observable evidence
  classification: ApplicationAgentClassification;
  sourceIp?: string;
  username?: string;
  host?: string;
  method?: string;
  url?: string;
  path?: string;
  endpoint?: string;
  statusCode?: number;
  userAgent?: string;
  requestCount?: number;
  evidence: string[]; // Human-readable, explainable evidence statements
  indicators: string[];
  observedActivity: string;
  detectedPattern: string;
  securityFinding: string;
  recommendedAction: string; // Informational / advisory only
  status: 'NEW' | 'REVIEWED' | 'DISPATCHED_TO_CORRELATION';
  rawEvent?: LogEvent;
}

/**
 * Full analysis object returned by ApplicationAgentService
 */
export interface ApplicationAgentAnalysis {
  totalApplicationEvents: number;
  webRequestsCount: number;
  apiRequestsCount: number;
  authEventsCount: number;
  suspiciousEventsCount: number;
  potentialThreatsCount: number;
  averageConfidence: number;
  uniqueUsersCount: number;
  uniqueSourceIpsCount: number;
  uniqueEndpointsCount: number;
  isRealData: boolean;
  dataSource: string;
  results: ApplicationAgentResult[];
  endpointActivity: EndpointActivityItem[];
  sourceIpActivity: SourceIpAppActivityItem[];
  userActivity: UserAppActivityItem[];
  eventsOverTime: { time: string; count: number; threats: number }[];
  statusCodeDistribution: { statusCode: string; count: number; color: string }[];
  topEndpoints: { endpoint: string; count: number; errors: number }[];
  topSourceIps: { sourceIp: string; count: number; threats: number }[];
  methodDistribution: { method: string; count: number; color: string }[];
  authFailuresOverTime: { time: string; failed: number; successful: number }[];
  threatSeverityDistribution: { severity: SeverityLevel; count: number; color: string }[];
  timeline: ApplicationTimelineItem[];
  baselineStatus: string;
}
