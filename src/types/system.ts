import { SeverityLevel, LogEvent } from './index';

export type SystemAgentClassification = 'BENIGN' | 'SUSPICIOUS' | 'THREAT';

export type SystemThreatType =
  | 'REPEATED_AUTH_FAILURES'
  | 'BRUTE_FORCE'
  | 'SUSPICIOUS_AUTH_SEQUENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'SUSPICIOUS_PROCESS'
  | 'UNUSUAL_HOST_ACTIVITY'
  | 'ACCOUNT_MISUSE'
  | 'SYSTEM_ANOMALY'
  | 'NONE';

export type AuthStatus = 'SUCCESS' | 'FAILURE' | 'UNKNOWN';

export type SystemEventType =
  | 'AUTH_LOGIN'
  | 'AUTH_FAILURE'
  | 'AUTH_SUCCESS'
  | 'PRIVILEGE_CHANGE'
  | 'PROCESS_EXEC'
  | 'SYSTEM_SERVICE'
  | 'ACCOUNT_MANAGEMENT'
  | 'SESSION_START'
  | 'SESSION_END'
  | 'GENERAL_SYSTEM';

/**
 * Single event extracted system attributes
 */
export interface SingleSystemEventFields {
  id: string;
  timestamp: string;
  host?: string;
  username?: string;
  sourceIp?: string;
  eventType: SystemEventType;
  authStatus: AuthStatus;
  processName?: string;
  processId?: number;
  commandLine?: string;
  parentProcess?: string;
  integrityLevel?: string;
  action?: string;
  message: string;
  rawEvent: LogEvent;
}

/**
 * Aggregated user session / auth features
 */
export interface UserAuthFeatures {
  username: string;
  hosts: Set<string>;
  sourceIps: Set<string>;
  totalAuthAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  failureTimestamps: number[];
  successTimestamps: number[];
  firstSeen: number;
  lastSeen: number;
  hasSuccessAfterFailures: boolean;
  successAfterFailuresDetails?: {
    failedCount: number;
    successTime: string;
    firstFailureTime: string;
    timeDeltaSeconds: number;
    sourceIp?: string;
    host?: string;
  };
  eventIds: string[];
}

/**
 * Aggregated host telemetry features
 */
export interface HostTelemetryFeatures {
  host: string;
  users: Set<string>;
  totalEvents: number;
  authEvents: number;
  processEvents: number;
  failedLogins: number;
  privilegeEvents: number;
  processesObserved: Set<string>;
  sourceIps: Set<string>;
  eventIds: string[];
}

/**
 * Structured output of System Agent detection (ready for correlation engine)
 */
export interface SystemAgentResult {
  id: string;
  agentId: 'SYSTEM_AGENT';
  eventId: string;
  timestamp: string;
  detection: string;
  threatDetected: boolean;
  threatType: SystemThreatType;
  severity: SeverityLevel;
  confidence: number; // 0.00 to 1.00 based on observable evidence
  classification: SystemAgentClassification;
  username: string;
  host: string;
  sourceIp?: string;
  eventType: string;
  processName?: string;
  commandLine?: string;
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
 * User Activity item for the User Activity section
 */
export interface UserActivityItem {
  username: string;
  authenticationAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  suspiciousEvents: number;
  hostsCount: number;
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
  reason: string;
}

/**
 * Host Activity item for the Host Activity section
 */
export interface HostActivityItem {
  host: string;
  totalEvents: number;
  authenticationEvents: number;
  processEvents: number;
  suspiciousEvents: number;
  highestSeverity: SeverityLevel;
  riskIndicator: 'NORMAL' | 'ELEVATED' | 'HIGH';
}

/**
 * System Chronological Timeline item
 */
export interface SystemTimelineItem {
  id: string;
  timestamp: string;
  host: string;
  username: string;
  eventType: string;
  detection: string;
  details: string;
  severity: SeverityLevel;
  classification: SystemAgentClassification;
}

/**
 * Full analysis object returned by SystemAgentService
 */
export interface SystemAgentAnalysis {
  totalSystemEvents: number;
  authEventsCount: number;
  failedLoginsCount: number;
  successfulLoginsCount: number;
  suspiciousEventsCount: number;
  potentialThreatsCount: number;
  averageConfidence: number;
  uniqueHostsCount: number;
  uniqueUsersCount: number;
  isRealData: boolean;
  dataSource: string;
  results: SystemAgentResult[];
  userActivity: UserActivityItem[];
  hostActivity: HostActivityItem[];
  authOverTime: { time: string; successful: number; failed: number }[];
  authRatioDistribution: { name: string; value: number; color: string }[];
  topUsersAuth: { username: string; attempts: number; failed: number }[];
  topHostsEvents: { host: string; count: number; threats: number }[];
  failedLoginSources: { source: string; count: number }[];
  severityDistribution: { severity: SeverityLevel; count: number; color: string }[];
  timeline: SystemTimelineItem[];
  baselineStatus: string;
}
