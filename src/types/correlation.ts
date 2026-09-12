import { AgentType, SeverityLevel, LogEvent } from './index';

/**
 * Normalized Security Finding
 * Common representation across Network, System, and Application agents
 */
export interface SecurityFinding {
  id: string;
  agentId: AgentType; // 'NETWORK_AGENT' | 'SYSTEM_AGENT' | 'APPLICATION_AGENT'
  eventId: string;
  timestamp: string; // ISO 8601 or standard string
  source: string;
  host?: string;
  sourceIp?: string;
  destinationIp?: string;
  username?: string;
  eventType: string;
  threatType: string;
  severity: SeverityLevel;
  confidence: number; // 0.00 to 1.00
  evidence: string[];
  indicators: string[];
  classification?: 'BENIGN' | 'SUSPICIOUS' | 'THREAT';
  rawEvent?: LogEvent;
  metadata?: Record<string, unknown>;
}

/**
 * Rule categories in the modular correlation engine
 */
export type CorrelationRuleCategory =
  | 'TIME_PROXIMITY'
  | 'SOURCE_IP_MATCH'
  | 'DESTINATION_IP_MATCH'
  | 'HOST_MATCH'
  | 'USERNAME_MATCH'
  | 'EVENT_SEQUENCE'
  | 'CROSS_AGENT_ACTIVITY'
  | 'THREAT_TYPE_RELATIONSHIP';

/**
 * Result returned by an individual correlation rule evaluation
 */
export interface CorrelationRuleResult {
  ruleId: string;
  ruleName: string;
  category: CorrelationRuleCategory;
  matched: boolean;
  score: number; // contribution between 0.00 and 1.00
  reason: string;
  evidence: string[];
}

/**
 * Correlation strength metric (distinct from threat severity)
 */
export type CorrelationStrength = 'LOW' | 'MEDIUM' | 'HIGH';

/**
 * Attack sequence step within a correlated timeline
 */
export interface CorrelationSequenceStep {
  step: number;
  timestamp: string;
  agentId: AgentType;
  findingId: string;
  eventId?: string; // Backward compatibility alias
  description: string;
  threatType: string;
  severity: SeverityLevel;
  sourceIp?: string;
  host?: string;
  user?: string;
}

/**
 * Unified Correlated Event
 * Synthesizes multi-agent findings into a coherent potential security incident.
 */
export interface CorrelatedEvent {
  id: string;
  correlationId: string; // Backward compatibility with previous schema
  timestamp?: string; // Backward compatibility with previous schema
  createdAt: string;
  startTime: string;
  endTime: string;
  duration: string;

  // Findings linkage
  findingIds: string[];
  eventIds: string[]; // Backward compatibility
  eventsCount: number; // Backward compatibility
  eventCount?: number; // Backward compatibility alias
  participatingAgents: AgentType[];
  sources: string[]; // Backward compatibility

  // Correlated entities
  sourceIps: string[];
  destinationIps: string[];
  hosts: string[];
  users: string[];
  eventTypes: string[];
  threatTypes: string[];

  // Attack sequence & reasoning
  sequence?: CorrelationSequenceStep[];
  correlationStrength: CorrelationStrength;
  correlationConfidence: number; // 0.00 to 1.00
  confidence: number; // Backward compatibility (0-100)
  severity: SeverityLevel; // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

  // Descriptive narrative
  title: string;
  attackPattern: string; // Backward compatibility
  summary: string;
  description: string; // Backward compatibility
  evidence: string[];
  indicators: string[];
  explanation: string; // Detailed Causal "Why were these events connected?"
  recommendedAction?: string; // Containment recommendation

  // Lifecycle status
  status: 'PENDING' | 'CORRELATED' | 'ESCALATED' | 'DISMISSED';
  mitreTechniqueId?: string;
  agentContributions: {
    network?: string;
    system?: string;
    application?: string;
  };
  ruleResults?: CorrelationRuleResult[];
  metadata?: Record<string, unknown>;
}

/**
 * Configurable parameters for the correlation engine
 */
export interface CorrelationConfig {
  timeWindowSeconds: number; // e.g. 30, 60, 300 (5m), 900 (15m)
  minFindings: number; // e.g. 2, 3, 4
  crossAgentRequired: boolean; // whether cross-agent findings are mandatory
  minCorrelationStrength: CorrelationStrength; // 'LOW' | 'MEDIUM' | 'HIGH'
  autoCorrelationEnabled: boolean;
}

/**
 * Predefined Demo Scenarios for demonstration & academic testing
 */
export type CorrelationScenarioId = 'DEMO_1' | 'DEMO_2' | 'DEMO_3' | 'DEMO_4';

export interface CorrelationDemoScenario {
  id: CorrelationScenarioId;
  name: string;
  description: string;
  expectedOutcome: string;
  findings: SecurityFinding[];
}

/**
 * Top-level Correlation Engine telemetry metrics
 */
export interface CorrelationMetrics {
  totalFindings: number;
  correlatedEventsCount: number;
  crossAgentCorrelationsCount: number;
  highStrengthCorrelationsCount: number;
  uniqueSourceIpsCount: number;
  affectedHostsCount: number;
  affectedUsersCount: number;
  engineStatus: 'READY' | 'DEMO' | 'NOT_CONNECTED';
  dataSource: 'UPLOADED_DATA' | 'DEMO_DATA';
}
