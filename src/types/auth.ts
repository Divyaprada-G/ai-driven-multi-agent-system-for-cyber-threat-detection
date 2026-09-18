/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Role-Based Access Control & Authentication Types
 */

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface UserAccount {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  displayName: string;
  department?: string;
  createdAt: string;
  lastLoginAt?: string;
  failedLoginAttempts: number;
  isLocked: boolean;
  lockUntil?: string;
}

export interface UserAccountInternal extends UserAccount {
  passwordHash: string;
  salt: string;
}

export interface AuthSession {
  token: string;
  userId: string;
  username: string;
  role: UserRole;
  displayName: string;
  createdAt: string;
  expiresAt: string;
  ipAddress: string;
  userAgent?: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: UserAccount;
  expiresAt?: string;
  error?: string;
  code?: string;
}

export interface RolePermissions {
  role: UserRole;
  description: string;
  capabilities: {
    canViewTelemetry: boolean;
    canViewAlerts: boolean;
    canViewIncidents: boolean;
    canViewAuditLogs: boolean;
    canAcknowledgeAlerts: boolean;
    canUpdateIncidents: boolean;
    canExecuteSimulation: boolean;
    canRunPredictions: boolean;
    canUploadLogs: boolean;
    canControlCollectors: boolean;
    canControlPipeline: boolean;
    canTrainModels: boolean;
    canManageSeverityRules: boolean;
    canResetDatabase: boolean;
    canManageUsers: boolean;
  };
}

export const ROLE_DEFINITIONS: Record<UserRole, RolePermissions> = {
  ADMIN: {
    role: 'ADMIN',
    description: 'Security Administrator with full oversight, collector management, model retraining, and system control.',
    capabilities: {
      canViewTelemetry: true,
      canViewAlerts: true,
      canViewIncidents: true,
      canViewAuditLogs: true,
      canAcknowledgeAlerts: true,
      canUpdateIncidents: true,
      canExecuteSimulation: true,
      canRunPredictions: true,
      canUploadLogs: true,
      canControlCollectors: true,
      canControlPipeline: true,
      canTrainModels: true,
      canManageSeverityRules: true,
      canResetDatabase: true,
      canManageUsers: true,
    }
  },
  ANALYST: {
    role: 'ANALYST',
    description: 'Tier-2 SOC Analyst responsible for alert triage, incident response, investigation notes, and threat simulation.',
    capabilities: {
      canViewTelemetry: true,
      canViewAlerts: true,
      canViewIncidents: true,
      canViewAuditLogs: true,
      canAcknowledgeAlerts: true,
      canUpdateIncidents: true,
      canExecuteSimulation: true,
      canRunPredictions: true,
      canUploadLogs: true,
      canControlCollectors: false,
      canControlPipeline: false,
      canTrainModels: false,
      canManageSeverityRules: false,
      canResetDatabase: false,
      canManageUsers: false,
    }
  },
  VIEWER: {
    role: 'VIEWER',
    description: 'Auditor or Compliance Officer with read-only visibility into dashboards, reports, and threat timelines.',
    capabilities: {
      canViewTelemetry: true,
      canViewAlerts: true,
      canViewIncidents: true,
      canViewAuditLogs: false,
      canAcknowledgeAlerts: false,
      canUpdateIncidents: false,
      canExecuteSimulation: false,
      canRunPredictions: false,
      canUploadLogs: false,
      canControlCollectors: false,
      canControlPipeline: false,
      canTrainModels: false,
      canManageSeverityRules: false,
      canResetDatabase: false,
      canManageUsers: false,
    }
  }
};
