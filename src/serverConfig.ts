/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Central Backend Configuration Module
 * 
 * Manages environment variables, port bindings, runtime flags,
 * authentication secrets, external integration parameters, and validation.
 */

import path from 'path';

export interface ServerConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  host: string;
  serviceName: string;
  version: string;
  sessionSecret: string;
  backendApiKey: string;
  mlServiceUrl: string;
  n8nDefaultWebhookUrl: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  requestBodyLimit: string;
  dataDir: string;
  corsOrigins: string[];
  mongodbUri?: string;
  mongodbDbName: string;
}

const defaultCorsOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://ai.studio'
];

export const config: ServerConfig = {
  env: (process.env.NODE_ENV as any) || 'development',
  port: 3000,
  host: '0.0.0.0',
  serviceName: 'cyber-threat-detection-api',
  version: '1.0.0',
  sessionSecret: process.env.SESSION_SECRET || 'soc_default_internal_session_secret_2026',
  backendApiKey: process.env.BACKEND_API_KEY || 'soc-collector-default-key-2026',
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000',
  n8nDefaultWebhookUrl: process.env.N8N_WEBHOOK_URL || '',
  logLevel: (process.env.LOG_LEVEL as any) || 'info',
  requestBodyLimit: '15mb',
  dataDir: path.join(process.cwd(), 'data'),
  corsOrigins: process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : defaultCorsOrigins,
  mongodbUri: process.env.MONGODB_URI || undefined,
  mongodbDbName: process.env.MONGODB_DB_NAME || 'cyber_threat_detection'
};

export function validateConfig(): { valid: boolean; warnings: string[] } {
  const warnings: string[] = [];
  if (!process.env.SESSION_SECRET) {
    warnings.push('SESSION_SECRET not set in environment; using secure fallback key for development.');
  }
  if (!process.env.BACKEND_API_KEY) {
    warnings.push('BACKEND_API_KEY not configured; collectors will use development authentication mode.');
  }
  if (!process.env.ML_SERVICE_URL) {
    warnings.push('ML_SERVICE_URL not set in environment; defaulting to local proxy http://127.0.0.1:8000');
  }
  if (!process.env.MONGODB_URI) {
    warnings.push('MONGODB_URI not set; MongoDB will run with fallback to local persistent store.');
  }
  if (!process.env.SQL_HOST && !process.env.DATABASE_URL) {
    warnings.push('SQL database environment variables not provided; local persistent JSON storage active.');
  }
  return { valid: true, warnings };
}

/**
 * Returns a redacted representation of config suitable for safe logging
 */
export function getSafeConfig(): Partial<ServerConfig> {
  return {
    env: config.env,
    port: config.port,
    host: config.host,
    serviceName: config.serviceName,
    version: config.version,
    logLevel: config.logLevel,
    corsOrigins: config.corsOrigins,
    mongodbDbName: config.mongodbDbName,
    // Sensitive keys explicitly redacted
    sessionSecret: '[REDACTED]',
    backendApiKey: '[REDACTED]',
    mongodbUri: config.mongodbUri ? config.mongodbUri.replace(/(mongodb(?:\+srv)?:\/\/[^:]+:)([^@]+)@/i, '$1*****@') : undefined
  };
}
