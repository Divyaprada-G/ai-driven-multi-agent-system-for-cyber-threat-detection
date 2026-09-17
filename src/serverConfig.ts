/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Central Backend Configuration Module
 * 
 * Manages environment variables, port bindings, runtime flags,
 * external integration parameters, and validation.
 */

import path from 'path';

export interface ServerConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  host: string;
  serviceName: string;
  version: string;
  mlServiceUrl: string;
  n8nDefaultWebhookUrl: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  requestBodyLimit: string;
  dataDir: string;
  corsOrigins: string[];
}

export const config: ServerConfig = {
  env: (process.env.NODE_ENV as any) || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  host: '0.0.0.0',
  serviceName: 'cyber-threat-detection-api',
  version: '1.0.0',
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000',
  n8nDefaultWebhookUrl: process.env.N8N_WEBHOOK_URL || '',
  logLevel: (process.env.LOG_LEVEL as any) || 'info',
  requestBodyLimit: '15mb',
  dataDir: path.join(process.cwd(), 'data'),
  corsOrigins: ['*']
};

export function validateConfig(): { valid: boolean; warnings: string[] } {
  const warnings: string[] = [];
  if (!process.env.ML_SERVICE_URL) {
    warnings.push('ML_SERVICE_URL not set in environment; defaulting to local proxy http://127.0.0.1:8000');
  }
  if (!process.env.SQL_HOST && !process.env.DATABASE_URL) {
    warnings.push('SQL database environment variables not provided; local persistent JSON storage active.');
  }
  return { valid: true, warnings };
}
