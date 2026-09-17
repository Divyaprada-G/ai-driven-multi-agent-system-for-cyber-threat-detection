/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Structured Application Logger
 * 
 * Provides standardized JSON/timestamped logging with log levels:
 * DEBUG, INFO, WARN, ERROR.
 */

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

const LOG_LEVEL_WEIGHTS: Record<LogLevel, number> = {
  DEBUG: 10,
  INFO: 20,
  WARN: 30,
  ERROR: 40
};

class Logger {
  private currentLevel: LogLevel = 'INFO';
  private serviceName: string = 'SOC-Platform';

  constructor(service: string = 'SOC-Platform', level: LogLevel = 'INFO') {
    this.serviceName = service;
    this.currentLevel = level;
  }

  public setLevel(level: LogLevel) {
    this.currentLevel = level;
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_WEIGHTS[level] >= LOG_LEVEL_WEIGHTS[this.currentLevel];
  }

  private format(level: LogLevel, message: string, meta?: any): string {
    const ts = new Date().toISOString();
    const metaStr = meta ? ` | ${typeof meta === 'object' ? JSON.stringify(meta) : meta}` : '';
    return `[${ts}] [${level}] [${this.serviceName}] ${message}${metaStr}`;
  }

  public debug(message: string, meta?: any) {
    if (this.shouldLog('DEBUG')) {
      console.debug(this.format('DEBUG', message, meta));
    }
  }

  public info(message: string, meta?: any) {
    if (this.shouldLog('INFO')) {
      console.log(this.format('INFO', message, meta));
    }
  }

  public warn(message: string, meta?: any) {
    if (this.shouldLog('WARN')) {
      console.warn(this.format('WARN', message, meta));
    }
  }

  public error(message: string, error?: any) {
    if (this.shouldLog('ERROR')) {
      const errDetail = error instanceof Error ? `${error.message}\n${error.stack}` : error;
      console.error(this.format('ERROR', message, errDetail));
    }
  }
}

export const logger = new Logger('SOC-Platform', (process.env.LOG_LEVEL?.toUpperCase() as LogLevel) || 'INFO');
