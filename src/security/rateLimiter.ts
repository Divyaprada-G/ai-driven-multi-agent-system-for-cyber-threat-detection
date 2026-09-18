/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Sliding Window In-Memory Rate Limiter Middleware
 * 
 * Provides defense against Denial-of-Service (DoS) and Brute-Force Attacks:
 * - Auth Rate Limiting (Strict: 10 attempts / 10 min)
 * - General API Rate Limiting (Balanced: 300 req / min)
 * - Telemetry Ingestion Limiting (High-Throughput: 1500 req / min)
 */

import { Request, Response, NextFunction } from 'express';
import { auditService } from '../services/auditService';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  name: string;
}

interface ClientRecord {
  timestamps: number[];
}

export class InMemoryRateLimiter {
  private clients: Map<string, ClientRecord> = new Map();
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly name: string;
  private cleanupInterval: NodeJS.Timeout;

  constructor(config: RateLimitConfig) {
    this.windowMs = config.windowMs;
    this.maxRequests = config.maxRequests;
    this.name = config.name;

    // Periodic sweep of stale client records every 2 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 2 * 60 * 1000);
    this.cleanupInterval.unref();
  }

  private cleanup(): void {
    const cutoff = Date.now() - this.windowMs;
    for (const [ip, record] of this.clients.entries()) {
      record.timestamps = record.timestamps.filter(t => t > cutoff);
      if (record.timestamps.length === 0) {
        this.clients.delete(ip);
      }
    }
  }

  public getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || '127.0.0.1';
  }

  public consume(ip: string): { allowed: boolean; remaining: number; resetTimeMs: number } {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    let record = this.clients.get(ip);
    if (!record) {
      record = { timestamps: [] };
      this.clients.set(ip, record);
    }

    record.timestamps = record.timestamps.filter(t => t > cutoff);

    if (record.timestamps.length >= this.maxRequests) {
      const oldestInWindow = record.timestamps[0];
      const resetTimeMs = oldestInWindow + this.windowMs - now;
      return { allowed: false, remaining: 0, resetTimeMs };
    }

    record.timestamps.push(now);
    const remaining = Math.max(0, this.maxRequests - record.timestamps.length);
    return { allowed: true, remaining, resetTimeMs: this.windowMs };
  }

  public middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const ip = this.getClientIp(req);
      const now = Date.now();
      const cutoff = now - this.windowMs;

      let record = this.clients.get(ip);
      if (!record) {
        record = { timestamps: [] };
        this.clients.set(ip, record);
      }

      // Filter out timestamps outside current window
      record.timestamps = record.timestamps.filter(t => t > cutoff);

      if (record.timestamps.length >= this.maxRequests) {
        const oldestInWindow = record.timestamps[0];
        const retryAfterSeconds = Math.ceil((oldestInWindow + this.windowMs - now) / 1000);

        // Record security audit for rate limit breach
        auditService.recordAction({
          action: 'RATE_LIMIT_EXCEEDED',
          entityType: 'SYSTEM',
          entityId: ip,
          actor: 'RateLimiterGuard',
          details: `Rate limit '${this.name}' exceeded by IP ${ip} (${record.timestamps.length} reqs / ${this.windowMs / 1000}s).`,
          metadata: { ipAddress: ip, path: req.path, rateLimiter: this.name, retryAfterSeconds }
        });

        res.setHeader('Retry-After', retryAfterSeconds.toString());
        res.setHeader('X-RateLimit-Limit', this.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', '0');
        res.setHeader('X-RateLimit-Reset', Math.ceil((now + retryAfterSeconds * 1000) / 1000).toString());

        return res.status(429).json({
          success: false,
          error: `Too many requests. Rate limit '${this.name}' exceeded. Please retry in ${retryAfterSeconds} seconds.`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: retryAfterSeconds,
          timestamp: new Date().toISOString()
        });
      }

      record.timestamps.push(now);
      const remaining = Math.max(0, this.maxRequests - record.timestamps.length);

      res.setHeader('X-RateLimit-Limit', this.maxRequests.toString());
      res.setHeader('X-RateLimit-Remaining', remaining.toString());
      res.setHeader('X-RateLimit-Reset', Math.ceil((now + this.windowMs) / 1000).toString());

      return next();
    };
  }
}

// Pre-configured rate limiters
export const authRateLimiter = new InMemoryRateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  maxRequests: 15,          // 15 attempts per 10 minutes per IP
  name: 'auth'
});

export const apiRateLimiter = new InMemoryRateLimiter({
  windowMs: 60 * 1000,      // 1 minute
  maxRequests: 300,         // 300 requests per minute
  name: 'api'
});

export const collectorRateLimiter = new InMemoryRateLimiter({
  windowMs: 60 * 1000,      // 1 minute
  maxRequests: 1500,        // 1500 telemetry batches per minute
  name: 'telemetry_ingest'
});
