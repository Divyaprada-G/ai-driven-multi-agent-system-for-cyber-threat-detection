/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Alert Rate Limiting & Duplicate Prevention Engine
 * 
 * Protects SOC operators from alert fatigue and notification flooding.
 * Implements:
 * 1. Deterministic alert hashing
 * 2. Sliding window deduplication
 * 3. Burst tracking & occurrence aggregation
 * 4. Per-entity rate limiting
 */

import crypto from 'crypto';

export interface RateLimitCheckInput {
  source: string;
  threatCategory: string;
  primaryIp?: string;
  agentName?: string;
  detectionMethod?: string;
  severity?: string;
  timestamp?: string | number;
}

export interface RateLimitResult {
  allowAlert: boolean;
  isDuplicate: boolean;
  isRateLimited: boolean;
  contentHash: string;
  fingerprint?: string;
  burstCount: number;
  frequency?: number;
  suppressNotification: boolean;
  reason?: string;
}

interface DeduplicationBucket {
  contentHash: string;
  firstSeenMs: number;
  lastSeenMs: number;
  count: number;
  recentTimestamps: number[];
}

export class AlertRateLimiter {
  private windowMinutes: number;
  private maxAlertsPerMinute: number;
  private buckets: Map<string, DeduplicationBucket> = new Map();

  constructor(windowMinutes: number = 10, maxAlertsPerMinute: number = 10) {
    this.windowMinutes = windowMinutes;
    this.maxAlertsPerMinute = maxAlertsPerMinute;
  }

  /**
   * Compute deterministic alert content hash for deduplication
   */
  public computeAlertHash(input: RateLimitCheckInput): string {
    const normSource = (input.source || 'unknown').toLowerCase().trim();
    const normCategory = (input.threatCategory || 'threat').toLowerCase().trim();
    const normIp = (input.primaryIp || '').trim();
    const normAgent = (input.agentName || '').toLowerCase().trim();

    const raw = `${normSource}|${normCategory}|${normIp}|${normAgent}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
  }

  /**
   * Evaluate whether an alert should be allowed, deduplicated, or rate-limited
   */
  public evaluate(input: RateLimitCheckInput): RateLimitResult {
    const hash = this.computeAlertHash(input);
    const nowMs = Date.now();
    const windowMs = this.windowMinutes * 60 * 1000;
    const oneMinuteMs = 60 * 1000;

    // Clean up stale buckets older than 2x window
    this.cleanupStaleBuckets(nowMs, windowMs * 2);

    let bucket = this.buckets.get(hash);

    if (!bucket) {
      // First time seen
      bucket = {
        contentHash: hash,
        firstSeenMs: nowMs,
        lastSeenMs: nowMs,
        count: 1,
        recentTimestamps: [nowMs]
      };
      this.buckets.set(hash, bucket);

      return {
        allowAlert: true,
        isDuplicate: false,
        isRateLimited: false,
        contentHash: hash,
        fingerprint: hash,
        burstCount: 1,
        frequency: 1,
        suppressNotification: false
      };
    }

    // Bucket exists - update stats
    bucket.count += 1;
    bucket.lastSeenMs = nowMs;
    bucket.recentTimestamps.push(nowMs);

    // Prune timestamps older than 1 minute to check per-minute rate limit
    bucket.recentTimestamps = bucket.recentTimestamps.filter(t => nowMs - t <= oneMinuteMs);

    // Rate limit check: more than max per minute
    if (bucket.recentTimestamps.length > this.maxAlertsPerMinute) {
      return {
        allowAlert: false,
        isDuplicate: true,
        isRateLimited: true,
        contentHash: hash,
        fingerprint: hash,
        burstCount: bucket.count,
        frequency: bucket.count,
        suppressNotification: true,
        reason: `Rate limit threshold exceeded (${bucket.recentTimestamps.length} occurrences in last 60s). Suppressed notification.`
      };
    }

    // Deduplication check: if within sliding deduplication window
    const isWithinWindow = nowMs - bucket.firstSeenMs <= windowMs;
    if (isWithinWindow) {
      return {
        allowAlert: true, // Still recorded/aggregated in store
        isDuplicate: true,
        isRateLimited: false,
        contentHash: hash,
        fingerprint: hash,
        burstCount: bucket.count,
        frequency: bucket.count,
        suppressNotification: true, // Suppress repeated external notifications during active burst
        reason: `Deduplicated active burst (occurrence #${bucket.count}). Notification suppressed to prevent alert flood.`
      };
    }

    // If outside the previous window, reset the sliding window
    bucket.firstSeenMs = nowMs;
    bucket.count = 1;
    bucket.recentTimestamps = [nowMs];

    return {
      allowAlert: true,
      isDuplicate: false,
      isRateLimited: false,
      contentHash: hash,
      fingerprint: hash,
      burstCount: 1,
      frequency: 1,
      suppressNotification: false
    };
  }

  private cleanupStaleBuckets(nowMs: number, maxAgeMs: number): void {
    if (this.buckets.size < 200) return;
    for (const [key, bucket] of this.buckets.entries()) {
      if (nowMs - bucket.lastSeenMs > maxAgeMs) {
        this.buckets.delete(key);
      }
    }
  }

  public reset(): void {
    this.buckets.clear();
  }
}

export const alertRateLimiter = new AlertRateLimiter(10, 10);
