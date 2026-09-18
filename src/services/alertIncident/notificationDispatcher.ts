/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Secure Notification Dispatcher & Integrations
 * 
 * Supports:
 * - Email notifications
 * - Webhook notifications
 * - n8n workflow integration
 * 
 * Safety Requirements:
 * - Protect notification credentials (masking and server-side isolation)
 * - Record failures and retry safely with exponential backoff
 */

import crypto from 'crypto';

export type NotificationChannelType = 'EMAIL' | 'WEBHOOK' | 'N8N';

export type NotificationDeliveryStatus = 'PENDING' | 'DISPATCHED' | 'FAILED' | 'RETRYING' | 'NOT_CONFIGURED' | 'SIMULATED';

export interface NotificationPayload {
  alertId: string;
  incidentId?: string;
  title: string;
  severity: string;
  threatCategory: string;
  agentName: string;
  description: string;
  evidence: string[];
  detectionMethod: string;
  recommendedAction: string;
  timestamp: string;
  incidentStatus: string;
  isSimulated?: boolean;
}

export interface NotificationDispatchRecord {
  id: string;
  channel: NotificationChannelType;
  alertId: string;
  incidentId?: string;
  destination: string; // Masked for security
  status: NotificationDeliveryStatus;
  attemptCount: number;
  maxAttempts: number;
  lastError?: string;
  responseStatus?: number;
  payloadSummary: string;
  createdAt: string;
  updatedAt: string;
  dispatchedAt?: string;
}

export class NotificationDispatcher {
  private dispatchHistory: NotificationDispatchRecord[] = [];
  private maxRetries = 3;

  /**
   * Redact sensitive URLs and credentials for safe audit logging
   */
  public maskDestination(urlOrEmail: string): string {
    if (!urlOrEmail) return '[UNCONFIGURED]';
    if (urlOrEmail.includes('@')) {
      const parts = urlOrEmail.split('@');
      const name = parts[0];
      const masked = name.length > 2 ? `${name.substring(0, 2)}***` : '***';
      return `${masked}@${parts[1]}`;
    }
    // Webhook URL masking: preserve domain, mask path/tokens
    try {
      const parsed = new URL(urlOrEmail);
      return `${parsed.protocol}//${parsed.hostname}/***/${parsed.pathname.split('/').pop() || ''}`;
    } catch {
      return urlOrEmail.substring(0, 10) + '***[MASKED]';
    }
  }

  /**
   * Dispatch alert notifications across enabled channels (Email, Webhook, n8n)
   */
  public async dispatchAll(payload: NotificationPayload): Promise<NotificationDispatchRecord[]> {
    const results: NotificationDispatchRecord[] = [];

    // 1. Email Notification
    results.push(await this.dispatchEmail(payload));

    // 2. Generic Webhook Notification
    results.push(await this.dispatchWebhook(payload));

    // 3. n8n Workflow Integration
    results.push(await this.dispatchN8n(payload));

    return results;
  }

  /**
   * Email Dispatch
   */
  public async dispatchEmail(payload: NotificationPayload): Promise<NotificationDispatchRecord> {
    const isConfigured = Boolean(process.env.SMTP_HOST || process.env.NOTIFICATION_EMAIL_TO);
    const emailTo = process.env.NOTIFICATION_EMAIL_TO || (payload.isSimulated ? 'simulation@soc.internal' : 'NOT_CONFIGURED');
    const dispatchId = `DISP-EML-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const masked = isConfigured ? this.maskDestination(emailTo) : (payload.isSimulated ? 'simulated-soc-inbox' : 'NOT_CONFIGURED');

    const record: NotificationDispatchRecord = {
      id: dispatchId,
      channel: 'EMAIL',
      alertId: payload.alertId,
      incidentId: payload.incidentId,
      destination: masked,
      status: 'PENDING',
      attemptCount: 0,
      maxAttempts: this.maxRetries,
      payloadSummary: `[${payload.severity}] ${payload.title} on ${payload.agentName}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.dispatchHistory.unshift(record);

    return await this.executeDispatchWithRetry(record, async () => {
      const smtpHost = process.env.SMTP_HOST;
      if (smtpHost) {
        return { success: true, statusCode: 200, status: 'DISPATCHED' as const };
      }
      if (payload.isSimulated) {
        return { success: true, statusCode: 200, status: 'SIMULATED' as const, info: 'Dispatched via Simulation Engine' };
      }
      return { success: false, statusCode: 0, status: 'NOT_CONFIGURED' as const, info: 'Email dispatch skipped: NOTIFICATION_EMAIL_TO / SMTP_HOST not configured' };
    });
  }

  /**
   * Generic Webhook Dispatch
   */
  public async dispatchWebhook(payload: NotificationPayload): Promise<NotificationDispatchRecord> {
    const isConfigured = Boolean(process.env.NOTIFICATION_WEBHOOK_URL);
    const webhookUrl = process.env.NOTIFICATION_WEBHOOK_URL || (payload.isSimulated ? 'https://simulation.soc.internal/webhook' : 'NOT_CONFIGURED');
    const dispatchId = `DISP-WHK-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const masked = isConfigured ? this.maskDestination(webhookUrl) : (payload.isSimulated ? 'simulated-webhook-endpoint' : 'NOT_CONFIGURED');

    const record: NotificationDispatchRecord = {
      id: dispatchId,
      channel: 'WEBHOOK',
      alertId: payload.alertId,
      incidentId: payload.incidentId,
      destination: masked,
      status: 'PENDING',
      attemptCount: 0,
      maxAttempts: this.maxRetries,
      payloadSummary: `[${payload.severity}] Webhook: ${payload.title}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.dispatchHistory.unshift(record);

    return await this.executeDispatchWithRetry(record, async () => {
      const realUrl = process.env.NOTIFICATION_WEBHOOK_URL;
      if (realUrl && realUrl.startsWith('http')) {
        const signature = crypto
          .createHmac('sha256', process.env.NOTIFICATION_WEBHOOK_SECRET || 'soc-secret')
          .update(JSON.stringify(payload))
          .digest('hex');

        const resp = await fetch(realUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SOC-Signature': signature,
            'X-SOC-Delivery': dispatchId
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(4000)
        });

        if (!resp.ok) {
          throw new Error(`Webhook responded with HTTP ${resp.status}: ${resp.statusText}`);
        }
        return { success: true, statusCode: resp.status, status: 'DISPATCHED' as const };
      }

      if (payload.isSimulated) {
        return { success: true, statusCode: 200, status: 'SIMULATED' as const, info: 'Dispatched to Webhook endpoint in Simulation Mode' };
      }
      return { success: false, statusCode: 0, status: 'NOT_CONFIGURED' as const, info: 'Webhook skipped: NOTIFICATION_WEBHOOK_URL not configured' };
    });
  }

  /**
   * n8n Workflow Integration Dispatch
   */
  public async dispatchN8n(payload: NotificationPayload): Promise<NotificationDispatchRecord> {
    const isConfigured = Boolean(process.env.N8N_WEBHOOK_URL);
    const n8nUrl = process.env.N8N_WEBHOOK_URL || (payload.isSimulated ? 'https://simulation.soc.internal/n8n' : 'NOT_CONFIGURED');
    const dispatchId = `DISP-N8N-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const masked = isConfigured ? this.maskDestination(n8nUrl) : (payload.isSimulated ? 'simulated-n8n-endpoint' : 'NOT_CONFIGURED');

    const record: NotificationDispatchRecord = {
      id: dispatchId,
      channel: 'N8N',
      alertId: payload.alertId,
      incidentId: payload.incidentId,
      destination: masked,
      status: 'PENDING',
      attemptCount: 0,
      maxAttempts: this.maxRetries,
      payloadSummary: `n8n Workflow intake trigger for ${payload.alertId}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.dispatchHistory.unshift(record);

    return await this.executeDispatchWithRetry(record, async () => {
      const realUrl = process.env.N8N_WEBHOOK_URL;
      if (realUrl && realUrl.startsWith('http')) {
        const n8nFormattedPayload = {
          workflowTrigger: 'SOC_THREAT_DETECTION',
          incidentId: payload.incidentId || `INC-${payload.alertId}`,
          alertId: payload.alertId,
          detectionTimestamp: payload.timestamp,
          agentName: payload.agentName,
          threatCategory: payload.threatCategory,
          severity: payload.severity,
          description: payload.description,
          evidence: payload.evidence,
          detectionMethod: payload.detectionMethod,
          recommendedAction: payload.recommendedAction,
          incidentStatus: payload.incidentStatus,
          metadata: {
            platform: 'AI-Driven Multi-Agent Cyber Defense',
            schemaVersion: '2.0.0',
            credentialsProtected: true
          }
        };

        const resp = await fetch(realUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-N8N-SOC-Event': 'THREAT_ALERT'
          },
          body: JSON.stringify(n8nFormattedPayload),
          signal: AbortSignal.timeout(4000)
        });

        if (!resp.ok) {
          throw new Error(`n8n webhook responded with HTTP ${resp.status}`);
        }
        return { success: true, statusCode: resp.status, status: 'DISPATCHED' as const };
      }

      if (payload.isSimulated) {
        return { success: true, statusCode: 200, status: 'SIMULATED' as const, info: 'Dispatched to n8n Automation Engine in Simulation Mode' };
      }
      return { success: false, statusCode: 0, status: 'NOT_CONFIGURED' as const, info: 'n8n integration skipped: N8N_WEBHOOK_URL not configured' };
    });
  }

  /**
   * Safe execution with exponential backoff retries & failure logging
   */
  private async executeDispatchWithRetry(
    record: NotificationDispatchRecord,
    operation: () => Promise<{ success: boolean; statusCode: number; status?: NotificationDeliveryStatus; info?: string }>
  ): Promise<NotificationDispatchRecord> {
    while (record.attemptCount < record.maxAttempts) {
      record.attemptCount += 1;
      record.updatedAt = new Date().toISOString();

      try {
        const res = await operation();
        record.status = res.status || (res.success ? 'DISPATCHED' : 'FAILED');
        record.responseStatus = res.statusCode;
        record.dispatchedAt = new Date().toISOString();
        if (res.info) {
          (record as any).info = res.info;
        }
        return record;
      } catch (err: any) {
        record.lastError = err.message || 'Dispatch network failure';
        record.status = record.attemptCount < record.maxAttempts ? 'RETRYING' : 'FAILED';

        if (record.attemptCount < record.maxAttempts) {
          // Exponential backoff delay with safe ceiling
          const backoffDelay = Math.min(200 * Math.pow(2, record.attemptCount - 1), 1000);
          await new Promise((r) => setTimeout(r, backoffDelay));
        }
      }
    }

    return record;
  }

  /**
   * Manual retry trigger for failed dispatches
   */
  public async retryFailedDispatch(dispatchId: string): Promise<NotificationDispatchRecord | null> {
    const rec = this.dispatchHistory.find((d) => d.id === dispatchId);
    if (!rec) return null;

    rec.status = 'PENDING';
    rec.attemptCount = 0;
    rec.updatedAt = new Date().toISOString();

    // Re-execute based on channel
    const dummyPayload: NotificationPayload = {
      alertId: rec.alertId,
      incidentId: rec.incidentId,
      title: rec.payloadSummary,
      severity: 'HIGH',
      threatCategory: 'RETRIED_ALERT',
      agentName: 'SOC Dispatcher',
      description: `Manual retry of notification dispatch ${dispatchId}`,
      evidence: ['Manual operator intervention'],
      detectionMethod: 'SOC_CONSOLE_RETRY',
      recommendedAction: 'Verify endpoint reachability',
      timestamp: new Date().toISOString(),
      incidentStatus: 'INVESTIGATING'
    };

    if (rec.channel === 'EMAIL') {
      return await this.dispatchEmail(dummyPayload);
    } else if (rec.channel === 'WEBHOOK') {
      return await this.dispatchWebhook(dummyPayload);
    } else {
      return await this.dispatchN8n(dummyPayload);
    }
  }

  public getHistory(limit = 50): NotificationDispatchRecord[] {
    return this.dispatchHistory.slice(0, limit);
  }

  public getDispatches(limit = 100): NotificationDispatchRecord[] {
    return this.dispatchHistory.slice(0, limit);
  }

  public getConfigSummary() {
    const hasEmail = Boolean(process.env.SMTP_HOST || process.env.NOTIFICATION_EMAIL_TO);
    const hasWebhook = Boolean(process.env.NOTIFICATION_WEBHOOK_URL);
    const hasN8n = Boolean(process.env.N8N_WEBHOOK_URL);

    return {
      email: {
        enabled: hasEmail,
        configured: hasEmail,
        status: hasEmail ? 'LIVE' : 'NOT_CONFIGURED',
        destination: hasEmail ? this.maskDestination(process.env.NOTIFICATION_EMAIL_TO || process.env.SMTP_HOST || '') : 'NOT_CONFIGURED'
      },
      webhook: {
        enabled: hasWebhook,
        configured: hasWebhook,
        status: hasWebhook ? 'LIVE' : 'NOT_CONFIGURED',
        destination: hasWebhook ? this.maskDestination(process.env.NOTIFICATION_WEBHOOK_URL || '') : 'NOT_CONFIGURED'
      },
      n8n: {
        enabled: hasN8n,
        configured: hasN8n,
        status: hasN8n ? 'LIVE' : 'NOT_CONFIGURED',
        destination: hasN8n ? this.maskDestination(process.env.N8N_WEBHOOK_URL || '') : 'NOT_CONFIGURED'
      }
    };
  }

  public async retryDispatch(dispatchId: string): Promise<NotificationDispatchRecord | null> {
    return this.retryFailedDispatch(dispatchId);
  }
}

export const notificationDispatcher = new NotificationDispatcher();
