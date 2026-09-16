import { SecurityAlert, AlertStatus, AlertLifecycleStatus } from '../types';
import { alertManager } from './alertIncident/alertManager';
import { localApiClient } from './apiClient';

export interface IAlertService {
  getAlerts(): Promise<SecurityAlert[]>;
  getAlertById(alertId: string): Promise<SecurityAlert | undefined>;
  updateAlertStatus(alertId: string, status: AlertStatus, reason?: string): Promise<boolean>;
  triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }>;
}

class AlertServiceImpl implements IAlertService {
  async getAlerts(): Promise<SecurityAlert[]> {
    try {
      const dbAlerts = await localApiClient.getAlerts(100);
      if (Array.isArray(dbAlerts) && dbAlerts.length > 0) {
        // Map PostgreSQL alerts into SecurityAlert format
        return dbAlerts.map((row: any) => ({
          id: row.alertId || row.id,
          alertId: row.alertId || row.id,
          title: row.title,
          description: row.description,
          alertType: row.alertType || 'UNKNOWN',
          threat: row.title,
          threatClassification: row.alertType || 'UNKNOWN',
          severity: row.severity,
          riskScore: row.riskScore,
          priority: row.priority,
          status: row.status as AlertLifecycleStatus,
          timestamp: row.createdAt,
          source: row.sourceIp || 'Network',
          affectedEntities: [row.sourceIp, row.destinationIp, row.affectedHost].filter(Boolean),
          evidence: row.evidence || [],
          mitreTechniques: row.mitreTechniques || [],
          deduplicationCount: row.burstCount || 1,
          isRead: true,
          confidence: 0.9,
          history: []
        })) as unknown as SecurityAlert[];
      }
    } catch {
      // Fallback to in-memory manager if database is unavailable
    }
    return alertManager.getAlerts();
  }

  async getAlertById(alertId: string): Promise<SecurityAlert | undefined> {
    try {
      const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}`);
      if (res.ok) {
        const row = await res.json();
        return {
          id: row.alertId || row.id,
          alertId: row.alertId || row.id,
          title: row.title,
          description: row.description,
          alertType: row.alertType || 'UNKNOWN',
          threat: row.title,
          threatClassification: row.alertType || 'UNKNOWN',
          severity: row.severity,
          riskScore: row.riskScore,
          priority: row.priority,
          status: row.status as AlertLifecycleStatus,
          timestamp: row.createdAt,
          source: row.sourceIp || 'Network',
          affectedEntities: [row.sourceIp, row.destinationIp, row.affectedHost].filter(Boolean),
          evidence: row.evidence || [],
          mitreTechniques: row.mitreTechniques || [],
          deduplicationCount: row.burstCount || 1,
          isRead: true,
          confidence: 0.9,
          history: []
        } as unknown as SecurityAlert;
      }
    } catch {
      // Fallback
    }
    return alertManager.getAlertById(alertId);
  }

  async updateAlertStatus(alertId: string, status: AlertStatus, reason?: string): Promise<boolean> {
    // 1. Update server-side PostgreSQL
    try {
      await localApiClient.updateAlertStatus(alertId, status as string, 'SOC Analyst', reason);
    } catch (err) {
      console.warn('[AlertService] Failed persisting alert status to PostgreSQL:', err);
    }
    // 2. Update local manager for immediate reactivity in state listeners
    return alertManager.updateAlertStatus(alertId, status as AlertLifecycleStatus, reason);
  }

  async triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }> {
    const alert = alertManager.getAlertById(alertId);
    const executionId = `n8n-exec-${Math.random().toString(36).substring(2, 9)}`;
    if (alert) {
      alert.notificationStatus = 'DISPATCHED_N8N';
      await this.updateAlertStatus(alertId, alert.status, 'n8n automation simulation triggered');
    }
    return {
      success: true,
      message: `Simulated n8n Webhook dispatched for alert ${alertId}. Automated ticket and channel notifications enqueued (Simulation Only).`,
      executionId
    };
  }
}

export const alertService: IAlertService = new AlertServiceImpl();
export { alertManager };
