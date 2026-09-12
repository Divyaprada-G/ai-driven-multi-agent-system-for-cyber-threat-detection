import { SecurityAlert, AlertStatus, AlertLifecycleStatus } from '../types';
import { alertManager } from './alertIncident/alertManager';

export interface IAlertService {
  getAlerts(): Promise<SecurityAlert[]>;
  getAlertById(alertId: string): Promise<SecurityAlert | undefined>;
  updateAlertStatus(alertId: string, status: AlertStatus, reason?: string): Promise<boolean>;
  triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }>;
}

class AlertServiceImpl implements IAlertService {
  async getAlerts(): Promise<SecurityAlert[]> {
    return alertManager.getAlerts();
  }

  async getAlertById(alertId: string): Promise<SecurityAlert | undefined> {
    return alertManager.getAlertById(alertId);
  }

  async updateAlertStatus(alertId: string, status: AlertStatus, reason?: string): Promise<boolean> {
    return alertManager.updateAlertStatus(alertId, status as AlertLifecycleStatus, reason);
  }

  async triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }> {
    const alert = alertManager.getAlertById(alertId);
    const executionId = `n8n-exec-${Math.random().toString(36).substring(2, 9)}`;
    if (alert) {
      alert.notificationStatus = 'DISPATCHED_N8N';
      alertManager.updateAlertStatus(alertId, alert.status, 'n8n automation simulation triggered');
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

