import { SecurityAlert, AlertStatus } from '../types';
import { INITIAL_ALERTS } from './mockData';

export interface IAlertService {
  getAlerts(): Promise<SecurityAlert[]>;
  updateAlertStatus(alertId: string, status: AlertStatus): Promise<boolean>;
  triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }>;
}

class AlertServiceImpl implements IAlertService {
  private alerts: SecurityAlert[] = [...INITIAL_ALERTS];

  async getAlerts(): Promise<SecurityAlert[]> {
    return [...this.alerts];
  }

  async updateAlertStatus(alertId: string, status: AlertStatus): Promise<boolean> {
    const alert = this.alerts.find(a => a.alertId === alertId);
    if (alert) {
      alert.status = status;
      return true;
    }
    return false;
  }

  async triggerN8nAutomation(alertId: string): Promise<{ success: boolean; message: string; executionId: string }> {
    const alert = this.alerts.find(a => a.alertId === alertId);
    const executionId = `n8n-exec-${Math.random().toString(36).substring(2, 9)}`;
    if (alert) {
      alert.notificationStatus = 'DISPATCHED_N8N';
    }
    return {
      success: true,
      message: `Simulated n8n Webhook dispatched for alert ${alertId}. Automated ticket and channel notifications enqueued.`,
      executionId
    };
  }
}

export const alertService: IAlertService = new AlertServiceImpl();
