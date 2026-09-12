import { INITIAL_METRICS, INITIAL_AGENTS, INITIAL_INCIDENTS, INITIAL_RISK_ASSESSMENTS } from './mockData';

export interface SecurityReportData {
  generatedAt: string;
  reportId: string;
  scope: string;
  metrics: typeof INITIAL_METRICS;
  agents: typeof INITIAL_AGENTS;
  criticalIncidents: typeof INITIAL_INCIDENTS;
  highRisks: typeof INITIAL_RISK_ASSESSMENTS;
  recommendations: string[];
}

export const reportService = {
  async generateSummaryReport(): Promise<SecurityReportData> {
    return {
      generatedAt: new Date().toISOString(),
      reportId: `SOC-REP-${Date.now().toString().slice(-6)}`,
      scope: 'Multi-Agent Cyber Threat Detection - Executive Briefing',
      metrics: { ...INITIAL_METRICS },
      agents: [...INITIAL_AGENTS],
      criticalIncidents: INITIAL_INCIDENTS.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH'),
      highRisks: INITIAL_RISK_ASSESSMENTS.filter(r => r.score >= 70),
      recommendations: [
        'Enforce multi-factor authentication across all external VPN and administrative entrypoints.',
        'Review web application firewall parameterized rule coverage on legacy API endpoints.',
        'Maintain Wazuh host agent integrity monitoring rules on critical workstation segments.',
        'Deploy automated n8n playbooks for proactive threat mitigation.'
      ]
    };
  },

  exportCSV(data: Record<string, unknown>[]): void {
    if (!data.length) return;
    const headers = Object.keys(data[0]);
    const csvRows = [
      headers.join(','),
      ...data.map(row =>
        headers
          .map(header => {
            const val = row[header];
            const str = typeof val === 'object' ? JSON.stringify(val) : String(val ?? '');
            return `"${str.replace(/"/g, '""')}"`;
          })
          .join(',')
      )
    ];
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `soc_threat_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  },

  exportJSON(data: unknown): void {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `soc_threat_export_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
};
