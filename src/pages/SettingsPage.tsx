import React, { useState } from 'react';
import { Settings, Shield, Cpu, Bell, Sliders, Webhook, Save, CheckCircle2 } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'general' | 'detection' | 'agents' | 'alerts' | 'integration' | 'system'>('general');
  const [savedFeedback, setSavedFeedback] = useState(false);

  // Settings State Form
  const [generalConfig, setGeneralConfig] = useState({
    platformName: 'AI Driven Multi-Agent Cyber Threat Detection Platform',
    environment: 'Demo / Academic Simulation',
    retentionDays: '30',
    autoCorrelationEnabled: true
  });

  const [integrationConfig, setIntegrationConfig] = useState({
    n8nWebhookUrl: 'https://automation.internal.local/webhook/soc-triage-pipeline',
    suricataEvePath: '/var/log/suricata/eve.json',
    wazuhApiUrl: 'https://wazuh-manager.internal.local:55000',
    mockModeEnabled: true
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedFeedback(true);
    setTimeout(() => setSavedFeedback(false), 3000);
  };

  return (
    <div className="space-y-6" id="page-settings">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Configuration & Pipeline Parameters
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          System Settings & Platform Architecture
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Manage system thresholds, specialized agent heuristic sensitivity, integration webhooks (n8n), and data ingestion paths.
        </p>
      </div>

      {savedFeedback && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-700/80 rounded-xl text-xs font-mono text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>Configuration parameters updated successfully for active SOC session.</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-1.5 p-1 bg-slate-900/90 border border-slate-800 rounded-xl">
        {[
          { id: 'general', label: 'General', icon: Settings },
          { id: 'detection', label: 'Detection', icon: Shield },
          { id: 'agents', label: 'Agents', icon: Cpu },
          { id: 'alerts', label: 'Alert Configuration', icon: Bell },
          { id: 'integration', label: 'Integration', icon: Webhook },
          { id: 'system', label: 'System Information', icon: Sliders }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-settings-${tab.id}`}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono transition-colors ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <form onSubmit={handleSave} className="p-6 bg-slate-900/70 border border-slate-800 rounded-xl space-y-6">
        {/* General */}
        {activeTab === 'general' && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white font-mono">General SOC Platform Configuration</h3>

            <div className="space-y-3 max-w-xl text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Platform Display Name</label>
                <input
                  type="text"
                  value={generalConfig.platformName}
                  onChange={e => setGeneralConfig({ ...generalConfig, platformName: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Telemetry Data Retention Window (Days)</label>
                <input
                  type="number"
                  value={generalConfig.retentionDays}
                  onChange={e => setGeneralConfig({ ...generalConfig, retentionDays: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="pt-2 flex items-center gap-3">
                <input
                  type="checkbox"
                  id="chk-auto-correlation"
                  checked={generalConfig.autoCorrelationEnabled}
                  onChange={e => setGeneralConfig({ ...generalConfig, autoCorrelationEnabled: e.target.checked })}
                  className="accent-cyan-500 w-4 h-4 rounded"
                />
                <label htmlFor="chk-auto-correlation" className="text-slate-300">
                  Enable Autonomous Cross-Agent Correlation Pipeline
                </label>
              </div>
            </div>
          </div>
        )}

        {/* Detection */}
        {activeTab === 'detection' && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white font-mono">Threat Detection & ML Inference Thresholds</h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-2xl text-xs font-mono">
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-slate-300 font-bold block">Anomaly Detection Cutoff</span>
                <p className="text-[11px] text-slate-500">Isolation Forest contamination factor.</p>
                <input type="range" min="1" max="10" defaultValue="5" className="w-full accent-cyan-400" />
                <div className="flex justify-between text-[10px] text-slate-400">
                  <span>Conservative (0.01)</span>
                  <span>Aggressive (0.10)</span>
                </div>
              </div>

              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-slate-300 font-bold block">Minimum Confidence for Alerting</span>
                <p className="text-[11px] text-slate-500">Suppress low confidence heuristic flags.</p>
                <input type="range" min="50" max="95" defaultValue="80" className="w-full accent-cyan-400" />
                <div className="flex justify-between text-[10px] text-slate-400">
                  <span>50%</span>
                  <span>80% Default</span>
                  <span>95%</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Agents */}
        {activeTab === 'agents' && (
          <div className="space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold text-white font-mono">Specialized Agent Configuration</h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-cyan-400 font-bold block">Network Agent</span>
                <p className="text-[11px] text-slate-400">Port sweep detection window: 500ms</p>
                <p className="text-[11px] text-slate-400">DNS Tunneling entropy threshold: 4.5</p>
              </div>

              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-emerald-400 font-bold block">System Agent</span>
                <p className="text-[11px] text-slate-400">Monitored process privileges: High/System</p>
                <p className="text-[11px] text-slate-400">PowerShell base64 flag decode: Enabled</p>
              </div>

              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-purple-400 font-bold block">Application Agent</span>
                <p className="text-[11px] text-slate-400">OWASP SQLi Regex heuristics: v3.4</p>
                <p className="text-[11px] text-slate-400">Auth burst failure threshold: 10/min</p>
              </div>
            </div>
          </div>
        )}

        {/* Alerts */}
        {activeTab === 'alerts' && (
          <div className="space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold text-white font-mono">Alert Dispatch Rules & Channels</h3>
            <div className="space-y-2 max-w-xl">
              <div className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span>Dispatch Critical Alerts to PagerDuty On-Call</span>
                <input type="checkbox" defaultChecked className="accent-cyan-500 w-4 h-4" />
              </div>
              <div className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span>Relay High Severity to Slack Channel (#soc-alerts)</span>
                <input type="checkbox" defaultChecked className="accent-cyan-500 w-4 h-4" />
              </div>
              <div className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span>Auto-enqueue Correlated Incidents to n8n Webhook</span>
                <input type="checkbox" defaultChecked className="accent-cyan-500 w-4 h-4" />
              </div>
            </div>
          </div>
        )}

        {/* Integration */}
        {activeTab === 'integration' && (
          <div className="space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <Webhook className="w-4 h-4 text-cyan-400" />
              External Systems & Automation Pipeline (Future Prompts)
            </h3>
            <p className="text-xs text-slate-400">
              Configured connection boundaries for n8n webhooks, Wazuh manager API, and Suricata telemetry.
            </p>

            <div className="space-y-3 max-w-xl">
              <div>
                <label className="text-slate-400 block mb-1">n8n Automation Webhook URL</label>
                <input
                  type="text"
                  value={integrationConfig.n8nWebhookUrl}
                  onChange={e => setIntegrationConfig({ ...integrationConfig, n8nWebhookUrl: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Suricata EVE Log File Path</label>
                <input
                  type="text"
                  value={integrationConfig.suricataEvePath}
                  onChange={e => setIntegrationConfig({ ...integrationConfig, suricataEvePath: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Wazuh Manager REST API Endpoint</label>
                <input
                  type="text"
                  value={integrationConfig.wazuhApiUrl}
                  onChange={e => setIntegrationConfig({ ...integrationConfig, wazuhApiUrl: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>
          </div>
        )}

        {/* System Information */}
        {activeTab === 'system' && (
          <div className="space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold text-white font-mono">Academic Project & Architecture Information</h3>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 text-slate-300">
              <div>
                <span className="text-slate-500">Project Title: </span>
                <span className="text-cyan-400 font-bold">AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION</span>
              </div>
              <div>
                <span className="text-slate-500">Academic Scope: </span>
                <span>BE Major Project (Semester 7)</span>
              </div>
              <div>
                <span className="text-slate-500">Architecture Pipeline: </span>
                <span className="text-emerald-400">
                  Network/System/App Logs → 3 Domain Agents → Correlation Engine → ML Classifier → Risk Scoring → Alerts / n8n
                </span>
              </div>
              <div>
                <span className="text-slate-500">Execution Runtime: </span>
                <span>TypeScript / React 19 / Vite / Tailwind CSS / Recharts</span>
              </div>
            </div>
          </div>
        )}

        {/* Save Button */}
        <div className="flex justify-end pt-4 border-t border-slate-800">
          <button
            type="submit"
            id="btn-save-settings"
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-bold inline-flex items-center gap-2 transition-colors shadow-sm"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Configuration</span>
          </button>
        </div>
      </form>
    </div>
  );
};
