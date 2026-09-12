import React, { useState } from 'react';
import { Sliders, X, Check, RefreshCw, ShieldAlert, Clock, Layers } from 'lucide-react';
import { AlertGenerationConfig } from '../../types/alertIncident';
import { alertManager } from '../../services/alertIncident/alertManager';

interface AlertGenerationRulesModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

export const AlertGenerationRulesModal: React.FC<AlertGenerationRulesModalProps> = ({
  isOpen,
  onClose,
  onSaved
}) => {
  if (!isOpen) return null;

  const currentConfig = alertManager.getConfig();
  const [config, setConfig] = useState<AlertGenerationConfig>(currentConfig);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSave = () => {
    alertManager.updateConfig(config);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      if (onSaved) onSaved();
      onClose();
    }, 500);
  };

  const handleReset = () => {
    setConfig({
      criticalRiskAutoAlert: true,
      highRiskAutoAlert: true,
      mediumRiskAutoAlert: true,
      mediumRiskThreshold: 50,
      lowRiskAutoAlert: false,
      lowRiskThreshold: 30,
      deduplicationWindowMinutes: 15,
      autoGroupCorrelatedIncidents: true
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
      <div
        id="modal-alert-generation-rules"
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-5 my-8 text-slate-200"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-600/40 text-cyan-400">
              <Sliders className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                Pipeline Rule Engine
              </span>
              <h2 className="text-lg font-bold text-white tracking-tight">
                Alert Generation & Deduplication Policy
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs text-slate-400">
          Control which Risk Assessment outcomes automatically trigger security alerts, configure deduplication burst dampening, and specify grouping criteria.
        </p>

        {/* Rules Grid */}
        <div className="space-y-4">
          {/* Critical & High */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-3">
            <div className="text-xs font-mono text-slate-300 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              High-Priority Automated Triggers
            </div>

            <div className="space-y-2.5">
              <label className="flex items-center justify-between text-xs font-mono cursor-pointer">
                <div>
                  <span className="text-rose-400 font-bold">CRITICAL Severity (P1)</span>
                  <p className="text-[11px] text-slate-400 font-sans">Always generate immediate alert for Critical Risk (90-100 score)</p>
                </div>
                <input
                  type="checkbox"
                  checked={config.criticalRiskAutoAlert}
                  onChange={e => setConfig({ ...config, criticalRiskAutoAlert: e.target.checked })}
                  className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-rose-500 focus:ring-0 focus:ring-offset-0"
                />
              </label>

              <label className="flex items-center justify-between text-xs font-mono cursor-pointer">
                <div>
                  <span className="text-orange-400 font-bold">HIGH Severity (P2)</span>
                  <p className="text-[11px] text-slate-400 font-sans">Always generate immediate alert for High Risk (70-89 score)</p>
                </div>
                <input
                  type="checkbox"
                  checked={config.highRiskAutoAlert}
                  onChange={e => setConfig({ ...config, highRiskAutoAlert: e.target.checked })}
                  className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-orange-500 focus:ring-0 focus:ring-offset-0"
                />
              </label>
            </div>
          </div>

          {/* Medium Risk Threshold */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-mono text-amber-300 font-semibold uppercase tracking-wider">
                MEDIUM Severity Threshold (P3)
              </div>
              <input
                type="checkbox"
                checked={config.mediumRiskAutoAlert}
                onChange={e => setConfig({ ...config, mediumRiskAutoAlert: e.target.checked })}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-amber-500 focus:ring-0 focus:ring-offset-0"
              />
            </div>
            <p className="text-[11px] text-slate-400">
              Only generate alerts for Medium findings if the calculated risk score equals or exceeds the threshold.
            </p>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={30}
                max={70}
                step={5}
                disabled={!config.mediumRiskAutoAlert}
                value={config.mediumRiskThreshold}
                onChange={e => setConfig({ ...config, mediumRiskThreshold: Number(e.target.value) })}
                className="flex-1 accent-amber-500 disabled:opacity-40"
              />
              <span className="text-xs font-mono font-bold text-amber-400 w-12 text-right">
                &ge; {config.mediumRiskThreshold}
              </span>
            </div>
          </div>

          {/* Low Risk Suppression */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-2">
            <label className="flex items-center justify-between text-xs font-mono cursor-pointer">
              <div>
                <span className="text-blue-400 font-bold">LOW Severity Monitored Events (P4)</span>
                <p className="text-[11px] text-slate-400 font-sans">
                  Suppress Low severity alerts by default (retained in telemetry logs without alerting on-call).
                </p>
              </div>
              <input
                type="checkbox"
                checked={config.lowRiskAutoAlert}
                onChange={e => setConfig({ ...config, lowRiskAutoAlert: e.target.checked })}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-blue-500 focus:ring-0 focus:ring-offset-0"
              />
            </label>
          </div>

          {/* Deduplication Window */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-3">
            <div className="text-xs font-mono text-slate-300 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-cyan-400" />
              Deduplication Time Window
            </div>
            <p className="text-[11px] text-slate-400">
              Correlated alerts sharing the same threat pattern and entity within this window will increment the burst occurrence counter instead of creating duplicates.
            </p>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={5}
                max={60}
                step={5}
                value={config.deduplicationWindowMinutes}
                onChange={e => setConfig({ ...config, deduplicationWindowMinutes: Number(e.target.value) })}
                className="flex-1 accent-cyan-500"
              />
              <span className="text-xs font-mono font-bold text-cyan-400 w-16 text-right">
                {config.deduplicationWindowMinutes} min
              </span>
            </div>
          </div>

          {/* Auto Grouping */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80">
            <label className="flex items-center justify-between text-xs font-mono cursor-pointer">
              <div className="flex items-start gap-2">
                <Layers className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <span className="text-slate-200 font-bold">Auto-Group Correlated Alerts into Incidents</span>
                  <p className="text-[11px] text-slate-400 font-sans">
                    Automatically link alerts sharing identical correlation clusters to unified Security Incidents.
                  </p>
                </div>
              </div>
              <input
                type="checkbox"
                checked={config.autoGroupCorrelatedIncidents}
                onChange={e => setConfig({ ...config, autoGroupCorrelatedIncidents: e.target.checked })}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 ml-2"
              />
            </label>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800">
          <button
            type="button"
            onClick={handleReset}
            className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              id="btn-save-alert-rules"
              type="button"
              onClick={handleSave}
              className="px-4 py-1.5 text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-lg shadow-cyan-600/20"
            >
              {savedSuccess ? <Check className="w-3.5 h-3.5" /> : null}
              <span>{savedSuccess ? 'Saved' : 'Apply Rules'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
