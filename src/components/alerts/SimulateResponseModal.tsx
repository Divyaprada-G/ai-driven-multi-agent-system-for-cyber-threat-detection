import React, { useState } from 'react';
import {
  ShieldAlert,
  X,
  AlertTriangle,
  CheckCircle2,
  Terminal,
  Lock,
  WifiOff,
  FileSpreadsheet,
  Send,
  Ticket
} from 'lucide-react';
import { ResponseSimulationActionType, SimulatedResponseRecord } from '../../types/alertIncident';
import { alertManager } from '../../services/alertIncident/alertManager';
import { incidentManager } from '../../services/alertIncident/incidentManager';

interface SimulateResponseModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetId: string;
  targetType: 'ALERT' | 'INCIDENT';
  defaultTargetEntity?: string;
  defaultAction?: ResponseSimulationActionType;
  onExecuted?: (record: SimulatedResponseRecord) => void;
}

export const SimulateResponseModal: React.FC<SimulateResponseModalProps> = ({
  isOpen,
  onClose,
  targetId,
  targetType,
  defaultTargetEntity = '192.168.1.100',
  defaultAction = 'BLOCK_IP',
  onExecuted
}) => {
  if (!isOpen) return null;

  const [actionType, setActionType] = useState<ResponseSimulationActionType>(defaultAction);
  const [target, setTarget] = useState(defaultTargetEntity);
  const [executedRecord, setExecutedRecord] = useState<SimulatedResponseRecord | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);

  const ACTIONS: Array<{
    type: ResponseSimulationActionType;
    label: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    defaultTarget: string;
  }> = [
    {
      type: 'BLOCK_IP',
      label: 'Simulate Firewall IP Quarantine',
      description: 'Simulates pushing an ingress drop rule to edge and core firewalls.',
      icon: Lock,
      defaultTarget: defaultTargetEntity.includes('.') ? defaultTargetEntity : '198.51.100.42'
    },
    {
      type: 'ISOLATE_HOST',
      label: 'Simulate Host Endpoint Isolation',
      description: 'Simulates severing network connections on host except for secure SOC EDR tunnel.',
      icon: WifiOff,
      defaultTarget: defaultTargetEntity.includes('srv') || defaultTargetEntity.includes('workstation') ? defaultTargetEntity : 'workstation-fin-04'
    },
    {
      type: 'WAF_RULE_DEPLOY',
      label: 'Simulate WAF Rule Deployment',
      description: 'Simulates staging a regex blocking signature on the application reverse proxy.',
      icon: Terminal,
      defaultTarget: '/api/v2/checkout'
    },
    {
      type: 'REVOKE_TOKEN',
      label: 'Simulate Session / Token Revocation',
      description: 'Simulates invalidating active OAuth tokens and forced user re-authentication.',
      icon: Lock,
      defaultTarget: 'user.compromised@corp.internal'
    },
    {
      type: 'ESCALATE_TICKET',
      label: 'Simulate SOC Incident Ticket Escalation',
      description: 'Simulates generating a prioritized incident ticket in enterprise ITSM.',
      icon: Ticket,
      defaultTarget: `${targetType}-${targetId}`
    },
    {
      type: 'GENERATE_REPORT',
      label: 'Simulate Forensic Audit Report',
      description: 'Simulates compiling chain-of-custody PDF artifact for legal & compliance.',
      icon: FileSpreadsheet,
      defaultTarget: `Audit-Package-${targetId}`
    }
  ];

  const currentActionMeta = ACTIONS.find(a => a.type === actionType) || ACTIONS[0];

  const handleExecute = () => {
    setIsExecuting(true);
    setTimeout(() => {
      let record: SimulatedResponseRecord | null = null;
      if (targetType === 'ALERT') {
        record = alertManager.recordSimulatedResponse(targetId, actionType, target, currentActionMeta.label);
      } else {
        record = incidentManager.recordSimulatedResponse(targetId, actionType, target, currentActionMeta.label);
      }

      setIsExecuting(false);
      setExecutedRecord(record);
      if (record && onExecuted) {
        onExecuted(record);
      }
    }, 400);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
      <div
        id="modal-simulate-response"
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 my-8 text-slate-200"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-950/60 border border-amber-600/40 text-amber-400">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 uppercase tracking-wider font-bold">
                  Safe Simulation Mode
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {targetType}: {targetId}
                </span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight mt-1">
                Simulate Automated Incident Response Action
              </h2>
            </div>
          </div>
          <button
            id="btn-close-sim-modal"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Prominent Mandatory Safety Warning Banner */}
        <div className="p-4 bg-amber-950/40 border-2 border-amber-600/60 rounded-xl space-y-1.5">
          <div className="flex items-center gap-2 text-amber-300 font-mono text-xs font-bold uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            SAFETY & ETHICS NOTICE: SIMULATED ACTION ONLY
          </div>
          <p className="text-xs text-amber-100/90 leading-relaxed font-mono">
            A real firewall, IP blocking, or host isolation action would be requested here. In this demo/academic environment, <span className="font-bold underline text-amber-200">no network configuration was changed</span>, no shell commands were executed, and no external endpoints were modified. All actions are safely logged for academic audit trails.
          </p>
        </div>

        {/* Action Type Selection */}
        {!executedRecord ? (
          <div className="space-y-4">
            <div>
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2">
                Select Containment Action to Simulate:
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {ACTIONS.map(item => {
                  const Icon = item.icon;
                  const isSelected = actionType === item.type;
                  return (
                    <button
                      key={item.type}
                      type="button"
                      onClick={() => {
                        setActionType(item.type);
                        setTarget(item.defaultTarget);
                      }}
                      className={`p-3 text-left rounded-xl border transition-all flex items-start gap-2.5 ${
                        isSelected
                          ? 'bg-cyan-950/60 border-cyan-500 text-white shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                          : 'bg-slate-950/70 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                      }`}
                    >
                      <Icon className={`w-4 h-4 shrink-0 mt-0.5 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                      <div>
                        <div className="text-xs font-bold tracking-tight">{item.label}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{item.description}</div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Target Input */}
            <div>
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1.5">
                Simulated Target Asset / Entity:
              </label>
              <input
                id="input-sim-target"
                type="text"
                value={target}
                onChange={e => setTarget(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                placeholder="e.g. 192.168.1.100, host-01, /checkout"
              />
            </div>

            {/* Simulated Command Preview */}
            <div>
              <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Simulated Dry-Run Payload Preview:
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 leading-relaxed overflow-x-auto">
                <span className="text-slate-500"># DRY-RUN SIMULATION (Non-Destructive)</span>
                <br />
                <span className="text-cyan-400">DISPATCH</span> {actionType} &rarr; <span className="text-amber-300">{target}</span>
                <br />
                <span className="text-slate-400">AUDIT_LOG</span>: Target ID: {targetId} | Mode: SAFE_SIMULATION
              </div>
            </div>

            {/* Execution CTA */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                id="btn-confirm-simulate-response"
                type="button"
                onClick={handleExecute}
                disabled={isExecuting || !target.trim()}
                className="px-4 py-2 bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-slate-950 font-bold rounded-lg text-xs font-mono inline-flex items-center gap-2 transition-all shadow-lg shadow-amber-500/20 disabled:opacity-50"
              >
                <ShieldAlert className="w-4 h-4" />
                <span>{isExecuting ? 'Simulating...' : 'Execute Simulated Response'}</span>
              </button>
            </div>
          </div>
        ) : (
          /* Success Screen */
          <div className="space-y-4 py-2">
            <div className="p-4 bg-emerald-950/40 border border-emerald-600/40 rounded-xl flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-bold text-emerald-200">
                  Response Action Simulated Successfully
                </h4>
                <p className="text-xs text-emerald-300/80 mt-1 font-mono">
                  Action was registered in the audit history. No real network configuration changes were executed.
                </p>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 font-mono text-xs text-slate-300">
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-500">Record ID:</span>
                <span className="text-cyan-400 font-bold">{executedRecord.id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-500">Timestamp:</span>
                <span className="text-slate-300">{executedRecord.timestamp}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-500">Action:</span>
                <span className="text-amber-300 font-semibold">{executedRecord.title}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Target:</span>
                <span className="text-white">{executedRecord.target}</span>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-white rounded-lg border border-slate-700 transition-colors"
              >
                Close Simulation
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
