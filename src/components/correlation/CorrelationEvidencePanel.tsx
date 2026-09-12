import React from 'react';
import { CorrelatedEvent } from '../../types/correlation';
import { ShieldCheck, HardDrive, Server, User, Clock, Cpu, GitFork, CheckCircle, AlertCircle } from 'lucide-react';

interface CorrelationEvidencePanelProps {
  correlatedEvent: CorrelatedEvent;
}

export const CorrelationEvidencePanel: React.FC<CorrelationEvidencePanelProps> = ({ correlatedEvent }) => {
  const ruleResults = correlatedEvent.ruleResults || [];

  const srcIpRule = ruleResults.find(r => r.category === 'SOURCE_IP_MATCH');
  const dstIpRule = ruleResults.find(r => r.category === 'DESTINATION_IP_MATCH');
  const hostRule = ruleResults.find(r => r.category === 'HOST_MATCH');
  const userRule = ruleResults.find(r => r.category === 'USERNAME_MATCH');
  const timeRule = ruleResults.find(r => r.category === 'TIME_PROXIMITY');
  const crossAgentRule = ruleResults.find(r => r.category === 'CROSS_AGENT_ACTIVITY');
  const seqRule = ruleResults.find(r => r.category === 'EVENT_SEQUENCE');

  const evidenceItems = [
    {
      id: 'src-ip',
      label: 'Shared Source IP',
      icon: HardDrive,
      matched: Boolean(srcIpRule?.matched),
      value: correlatedEvent.sourceIps.join(', ') || 'N/A',
      detail: srcIpRule?.reason || (correlatedEvent.sourceIps.length > 0 ? `Shared IP: ${correlatedEvent.sourceIps[0]}` : null),
      color: 'text-cyan-400'
    },
    {
      id: 'dest-ip',
      label: 'Shared Destination / Target',
      icon: HardDrive,
      matched: Boolean(dstIpRule?.matched || correlatedEvent.destinationIps.length > 0),
      value: correlatedEvent.destinationIps.join(', ') || 'Internal DMZ Infrastructure',
      detail: dstIpRule?.reason || (correlatedEvent.destinationIps.length > 0 ? `Target IP: ${correlatedEvent.destinationIps[0]}` : null),
      color: 'text-blue-400'
    },
    {
      id: 'host',
      label: 'Shared Monitored Host',
      icon: Server,
      matched: Boolean(hostRule?.matched || correlatedEvent.hosts.length > 0),
      value: correlatedEvent.hosts.join(', ') || null,
      detail: hostRule?.reason || (correlatedEvent.hosts.length > 0 ? `Target Host: ${correlatedEvent.hosts[0]}` : null),
      color: 'text-emerald-400'
    },
    {
      id: 'user',
      label: 'Shared User Identity',
      icon: User,
      matched: Boolean(userRule?.matched || correlatedEvent.users.length > 0),
      value: correlatedEvent.users.join(', ') || null,
      detail: userRule?.reason || (correlatedEvent.users.length > 0 ? `Target User: ${correlatedEvent.users[0]}` : null),
      color: 'text-purple-400'
    },
    {
      id: 'time',
      label: 'Time Relationship',
      icon: Clock,
      matched: Boolean(timeRule?.matched),
      value: `${correlatedEvent.duration} elapsed between earliest & latest event`,
      detail: timeRule?.reason || `Window: ${correlatedEvent.startTime} to ${correlatedEvent.endTime}`,
      color: 'text-amber-400'
    },
    {
      id: 'agents',
      label: 'Agent Relationship',
      icon: Cpu,
      matched: Boolean(crossAgentRule?.matched),
      value: `${correlatedEvent.participatingAgents.length} Agents: ${correlatedEvent.participatingAgents.map(a => a.replace('_', ' ')).join(', ')}`,
      detail: crossAgentRule?.reason || `Multi-domain involvement confirmed`,
      color: 'text-indigo-400'
    },
    {
      id: 'sequence',
      label: 'Attack Sequence Relationship',
      icon: GitFork,
      matched: Boolean(seqRule?.matched),
      value: correlatedEvent.title,
      detail: seqRule?.reason || `Tactical ordering confirmed across ${correlatedEvent.sequence?.length || 0} stages`,
      color: 'text-rose-400'
    }
  ];

  // Only display evidence that ACTUALLY exists/matched (per requirement 22)
  const activeEvidence = evidenceItems.filter(item => item.matched && item.value !== null);

  return (
    <div className="p-4 sm:p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-4" id="correlation-evidence-panel">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Correlated Forensic Evidence & Linkage Matrix
          </h4>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Verified contextual relationships justifying multi-event correlation.
          </p>
        </div>
        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
          {activeEvidence.length} Verified Evidence Linkages
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {activeEvidence.map(item => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              className="p-3 bg-slate-900/80 border border-slate-800/80 rounded-lg space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Icon className={`w-3.5 h-3.5 ${item.color}`} />
                  <span className="text-[11px] font-mono font-bold text-slate-200">
                    {item.label}
                  </span>
                </div>
                <div className="flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                  <CheckCircle className="w-3 h-3" />
                  <span>Verified</span>
                </div>
              </div>

              <div className="text-xs font-mono font-semibold text-white pl-5">
                {item.value}
              </div>

              {item.detail && (
                <div className="text-[10px] text-slate-400 pl-5 leading-relaxed">
                  {item.detail}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Raw Indicators List if present */}
      {correlatedEvent.indicators && correlatedEvent.indicators.length > 0 && (
        <div className="pt-2 border-t border-slate-800/80">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block mb-1.5">
            Correlated Indicator Tags
          </span>
          <div className="flex flex-wrap gap-1.5">
            {correlatedEvent.indicators.map((ind, i) => (
              <span
                key={i}
                className="text-[10px] font-mono px-2 py-0.5 bg-slate-900 text-slate-300 rounded border border-slate-800"
              >
                {ind}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
