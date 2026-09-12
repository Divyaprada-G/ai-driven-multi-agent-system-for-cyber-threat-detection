import React from 'react';
import { Activity, AlertTriangle, ShieldCheck, Globe, Network, Radio } from 'lucide-react';
import { StatCard } from '../common/StatCard';
import { NetworkAgentAnalysis } from '../../types';

interface NetworkMetricsBarProps {
  analysis: NetworkAgentAnalysis;
}

export const NetworkMetricsBar: React.FC<NetworkMetricsBarProps> = ({ analysis }) => {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3" id="network-metrics-bar">
      <StatCard
        id="stat-net-events-analyzed"
        title="Events Analyzed"
        value={analysis.totalEventsAnalyzed.toLocaleString()}
        subtitle="Network packets & flows"
        icon={Activity}
        variant="info"
      />
      <StatCard
        id="stat-net-suspicious"
        title="Suspicious Events"
        value={analysis.suspiciousEventsCount.toLocaleString()}
        subtitle="Anomalies & deviations"
        icon={AlertTriangle}
        variant="warning"
      />
      <StatCard
        id="stat-net-threats"
        title="Potential Threats"
        value={analysis.potentialThreatsCount.toLocaleString()}
        subtitle="Scans, bursts, backdoors"
        icon={Radio}
        variant="danger"
      />
      <StatCard
        id="stat-net-confidence"
        title="Avg. Confidence"
        value={`${analysis.averageConfidence}%`}
        subtitle="Heuristic certainty"
        icon={ShieldCheck}
        variant="emerald"
      />
      <StatCard
        id="stat-net-src-ips"
        title="Unique Source IPs"
        value={analysis.uniqueSourceIps}
        subtitle="Distinct emitters"
        icon={Network}
        variant="default"
      />
      <StatCard
        id="stat-net-dst-ips"
        title="Unique Dest IPs"
        value={analysis.uniqueDestinationIps}
        subtitle="Targeted endpoints"
        icon={Globe}
        variant="default"
      />
    </div>
  );
};
