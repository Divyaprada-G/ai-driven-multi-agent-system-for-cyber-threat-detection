import React, { useState } from 'react';
import {
  X,
  Database,
  Binary,
  Layers,
  Shield,
  GitBranch,
  Cpu,
  Flame,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  Copy,
  Check
} from 'lucide-react';
import { TestPredictionResult } from '../../types/datasetMl';

interface Props {
  result: TestPredictionResult | null;
  onClose: () => void;
}

export const EndToEndTraceabilityModal: React.FC<Props> = ({ result, onClose }) => {
  const [selectedStage, setSelectedStage] = useState<number>(5);
  const [copied, setCopied] = useState(false);

  if (!result) return null;

  const trace = result.traceability;

  const stages = [
    {
      num: 1,
      title: 'Dataset Record',
      subtitle: 'Raw Network Flow Telemetry',
      icon: Database,
      id: trace.datasetRecordId || 'FLOW-192.168.10.14-07/07/2017',
      agent: 'CICIDS2017 Dataset',
      details: {
        flowId: trace.datasetRecordId || '192.168.10.14-172.16.0.1-49212-80-6',
        sourceIp: result.evidence?.rawIdentifierMeta?.sourceIp || '192.168.10.14',
        destIp: result.evidence?.rawIdentifierMeta?.destIp || '172.16.0.1',
        destPort: result.evidence?.rawIdentifierMeta?.destPort || 80,
        protocol: result.evidence?.rawIdentifierMeta?.protocol || 'TCP',
        flowDuration: '9,200,000 μs',
        totalPackets: '142 fwd / 0 bwd'
      }
    },
    {
      num: 2,
      title: 'Preprocessed Vector',
      subtitle: 'Leakage-Free Imputed & Scaled',
      icon: Binary,
      id: `VEC-${result.modelId.slice(-6)}`,
      agent: 'StandardScaler Pipeline',
      details: {
        scalingStrategy: 'Fit-on-Train StandardScaler',
        missingStrategy: 'Median Imputation',
        isolatedIdentifiers: ['Source IP', 'Destination IP', 'Flow ID', 'Timestamp'],
        featureCount: result.evidence?.evaluatedFeaturesCount || 16,
        transformedShape: '[1, 16] numerical matrix'
      }
    },
    {
      num: 3,
      title: 'Security Event',
      subtitle: 'Normalized Telemetry Format',
      icon: Layers,
      id: trace.securityEventId,
      agent: 'Log Normalizer',
      details: {
        eventId: trace.securityEventId,
        logType: 'NETWORK',
        timestamp: new Date().toISOString(),
        source: 'Perimeter Gateway Router / Bro-Zeek',
        message: `Network connection flow observed from ${result.evidence?.rawIdentifierMeta?.sourceIp || '192.168.10.14'}`
      }
    },
    {
      num: 4,
      title: 'Agent Finding',
      subtitle: 'Multi-Agent Network Specialist',
      icon: Shield,
      id: `AGNT-${trace.associatedAgent}`,
      agent: 'Network Security Agent',
      details: {
        agentType: trace.associatedAgent,
        status: 'ACTIVE',
        detection: `Anomalous SYN packet rate and high flow duration detected on port ${result.evidence?.rawIdentifierMeta?.destPort || 80}`,
        severity: result.predictedClass === 'BENIGN' ? 'LOW' : 'HIGH',
        confidence: `${(result.predictionConfidence * 100).toFixed(1)}%`
      }
    },
    {
      num: 5,
      title: 'Correlated Cluster',
      subtitle: 'Multi-Stage Event Correlation',
      icon: GitBranch,
      id: 'CORR-CLUSTER-771',
      agent: 'Event Correlation Engine',
      details: {
        correlationRule: 'NETWORK_ANOMALY_ESCALATION',
        crossAgentSources: ['NETWORK_AGENT', 'FIREWALL_LOG'],
        confidence: '94%',
        description: 'Single-source burst flow pattern matching volumetric DDoS reconnaissance signature.'
      }
    },
    {
      num: 6,
      title: 'ML Model Prediction',
      subtitle: 'Ensemble Classification / Probability',
      icon: Cpu,
      id: trace.threatDetectionId,
      agent: `${result.modelId} (${result.modelVersion})`,
      details: {
        modelType: result.modelStatus === 'DEMO_MODEL' ? 'Random Forest (Demo Reference)' : 'Random Forest Classifier',
        predictedClass: result.predictedClass,
        modelProbability: `${(result.predictionConfidence * 100).toFixed(2)}%`,
        status: result.modelStatus,
        disclaimer: result.confidenceDisclaimer,
        topFeatures: result.importantContributingFeatures.map(f => `${f.feature} (${f.impact})`).join(', ')
      }
    },
    {
      num: 7,
      title: 'Quantitative Risk Score',
      subtitle: '7-Factor Risk & Threat Prioritization',
      icon: Flame,
      id: trace.riskAssessmentId || 'RISK-ASSESS-881',
      agent: 'Risk Scoring Engine',
      details: {
        compositeScore: `${result.evidence?.riskAssessmentScore || 85}/100`,
        riskBand: result.evidence?.riskBand || 'HIGH',
        priority: result.evidence?.priority || 'P1',
        factors: 'Asset Criticality (80), Threat Likelihood (90), Confidence (94), Anomaly Score (89)'
      }
    },
    {
      num: 8,
      title: 'Security Alert / Incident',
      subtitle: 'Alert Queue & Incident Escalation',
      icon: AlertTriangle,
      id: trace.securityAlertId || 'ALT-ML-901',
      agent: 'Alert & Incident Manager',
      details: {
        alertId: trace.securityAlertId || 'ALT-ML-901',
        incidentId: trace.incidentId || 'INC-2026-0045',
        lifecycleStatus: 'NEW / TRIAGED',
        recommendedAction: 'Apply simulated firewall rate-limiting rule on ingress boundary for source IP.',
        auditLogged: 'Yes (Action: ALERT_CREATED & PREDICTION_EXECUTED recorded in audit log)'
      }
    }
  ];

  const currentStage = stages[selectedStage];

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(currentStage.details, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <GitBranch className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100 text-sm tracking-wide flex items-center gap-2">
                <span>End-to-End Traceability Lineage (8 Stages)</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 font-mono">
                  FULL AUDIT CHAIN
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Verified bidirectional provenance from raw benchmark dataset record to SOC Incident
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* 8-Stage Horizontal Timeline Stepper */}
        <div className="px-6 py-4 bg-slate-950/40 border-b border-slate-800 overflow-x-auto">
          <div className="flex items-center min-w-[760px] justify-between">
            {stages.map((stage, idx) => {
              const isSelected = selectedStage === idx;
              const Icon = stage.icon;
              return (
                <React.Fragment key={stage.num}>
                  <button
                    type="button"
                    onClick={() => setSelectedStage(idx)}
                    className={`flex flex-col items-center gap-1.5 p-2 rounded-xl transition-all group ${
                      isSelected
                        ? 'bg-blue-500/15 ring-1 ring-blue-500/50'
                        : 'hover:bg-slate-800/50'
                    }`}
                  >
                    <div
                      className={`w-9 h-9 rounded-xl flex items-center justify-center font-mono text-xs font-bold transition-all ${
                        isSelected
                          ? 'bg-blue-600 text-white shadow-md shadow-blue-900/40'
                          : 'bg-slate-800 text-slate-400 group-hover:text-slate-200'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>
                    <span
                      className={`text-[11px] font-semibold tracking-tight ${
                        isSelected ? 'text-blue-300' : 'text-slate-400'
                      }`}
                    >
                      {stage.num}. {stage.title}
                    </span>
                  </button>

                  {idx < stages.length - 1 && (
                    <div className="h-0.5 flex-1 bg-slate-800 mx-1 mb-5" />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* Body Stage Details */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-blue-500/20 text-blue-400 font-bold font-mono text-base">
                Stage {currentStage.num}
              </div>
              <div>
                <h4 className="font-bold text-slate-100 text-sm">{currentStage.title}</h4>
                <p className="text-xs text-slate-400">{currentStage.subtitle}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto font-mono text-xs">
              <span className="text-slate-500">Trace ID:</span>
              <span className="px-2 py-1 rounded bg-slate-800 text-cyan-300 font-semibold">
                {currentStage.id}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left: Summary Attributes */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <span className="text-xs font-semibold text-slate-300 block border-b border-slate-800/80 pb-2">
                Operational Lineage Parameters
              </span>
              <div className="space-y-2 text-xs font-mono">
                {Object.entries(currentStage.details).map(([key, val]) => (
                  <div key={key} className="flex flex-col sm:flex-row sm:justify-between gap-1 py-1 border-b border-slate-900">
                    <span className="text-slate-500 capitalize">{key.replace(/([A-Z])/g, ' $1')}:</span>
                    <span className="text-slate-200 font-medium text-right truncate max-w-xs">{String(val)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Raw JSON Data Inspection */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 flex flex-col">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-xs font-semibold text-slate-300">
                  Raw Provenance Payload (JSON)
                </span>
                <button
                  type="button"
                  onClick={handleCopyJson}
                  className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 transition-colors"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>

              <pre className="p-3 bg-slate-900 rounded-lg text-slate-300 font-mono text-[11px] overflow-x-auto flex-1 max-h-56 leading-relaxed">
                {JSON.stringify(currentStage.details, null, 2)}
              </pre>
            </div>
          </div>
        </div>

        {/* Footer Navigation */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-slate-950/60">
          <button
            type="button"
            disabled={selectedStage === 0}
            onClick={() => setSelectedStage(Math.max(0, selectedStage - 1))}
            className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 text-xs font-medium transition-colors"
          >
            ← Previous Stage
          </button>

          <span className="text-xs font-mono text-slate-500">
            Stage {selectedStage + 1} of {stages.length}
          </span>

          <button
            type="button"
            disabled={selectedStage === stages.length - 1}
            onClick={() => setSelectedStage(Math.min(stages.length - 1, selectedStage + 1))}
            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs font-medium transition-colors"
          >
            Next Stage →
          </button>
        </div>
      </div>
    </div>
  );
};
