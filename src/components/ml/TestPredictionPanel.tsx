import React, { useState } from 'react';
import {
  Sparkles,
  Play,
  CheckCircle2,
  AlertTriangle,
  Info,
  Shield,
  Layers,
  ArrowRight,
  ExternalLink,
  Flame,
  Binary
} from 'lucide-react';
import {
  TrainedModelArtifact,
  TestPredictionResult,
  TestPredictionRequest
} from '../../types/datasetMl';
import { mlTrainingService } from '../../services/mlTrainingService';

interface Props {
  activeModel: TrainedModelArtifact;
  onViewTraceability: (result: TestPredictionResult) => void;
}

const SAMPLE_TEST_CASES = [
  {
    name: 'SYN Flood / DDoS Signature',
    type: 'DDoS',
    features: {
      'Flow Duration': 9200000,
      'Total Fwd Packets': 142,
      'Total Backward Packets': 0,
      'Total Length of Fwd Packets': 9088,
      'Total Length of Bwd Packets': 0,
      'Flow Bytes/s': 965.75,
      'Flow Packets/s': 850.0,
      'Flow IAT Mean': 66269.0,
      'Fwd IAT Mean': 66739.0,
      'Bwd IAT Mean': 0.0,
      'FIN Flag Count': 0,
      'SYN Flag Count': 142,
      'RST Flag Count': 0,
      'ACK Flag Count': 0,
      'Down/Up Ratio': 0.0,
      'Average Packet Size': 64.0,
      dur: 0.48,
      sbytes: 48000,
      dbytes: 0,
      sttl: 254,
      dttl: 0,
      sloss: 12,
      dloss: 0,
      Sload: 799649.33,
      Dload: 0.0,
      Spkts: 650,
      Dpkts: 0,
      smeansz: 1500,
      dmeansz: 0,
      tcprtt: 0.0
    },
    rawIdentifiers: {
      flowId: '192.168.10.14-172.16.0.1-49212-80-6',
      sourceIp: '192.168.10.14',
      destIp: '172.16.0.1',
      sourcePort: 49212,
      destPort: 80,
      protocol: 'TCP'
    }
  },
  {
    name: 'Rapid Port Scan Telemetry',
    type: 'PortScan',
    features: {
      'Flow Duration': 1120,
      'Total Fwd Packets': 1,
      'Total Backward Packets': 1,
      'Total Length of Fwd Packets': 0,
      'Total Length of Bwd Packets': 0,
      'Flow Bytes/s': 0.0,
      'Flow Packets/s': 1785.71,
      'Flow IAT Mean': 1120.0,
      'Fwd IAT Mean': 0.0,
      'Bwd IAT Mean': 0.0,
      'FIN Flag Count': 0,
      'SYN Flag Count': 1,
      'RST Flag Count': 1,
      'ACK Flag Count': 0,
      'Down/Up Ratio': 1.0,
      'Average Packet Size': 0.0,
      dur: 0.000004,
      sbytes: 200,
      dbytes: 0,
      sttl: 254,
      dttl: 0,
      sloss: 0,
      dloss: 0,
      Sload: 200000000.0,
      Dload: 0.0,
      Spkts: 2,
      Dpkts: 0,
      smeansz: 100,
      dmeansz: 0,
      tcprtt: 0.0
    },
    rawIdentifiers: {
      flowId: '172.16.0.5-192.168.10.50-51002-23-6',
      sourceIp: '172.16.0.5',
      destIp: '192.168.10.50',
      sourcePort: 51002,
      destPort: 23,
      protocol: 'TCP'
    }
  },
  {
    name: 'Standard HTTPS Benign Flow',
    type: 'BENIGN',
    features: {
      'Flow Duration': 18900,
      'Total Fwd Packets': 2,
      'Total Backward Packets': 2,
      'Total Length of Fwd Packets': 120,
      'Total Length of Bwd Packets': 240,
      'Flow Bytes/s': 19047.61,
      'Flow Packets/s': 211.64,
      'Flow IAT Mean': 6300.0,
      'Fwd IAT Mean': 0.0,
      'Bwd IAT Mean': 0.0,
      'FIN Flag Count': 0,
      'SYN Flag Count': 1,
      'RST Flag Count': 0,
      'ACK Flag Count': 1,
      'Down/Up Ratio': 1.0,
      'Average Packet Size': 90.0,
      dur: 0.121478,
      sbytes: 724,
      dbytes: 268,
      sttl: 254,
      dttl: 252,
      sloss: 0,
      dloss: 0,
      Sload: 43003.67,
      Dload: 14372.97,
      Spkts: 10,
      Dpkts: 6,
      smeansz: 72,
      dmeansz: 45,
      tcprtt: 0.00065
    },
    rawIdentifiers: {
      flowId: '192.168.10.53-172.16.0.1-60100-443-6',
      sourceIp: '192.168.10.53',
      destIp: '172.16.0.1',
      sourcePort: 60100,
      destPort: 443,
      protocol: 'TCP'
    }
  }
];

export const TestPredictionPanel: React.FC<Props> = ({ activeModel, onViewTraceability }) => {
  const [selectedPreset, setSelectedPreset] = useState(0);
  const [featureInputs, setFeatureInputs] = useState<Record<string, any>>(SAMPLE_TEST_CASES[0].features);
  const [rawIdentifiers, setRawIdentifiers] = useState<Record<string, any>>(SAMPLE_TEST_CASES[0].rawIdentifiers);
  const [predictionResult, setPredictionResult] = useState<TestPredictionResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSelectPreset = (idx: number) => {
    setSelectedPreset(idx);
    setFeatureInputs(SAMPLE_TEST_CASES[idx].features);
    setRawIdentifiers(SAMPLE_TEST_CASES[idx].rawIdentifiers);
    setPredictionResult(null);
    setErrorMessage(null);
  };

  const handleRunInference = async () => {
    setLoading(true);
    setErrorMessage(null);

    try {
      const req: TestPredictionRequest = {
        modelId: activeModel.modelId,
        featureValues: featureInputs,
        rawIdentifierMeta: rawIdentifiers
      };

      const res = await mlTrainingService.predictSample(req);
      setPredictionResult(res);
    } catch (err: any) {
      setErrorMessage(err.message || 'Inference execution failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="test-prediction-panel" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
              Test Prediction on Unseen Data & Pipeline Escalation
            </h3>
            <p className="text-xs text-slate-400">
              Evaluate real-time inference on held-out records, extract probability, and dispatch through Risk Scoring & Alert Manager
            </p>
          </div>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          Model: <span className="text-cyan-300 font-semibold">{activeModel.modelId}</span>
        </div>
      </div>

      {/* Preset Test Case Selector */}
      <div className="space-y-2">
        <span className="text-xs text-slate-400 font-medium block">
          Choose a Real Network Flow Test Sample:
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {SAMPLE_TEST_CASES.map((preset, idx) => {
            const isSelected = selectedPreset === idx;
            return (
              <button
                key={preset.name}
                type="button"
                onClick={() => handleSelectPreset(idx)}
                className={`text-left p-3 rounded-lg border text-xs transition-all ${
                  isSelected
                    ? 'border-emerald-500 bg-emerald-500/10 text-slate-100 ring-1 ring-emerald-500/30'
                    : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between font-semibold">
                  <span>{preset.name}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {preset.type}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">
                  {preset.rawIdentifiers.sourceIp} → {preset.rawIdentifiers.destIp}:{preset.rawIdentifiers.destPort}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Feature Parameters Grid Preview */}
      <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
            <Binary className="w-3.5 h-3.5 text-cyan-400" />
            Unseen Telemetry Feature Vector (Input to Trained Model)
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            {activeModel.selectedFeatures.length} Active Features
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 max-h-48 overflow-y-auto pr-1">
          {activeModel.selectedFeatures.slice(0, 12).map(feat => {
            const val = featureInputs[feat] ?? 0;
            return (
              <div key={feat} className="p-2 rounded bg-slate-900 border border-slate-800/80">
                <span className="text-[10px] text-slate-400 truncate block font-mono" title={feat}>
                  {feat}
                </span>
                <span className="text-xs font-bold text-slate-200 font-mono block mt-0.5">
                  {String(val)}
                </span>
              </div>
            );
          })}
        </div>

        <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Flow ID: <strong className="text-slate-200">{rawIdentifiers.flowId}</strong></span>
          <span>Protocol: <strong className="text-slate-200">{rawIdentifiers.protocol}</strong></span>
        </div>
      </div>

      {/* Action Button */}
      <div className="flex justify-end">
        <button
          type="button"
          disabled={loading}
          onClick={handleRunInference}
          className="px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition-all shadow-md shadow-emerald-900/30"
        >
          {loading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Evaluating Model Inference...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Model Prediction & Triage Pipeline</span>
            </>
          )}
        </button>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-200 space-y-1">
          <div className="flex items-center gap-2 font-semibold text-red-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Missing Feature Validation Warning</span>
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed pl-6">{errorMessage}</p>
        </div>
      )}

      {/* Prediction Output & Pipeline Escalation */}
      {predictionResult && (
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <span className="text-[11px] text-slate-500 block uppercase tracking-wider font-mono">
                Model Classification Outcome
              </span>
              <div className="flex items-center gap-2.5 mt-0.5">
                <span
                  className={`text-lg font-bold font-mono ${
                    predictionResult.predictedClass === 'BENIGN'
                      ? 'text-emerald-400'
                      : 'text-red-400'
                  }`}
                >
                  {predictionResult.predictedClass}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                  Confidence: {(predictionResult.predictionConfidence * 100).toFixed(1)}%
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-purple-300 font-mono">
                  Risk Score: {predictionResult.evidence?.riskAssessmentScore || 0}/100
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onViewTraceability(predictionResult)}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors self-start sm:self-auto shadow-sm"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Inspect End-to-End Lineage (8 Stages)</span>
            </button>
          </div>

          {/* Mandatory Academic Disclaimer */}
          <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300 flex items-start gap-2">
            <Info className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-relaxed">
              <strong>Mandatory Academic Disclaimer:</strong> {predictionResult.confidenceDisclaimer}
            </span>
          </div>

          {/* Explainable AI breakdown */}
          <div className="space-y-2">
            <span className="text-xs font-semibold text-slate-200 block">
              Explainable AI: Key Contributing Features
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {predictionResult.importantContributingFeatures.map(feat => (
                <div
                  key={feat.feature}
                  className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-1"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-300 truncate" title={feat.feature}>
                      {feat.feature}
                    </span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-bold font-mono ${
                        feat.impact === 'HIGH'
                          ? 'bg-red-500/20 text-red-300'
                          : feat.impact === 'MEDIUM'
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {feat.impact}
                    </span>
                  </div>
                  <span className="text-xs font-mono font-bold text-slate-200">
                    {String(feat.value)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Downstream Traceability IDs */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-3 text-xs font-mono">
            <span className="text-slate-500">Security Event: <strong className="text-slate-200">{predictionResult.traceability.securityEventId}</strong></span>
            <span className="text-slate-500">Threat Detection: <strong className="text-slate-200">{predictionResult.traceability.threatDetectionId}</strong></span>
            {predictionResult.traceability.securityAlertId && (
              <span className="text-slate-500">Alert Created: <strong className="text-amber-400">{predictionResult.traceability.securityAlertId}</strong></span>
            )}
            {predictionResult.traceability.incidentId && (
              <span className="text-slate-500">Incident: <strong className="text-red-400">{predictionResult.traceability.incidentId}</strong></span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
