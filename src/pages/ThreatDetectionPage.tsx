import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Cpu,
  Activity,
  AlertTriangle,
  Play,
  Layers,
  Search,
  RefreshCw,
  Sliders,
  Sparkles,
  Database,
  CheckCircle2,
  ExternalLink,
  Eye,
  BarChart3,
  SlidersHorizontal
} from 'lucide-react';
import {
  ThreatDetectionResult,
  DetectionModelType,
  ModelStatus,
  ModelInfoDetails,
  ThreatClass
} from '../types/threatDetection';
import {
  threatDetectionService,
  THREAT_DEMO_SCENARIOS
} from '../services/threatDetection/threatDetectionService';
import { correlationService } from '../services/correlationService';
import { StatCard } from '../components/common/StatCard';
import { ModelStatusBanner } from '../components/threatDetection/ModelStatusBanner';
import { ThreatPipelineView } from '../components/threatDetection/ThreatPipelineView';
import { ThreatCategoriesChart } from '../components/threatDetection/ThreatCategoriesChart';
import { ModelComparisonSection } from '../components/threatDetection/ModelComparisonSection';
import { ModelEvaluationPanel } from '../components/threatDetection/ModelEvaluationPanel';
import { TrainingDataInterface } from '../components/threatDetection/TrainingDataInterface';
import { ThreatDetailModal } from '../components/threatDetection/ThreatDetailModal';

interface ThreatDetectionPageProps {
  onNavigate?: (page: any) => void;
}

export const ThreatDetectionPage: React.FC<ThreatDetectionPageProps> = ({ onNavigate }) => {
  const [modelInfo, setModelInfo] = useState<ModelInfoDetails | null>(null);
  const [activeModelType, setActiveModelType] = useState<DetectionModelType>(
    threatDetectionService.getActiveModelType()
  );
  const [detections, setDetections] = useState<ThreatDetectionResult[]>([]);
  const [selectedDetection, setSelectedDetection] = useState<ThreatDetectionResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [filterClass, setFilterClass] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [testPayload, setTestPayload] = useState('');
  const [activeTab, setActiveTab] = useState<'detections' | 'evaluation' | 'training' | 'comparison'>('detections');

  const loadData = useCallback(async () => {
    const [info, dets] = await Promise.all([
      threatDetectionService.getModelInfo(),
      threatDetectionService.getDetectionResults()
    ]);
    setModelInfo(info);
    setDetections(dets);
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectModelType = async (type: DetectionModelType) => {
    threatDetectionService.setActiveModelType(type);
    setActiveModelType(type);
    const info = await threatDetectionService.getModelInfo();
    setModelInfo(info);

    // Re-evaluate current events under new model architecture
    const correlated = await correlationService.getCorrelatedEvents();
    const updated = await threatDetectionService.detectThreats(correlated);
    setDetections(updated);
  };

  const handleRunScenario = async (scenarioId: string) => {
    setIsAnalyzing(true);
    try {
      const res = await threatDetectionService.runDemoScenario(scenarioId);
      setDetections(prev => [res, ...prev.filter(d => d.id !== res.id)]);
      setSelectedDetection(res);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeLiveCorrelations = async () => {
    setIsAnalyzing(true);
    try {
      const correlated = await correlationService.getCorrelatedEvents();
      const results = await threatDetectionService.detectThreats(correlated);
      setDetections(results);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSimulatePayload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testPayload.trim()) return;
    setIsAnalyzing(true);
    try {
      const newDet = await threatDetectionService.analyzeAnomaly(testPayload);
      setDetections(prev => [newDet, ...prev]);
      setSelectedDetection(newDet);
      setTestPayload('');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const filteredDetections = detections.filter(d => {
    if (filterClass !== 'ALL' && d.classification !== filterClass) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchId = d.id.toLowerCase().includes(term);
      const matchClass = d.classification.toLowerCase().includes(term);
      const matchCorr = d.correlationId.toLowerCase().includes(term);
      const matchEvidence = d.evidence.some(e => e.toLowerCase().includes(term));
      if (!matchId && !matchClass && !matchCorr && !matchEvidence) return false;
    }
    return true;
  });

  const threatsCount = detections.filter(d => d.threatDetected).length;
  const avgConfidence =
    detections.length > 0
      ? (detections.reduce((acc, d) => acc + d.confidence, 0) / detections.length) * 100
      : 0;
  const avgAnomaly =
    detections.length > 0
      ? detections.reduce((acc, d) => acc + d.anomalyScore, 0) / detections.length
      : 0;

  return (
    <div className="space-y-6" id="page-threat-detection">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5" />
              Stage 7 • AI/ML Threat Detection Engine
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight mt-0.5">
            Threat Classification & Anomaly Detection Layer
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Ingests multi-agent Correlated Security Events, extracts 18-dimensional feature vectors, scales via Min-Max normalization, and performs supervised classification and anomaly scoring with comprehensive explainable attribution.
          </p>
        </div>

        {/* Live Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            id="btn-analyze-live-correlations"
            onClick={handleAnalyzeLiveCorrelations}
            disabled={isAnalyzing}
            className="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-mono font-bold text-xs flex items-center gap-1.5 transition-colors shadow-lg shadow-cyan-600/20"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
            <span>Analyze Correlated Events</span>
          </button>
          {onNavigate && (
            <button
              onClick={() => onNavigate('correlation')}
              className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs flex items-center gap-1.5 transition-colors border border-slate-700"
            >
              <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
              <span>Event Correlation</span>
            </button>
          )}
        </div>
      </div>

      {/* Model Status & Mode Banner */}
      {modelInfo && (
        <ModelStatusBanner
          activeModelType={activeModelType}
          modelStatus={modelInfo.modelStatus}
          modelName={modelInfo.modelName}
          onSelectModelType={handleSelectModelType}
        />
      )}

      {/* End-to-End Pipeline Visualization */}
      <ThreatPipelineView />

      {/* Demo Scenario Quick-Run Bar */}
      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300 font-bold flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Standard Academic Demo Scenarios:
          </span>
          <span className="text-[10px] text-slate-500">
            Deterministic Heuristic Verification
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {THREAT_DEMO_SCENARIOS.map(scenario => (
            <button
              key={scenario.id}
              onClick={() => handleRunScenario(scenario.id)}
              disabled={isAnalyzing}
              className="p-2.5 rounded-lg bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-700/60 text-left transition-all group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white group-hover:text-cyan-400 truncate">
                    {scenario.name.split(':')[0]}
                  </span>
                  <span className={`px-1.5 py-0.2 text-[9px] font-mono rounded font-bold ${
                    scenario.expectedClass === 'BENIGN'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {scenario.expectedClass}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2 mt-1">
                  {scenario.description}
                </p>
              </div>
              <div className="flex items-center gap-1 text-[10px] text-cyan-400 font-mono mt-2 self-end">
                <span>Evaluate</span>
                <Play className="w-2.5 h-2.5 fill-cyan-400" />
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Telemetry Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard
          id="stat-total-evaluated"
          title="Events Evaluated"
          value={detections.length}
          subtitle="Clusters Ingested"
          icon={Activity}
          variant="info"
        />
        <StatCard
          id="stat-threats-detected"
          title="Threats Detected"
          value={threatsCount}
          subtitle="Actionable Detections"
          icon={AlertTriangle}
          variant={threatsCount > 0 ? 'critical' : 'default'}
        />
        <StatCard
          id="stat-avg-confidence"
          title="Avg Confidence"
          value={`${avgConfidence.toFixed(1)}%`}
          subtitle={activeModelType === 'RULE_BASED_DEMO' ? 'DEMO-DERIVED' : 'MODEL-DERIVED'}
          icon={ShieldAlert}
          variant="emerald"
        />
        <StatCard
          id="stat-avg-anomaly"
          title="Avg Anomaly Score"
          value={avgAnomaly.toFixed(3)}
          subtitle="Scale 0.0 - 1.0"
          icon={Cpu}
          variant="warning"
        />
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('detections')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'detections'
              ? 'bg-cyan-600 text-white'
              : 'text-slate-400 hover:text-white bg-slate-900/60'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Threat Detections ({detections.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('evaluation')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'evaluation'
              ? 'bg-cyan-600 text-white'
              : 'text-slate-400 hover:text-white bg-slate-900/60'
          }`}
        >
          <BarChart3 className="w-3.5 h-3.5" />
          <span>Model Evaluation & Benchmark</span>
        </button>

        <button
          onClick={() => setActiveTab('training')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'training'
              ? 'bg-cyan-600 text-white'
              : 'text-slate-400 hover:text-white bg-slate-900/60'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Training Data & Schemas</span>
        </button>

        <button
          onClick={() => setActiveTab('comparison')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'comparison'
              ? 'bg-cyan-600 text-white'
              : 'text-slate-400 hover:text-white bg-slate-900/60'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Model Architecture Matrix</span>
        </button>
      </div>

      {/* TAB 1: DETECTIONS VIEW */}
      {activeTab === 'detections' && (
        <div className="space-y-4">
          {/* Top Charts & Testing Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <ThreatCategoriesChart detections={detections} />
            </div>

            {/* Synthetic Anomaly Sandbox */}
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between">
              <div>
                <h4 className="text-sm font-bold text-white font-mono flex items-center gap-1.5">
                  <SlidersHorizontal className="w-4 h-4 text-cyan-400" />
                  Synthetic Log Testing Sandbox
                </h4>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Pass custom log payloads or attack sequences directly to the feature extraction pipeline.
                </p>
              </div>

              <form onSubmit={handleSimulatePayload} className="space-y-2 mt-2">
                <textarea
                  rows={3}
                  value={testPayload}
                  onChange={e => setTestPayload(e.target.value)}
                  placeholder="e.g. 192.168.1.105 - 'UNION SELECT schema_name FROM information_schema.schemata' HTTP/1.1 500"
                  className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
                />
                <button
                  type="submit"
                  disabled={isAnalyzing || !testPayload.trim()}
                  className="w-full py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-bold rounded-lg flex items-center justify-center gap-1.5 transition-colors shadow"
                >
                  <Play className="w-3 h-3" />
                  <span>Extract Features & Classify</span>
                </button>
              </form>

              <div className="text-[10px] font-mono text-slate-500 pt-2 border-t border-slate-800/80">
                Ready for Scikit-Learn Python endpoint integration.
              </div>
            </div>
          </div>

          {/* Detections Filter and Search Bar */}
          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Class Filter:</span>
              <select
                value={filterClass}
                onChange={e => setFilterClass(e.target.value)}
                className="px-2.5 py-1 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Classes (10)</option>
                <option value="MULTI_STAGE_THREAT">Multi-Stage Threat</option>
                <option value="AUTHENTICATION_THREAT">Authentication Threat</option>
                <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
                <option value="WEB_THREAT">Web Threat</option>
                <option value="API_THREAT">API Threat</option>
                <option value="NETWORK_THREAT">Network Threat</option>
                <option value="ANOMALY">Anomaly</option>
                <option value="BENIGN">Benign</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="UNKNOWN">Unknown</option>
              </select>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search ID, class, or evidence..."
                className="w-full pl-8 pr-3 py-1 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Detections Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredDetections.map(det => {
              const isBenign = det.classification === 'BENIGN';
              return (
                <div
                  key={det.id}
                  id={`card-det-${det.id.toLowerCase()}`}
                  className={`p-4 rounded-xl border bg-slate-900/90 transition-all hover:border-cyan-600/60 flex flex-col justify-between space-y-3 ${
                    det.severity === 'CRITICAL'
                      ? 'border-rose-900/60'
                      : det.severity === 'HIGH'
                      ? 'border-orange-900/60'
                      : 'border-slate-800'
                  }`}
                >
                  <div className="space-y-2">
                    {/* Header Row */}
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-cyan-400 font-bold">{det.id}</span>
                      <div className="flex items-center gap-1.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          det.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : det.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-300 border border-orange-800'
                            : det.severity === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}>
                          {det.severity}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {det.timestamp.slice(11, 19)}
                        </span>
                      </div>
                    </div>

                    {/* Threat Title & Classification */}
                    <div>
                      <h4 className="text-sm font-bold text-white font-mono flex items-center gap-1.5">
                        <span>{det.classification}</span>
                      </h4>
                      <div className="text-[11px] text-slate-400 mt-0.5 font-sans">
                        {det.threatType}
                      </div>
                    </div>

                    {/* Scores Matrix */}
                    <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 grid grid-cols-2 gap-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500 text-[10px] block">Confidence</span>
                        <span className="text-cyan-400 font-bold">
                          {(det.confidence * 100).toFixed(1)}%
                        </span>
                        <span className="text-[9px] text-slate-500 block">{det.confidenceType}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px] block">Anomaly Score</span>
                        <span className="text-rose-400 font-bold">
                          {det.anomalyScore.toFixed(3)}
                        </span>
                        <span className="text-[9px] text-slate-500 block">Anomaly metric</span>
                      </div>
                    </div>

                    {/* Evidence Snippet */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono uppercase text-slate-500 tracking-wider">
                        Key Supporting Signals:
                      </span>
                      <ul className="space-y-1 text-[11px] text-slate-300 font-mono">
                        {det.evidence.slice(0, 2).map((ev, i) => (
                          <li key={i} className="flex items-start gap-1">
                            <span className="text-cyan-400">•</span>
                            <span className="line-clamp-1">{ev}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Card Footer Actions */}
                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                    <span className="text-[10px] text-slate-500 truncate max-w-[130px]">
                      {det.correlationId}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => setSelectedDetection(det)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono flex items-center gap-1 transition-colors"
                      >
                        <Eye className="w-3 h-3 text-cyan-400" />
                        <span>Inspect</span>
                      </button>
                      {onNavigate && (
                        <button
                          onClick={() => onNavigate('correlation')}
                          title="View Correlated Cluster"
                          className="p-1 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-400 rounded transition-colors"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {filteredDetections.length === 0 && (
            <div className="p-8 text-center text-xs font-mono text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
              No threat detections match the selected filter. Try selecting "All Classes" or clearing the search box.
            </div>
          )}
        </div>
      )}

      {/* TAB 2: MODEL EVALUATION & BENCHMARK */}
      {activeTab === 'evaluation' && <ModelEvaluationPanel />}

      {/* TAB 3: TRAINING DATA & BENCHMARKS */}
      {activeTab === 'training' && <TrainingDataInterface />}

      {/* TAB 4: ARCHITECTURE MATRIX */}
      {activeTab === 'comparison' && (
        <ModelComparisonSection
          rfStatus={threatDetectionService.getRandomForestModel().getStatus()}
          ifStatus={threatDetectionService.getIsolationForestModel().getStatus()}
        />
      )}

      {/* Detail Modal */}
      <ThreatDetailModal
        detection={selectedDetection}
        onClose={() => setSelectedDetection(null)}
        onViewCorrelation={id => {
          setSelectedDetection(null);
          if (onNavigate) onNavigate('correlation');
        }}
      />
    </div>
  );
};
