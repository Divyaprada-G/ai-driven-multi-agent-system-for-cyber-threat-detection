import React, { useState, useEffect } from 'react';
import {
  Database,
  ShieldCheck,
  Cpu,
  Award,
  FolderGit2,
  Sparkles,
  FileText,
  Activity,
  ArrowRight,
  RotateCcw,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { datasetService } from '../services/datasets/datasetService';
import { mlTrainingService } from '../services/mlTrainingService';
import {
  DatasetSchema,
  PreprocessingConfig,
  DataLeakageCheckResult,
  TrainedModelArtifact,
  TestPredictionResult,
  MLBackendStatus
} from '../types/datasetMl';
import { ModelStatusAlert } from '../components/ml/ModelStatusAlert';
import { DatasetUploadCard } from '../components/ml/DatasetUploadCard';
import { DatasetSchemaViewer } from '../components/ml/DatasetSchemaViewer';
import { PreprocessingAndLeakagePanel } from '../components/ml/PreprocessingAndLeakagePanel';
import { ModelConfigurationPanel } from '../components/ml/ModelConfigurationPanel';
import { EvaluationResultsPanel } from '../components/ml/EvaluationResultsPanel';
import { ModelRegistryPanel } from '../components/ml/ModelRegistryPanel';
import { TestPredictionPanel } from '../components/ml/TestPredictionPanel';
import { EndToEndTraceabilityModal } from '../components/ml/EndToEndTraceabilityModal';
import { AcademicEvaluationReportModal } from '../components/ml/AcademicEvaluationReportModal';

interface Props {
  onNavigate?: (pageId: any) => void;
}

export const DatasetsMlTrainingPage: React.FC<Props> = ({ onNavigate }) => {
  const [schema, setSchema] = useState<DatasetSchema | null>(() => datasetService.getActiveSchema());
  const [activeTab, setActiveTab] = useState<'dataset' | 'preprocessing' | 'training' | 'evaluation' | 'registry' | 'testing'>('dataset');

  // Preprocessing config
  const [config, setConfig] = useState<PreprocessingConfig>(() => {
    const s = datasetService.getActiveSchema();
    const initialFeatures = s
      ? s.columns
          .filter(c => c.name !== s.labelColumn && !s.identifierColumns.includes(c.name))
          .map(c => c.name)
      : [];
    return {
      selectedFeatures: initialFeatures,
      excludedIdentifiers: s ? s.identifierColumns : [],
      handleMissingStrategy: 'median',
      handleDuplicates: true,
      handleInfinite: true,
      trainSplitRatio: 0.8,
      randomSeed: 42,
      useStratification: true
    };
  });

  // Model & Backend State
  const [models, setModels] = useState<TrainedModelArtifact[]>(() => mlTrainingService.getRegisteredModels());
  const [activeModel, setActiveModel] = useState<TrainedModelArtifact | null>(() => mlTrainingService.getActiveModel());
  const [backendStatus, setBackendStatus] = useState<MLBackendStatus>(() => mlTrainingService.getBackendStatus());

  // Modals
  const [traceabilityResult, setTraceabilityResult] = useState<TestPredictionResult | null>(null);
  const [showAcademicReport, setShowAcademicReport] = useState<boolean>(false);

  // Subscribe to service updates
  useEffect(() => {
    const unsubscribe = mlTrainingService.subscribe(() => {
      setModels(mlTrainingService.getRegisteredModels());
      setActiveModel(mlTrainingService.getActiveModel());
      setBackendStatus(mlTrainingService.getBackendStatus());
    });
    return unsubscribe;
  }, []);

  const handleDatasetLoaded = (newSchema: DatasetSchema) => {
    setSchema(newSchema);
    const newFeatures = newSchema.columns
      .filter(c => c.name !== newSchema.labelColumn && !newSchema.identifierColumns.includes(c.name))
      .map(c => c.name);

    setConfig(prev => ({
      ...prev,
      selectedFeatures: newFeatures,
      excludedIdentifiers: newSchema.identifierColumns
    }));
  };

  const handleLabelChange = (newLabel: string) => {
    const updated = datasetService.updateLabelColumn(newLabel);
    setSchema(updated);
    setConfig(prev => ({
      ...prev,
      selectedFeatures: prev.selectedFeatures.filter(f => f !== newLabel)
    }));
  };

  const handleModelTrained = (artifact: TrainedModelArtifact) => {
    setModels(mlTrainingService.getRegisteredModels());
    setActiveModel(artifact);
    setActiveTab('evaluation');
  };

  const handleRefreshHealth = async () => {
    const status = await mlTrainingService.checkBackendHealth();
    setBackendStatus(status);
  };

  // Compute live leakage checks
  const leakageResult: DataLeakageCheckResult = schema
    ? datasetService.checkDataLeakage(config, schema)
    : {
        trainRows: 0,
        testRows: 0,
        splitRatio: 0.8,
        randomSeed: 42,
        stratifiedApplied: false,
        identifierExclusionsCount: 0,
        leakageChecksPassed: true,
        checks: []
      };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
                <span>Datasets & ML Model Training Engine</span>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 font-mono font-medium">
                  Stage 11
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
                Ingest cybersecurity benchmark datasets, audit schema & data leakage, train Random Forest & Isolation Forest models, evaluate held-out test metrics, and verify end-to-end multi-agent traceability.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 self-start lg:self-center">
          {schema && activeModel && (
            <button
              type="button"
              onClick={() => setShowAcademicReport(true)}
              className="px-3.5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-2 transition-colors shadow-sm"
            >
              <FileText className="w-4 h-4" />
              <span>Academic Evaluation Report</span>
            </button>
          )}

          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate('threat-detection')}
              className="px-3.5 py-2 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <span>SOC Threat Detection View</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Honest Backend Status Alert */}
      <ModelStatusAlert
        backendStatus={backendStatus}
        activeModelStatus={activeModel?.modelStatus || 'DEMO_MODEL'}
        onRefreshHealth={handleRefreshHealth}
      />

      {/* Workflow Navigation Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-slate-800 text-xs font-medium">
        <button
          type="button"
          onClick={() => setActiveTab('dataset')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'dataset'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>1. Dataset & Schema</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('preprocessing')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'preprocessing'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>2. Preprocessing & Leakage Checks</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('training')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'training'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>3. Model Training</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('evaluation')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'evaluation'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Award className="w-4 h-4" />
          <span>4. Evaluation Metrics</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('registry')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'registry'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <FolderGit2 className="w-4 h-4" />
          <span>5. Model Registry ({models.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('testing')}
          className={`px-3.5 py-2 rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
            activeTab === 'testing'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>6. Test Prediction & Traceability</span>
        </button>
      </div>

      {/* Main Content Panels */}
      {activeTab === 'dataset' && (
        <div className="space-y-6">
          <DatasetUploadCard activeSchema={schema} onDatasetLoaded={handleDatasetLoaded} />
          {schema && <DatasetSchemaViewer schema={schema} onLabelChange={handleLabelChange} />}
        </div>
      )}

      {activeTab === 'preprocessing' && schema && (
        <PreprocessingAndLeakagePanel
          schema={schema}
          config={config}
          leakageResult={leakageResult}
          onConfigChange={setConfig}
        />
      )}

      {activeTab === 'training' && schema && (
        <ModelConfigurationPanel
          schema={schema}
          config={config}
          onModelTrained={handleModelTrained}
        />
      )}

      {activeTab === 'evaluation' && (
        <EvaluationResultsPanel activeModel={activeModel} />
      )}

      {activeTab === 'registry' && (
        <ModelRegistryPanel
          models={models}
          activeModelId={activeModel?.modelId || ''}
          onModelSelected={modelId => {
            const found = models.find(m => m.modelId === modelId);
            if (found) setActiveModel(found);
          }}
        />
      )}

      {activeTab === 'testing' && activeModel && (
        <TestPredictionPanel
          activeModel={activeModel}
          onViewTraceability={res => setTraceabilityResult(res)}
        />
      )}

      {/* Modals */}
      {traceabilityResult && (
        <EndToEndTraceabilityModal
          result={traceabilityResult}
          onClose={() => setTraceabilityResult(null)}
        />
      )}

      {showAcademicReport && schema && activeModel && (
        <AcademicEvaluationReportModal
          schema={schema}
          config={config}
          activeModel={activeModel}
          backendStatus={backendStatus}
          onClose={() => setShowAcademicReport(false)}
        />
      )}
    </div>
  );
};
