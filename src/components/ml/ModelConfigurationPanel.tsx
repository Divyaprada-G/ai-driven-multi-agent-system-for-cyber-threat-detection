import React, { useState } from 'react';
import {
  Cpu,
  Play,
  RotateCcw,
  CheckCircle,
  AlertCircle,
  Settings,
  TreePine,
  Activity,
  Zap
} from 'lucide-react';
import {
  RandomForestHyperparameters,
  IsolationForestHyperparameters,
  ModelTrainingStatus,
  DatasetSchema,
  PreprocessingConfig,
  TrainedModelArtifact
} from '../../types/datasetMl';
import { mlTrainingService } from '../../services/mlTrainingService';

interface Props {
  schema: DatasetSchema;
  config: PreprocessingConfig;
  onModelTrained: (artifact: TrainedModelArtifact) => void;
}

export const ModelConfigurationPanel: React.FC<Props> = ({
  schema,
  config,
  onModelTrained
}) => {
  const [modelType, setModelType] = useState<'RANDOM_FOREST' | 'ISOLATION_FOREST'>('RANDOM_FOREST');
  const [rfParams, setRfParams] = useState<RandomForestHyperparameters>({
    n_estimators: 200,
    max_depth: null,
    min_samples_split: 2,
    min_samples_leaf: 1,
    class_weight: 'balanced',
    random_state: 42
  });

  const [ifParams, setIfParams] = useState<IsolationForestHyperparameters>({
    n_estimators: 100,
    contamination: 0.05,
    max_samples: 'auto',
    random_state: 42
  });

  const [trainingStatus, setTrainingStatus] = useState<ModelTrainingStatus>('IDLE');
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleStartTraining = async () => {
    setErrorMessage(null);
    setTrainingStatus('VALIDATING');
    setStatusMessage('Initiating model training pipeline...');

    try {
      if (modelType === 'RANDOM_FOREST') {
        const artifact = await mlTrainingService.trainRandomForest(
          config,
          schema,
          rfParams,
          (status, msg) => {
            setTrainingStatus(status);
            setStatusMessage(msg);
          }
        );
        onModelTrained(artifact);
      } else {
        const artifact = await mlTrainingService.trainIsolationForest(
          config,
          schema,
          ifParams,
          (status, msg) => {
            setTrainingStatus(status);
            setStatusMessage(msg);
          }
        );
        onModelTrained(artifact);
      }
    } catch (err: any) {
      setTrainingStatus('FAILED');
      setErrorMessage(err.message || 'Model training failed.');
    }
  };

  const isTraining =
    trainingStatus === 'VALIDATING' ||
    trainingStatus === 'PREPROCESSING' ||
    trainingStatus === 'SPLITTING' ||
    trainingStatus === 'TRAINING' ||
    trainingStatus === 'EVALUATING' ||
    trainingStatus === 'SAVING';

  return (
    <div id="model-configuration-panel" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
              Model Training & Algorithm Configuration
            </h3>
            <p className="text-xs text-slate-400">
              Configure hyperparameters for Supervised Random Forest Classifier or Unsupervised Isolation Forest
            </p>
          </div>
        </div>

        {/* Algorithm Toggle */}
        <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setModelType('RANDOM_FOREST')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium flex items-center gap-1.5 transition-all ${
              modelType === 'RANDOM_FOREST'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <TreePine className="w-3.5 h-3.5" />
            <span>Random Forest</span>
          </button>

          <button
            type="button"
            onClick={() => setModelType('ISOLATION_FOREST')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium flex items-center gap-1.5 transition-all ${
              modelType === 'ISOLATION_FOREST'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Isolation Forest</span>
          </button>
        </div>
      </div>

      {/* Hyperparameter Inputs */}
      {modelType === 'RANDOM_FOREST' ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5 p-4 rounded-lg bg-slate-950/60 border border-slate-800">
          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              n_estimators (Trees)
            </label>
            <input
              type="number"
              min={10}
              max={1000}
              step={10}
              value={rfParams.n_estimators}
              onChange={e =>
                setRfParams({ ...rfParams, n_estimators: parseInt(e.target.value, 10) || 100 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              max_depth (Tree Limit)
            </label>
            <input
              type="number"
              placeholder="None (unbounded)"
              value={rfParams.max_depth === null ? '' : rfParams.max_depth}
              onChange={e =>
                setRfParams({
                  ...rfParams,
                  max_depth: e.target.value === '' ? null : parseInt(e.target.value, 10)
                })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none placeholder-slate-600"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              min_samples_split
            </label>
            <input
              type="number"
              min={2}
              max={50}
              value={rfParams.min_samples_split}
              onChange={e =>
                setRfParams({ ...rfParams, min_samples_split: parseInt(e.target.value, 10) || 2 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              min_samples_leaf
            </label>
            <input
              type="number"
              min={1}
              max={20}
              value={rfParams.min_samples_leaf}
              onChange={e =>
                setRfParams({ ...rfParams, min_samples_leaf: parseInt(e.target.value, 10) || 1 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">class_weight</label>
            <select
              value={rfParams.class_weight}
              onChange={e => setRfParams({ ...rfParams, class_weight: e.target.value as any })}
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            >
              <option value="balanced">balanced (auto inverse freq)</option>
              <option value="none">none (equal weights)</option>
            </select>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 p-4 rounded-lg bg-slate-950/60 border border-slate-800">
          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              n_estimators (Isolation Trees)
            </label>
            <input
              type="number"
              min={10}
              max={500}
              step={10}
              value={ifParams.n_estimators}
              onChange={e =>
                setIfParams({ ...ifParams, n_estimators: parseInt(e.target.value, 10) || 100 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">
              contamination (Anomaly Proportion)
            </label>
            <input
              type="number"
              min={0.001}
              max={0.5}
              step={0.01}
              value={ifParams.contamination}
              onChange={e =>
                setIfParams({ ...ifParams, contamination: parseFloat(e.target.value) || 0.05 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block font-medium mb-1">random_state</label>
            <input
              type="number"
              value={ifParams.random_state}
              onChange={e =>
                setIfParams({ ...ifParams, random_state: parseInt(e.target.value, 10) || 42 })
              }
              className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:ring-1 focus:ring-purple-500 focus:outline-none"
            />
          </div>
        </div>
      )}

      {/* Action Bar & Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
        <div className="flex-1">
          {trainingStatus !== 'IDLE' && (
            <div className="flex items-center gap-2 text-xs">
              {isTraining && (
                <div className="w-3.5 h-3.5 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
              )}
              {trainingStatus === 'COMPLETED' && (
                <CheckCircle className="w-4 h-4 text-emerald-400" />
              )}
              {trainingStatus === 'FAILED' && <AlertCircle className="w-4 h-4 text-red-400" />}
              <span
                className={`font-medium ${
                  trainingStatus === 'COMPLETED'
                    ? 'text-emerald-300'
                    : trainingStatus === 'FAILED'
                    ? 'text-red-300'
                    : 'text-purple-300'
                }`}
              >
                [{trainingStatus}] {statusMessage}
              </span>
            </div>
          )}
        </div>

        <button
          type="button"
          disabled={isTraining || config.selectedFeatures.length === 0}
          onClick={handleStartTraining}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
            isTraining || config.selectedFeatures.length === 0
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
              : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-md shadow-purple-900/30'
          }`}
        >
          {isTraining ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Training Model...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Train {modelType === 'RANDOM_FOREST' ? 'Random Forest' : 'Isolation Forest'}</span>
            </>
          )}
        </button>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-200 space-y-1">
          <div className="flex items-center gap-2 font-semibold text-red-300">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>Training Interrupted (Academic Integrity Guard)</span>
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed pl-6">{errorMessage}</p>
        </div>
      )}
    </div>
  );
};
