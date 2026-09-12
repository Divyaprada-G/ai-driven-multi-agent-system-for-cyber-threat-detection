import React from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Info,
  Sliders,
  Filter,
  Split,
  Binary,
  HelpCircle
} from 'lucide-react';
import {
  DatasetSchema,
  PreprocessingConfig,
  DataLeakageCheckResult
} from '../../types/datasetMl';
import { datasetService } from '../../services/datasets/datasetService';

interface Props {
  schema: DatasetSchema;
  config: PreprocessingConfig;
  leakageResult: DataLeakageCheckResult;
  onConfigChange: (newConfig: PreprocessingConfig) => void;
}

export const PreprocessingAndLeakagePanel: React.FC<Props> = ({
  schema,
  config,
  leakageResult,
  onConfigChange
}) => {
  const handleToggleFeature = (featureName: string) => {
    const isSelected = config.selectedFeatures.includes(featureName);
    const updated = isSelected
      ? config.selectedFeatures.filter(f => f !== featureName)
      : [...config.selectedFeatures, featureName];
    onConfigChange({ ...config, selectedFeatures: updated });
  };

  const handleSelectAllFeatures = () => {
    // Select all non-target, non-identifier features
    const all = schema.columns
      .filter(c => c.name !== schema.labelColumn && !schema.identifierColumns.includes(c.name))
      .map(c => c.name);
    onConfigChange({ ...config, selectedFeatures: all });
  };

  const handleSelectNumericOnly = () => {
    const numeric = schema.columns
      .filter(
        c =>
          c.dataType === 'numeric' &&
          c.name !== schema.labelColumn &&
          !schema.identifierColumns.includes(c.name)
      )
      .map(c => c.name);
    onConfigChange({ ...config, selectedFeatures: numeric });
  };

  const handleDeselectAll = () => {
    onConfigChange({ ...config, selectedFeatures: [] });
  };

  return (
    <div id="preprocessing-leakage-panel" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
              Preprocessing Pipeline & Data Leakage Prevention
            </h3>
            <p className="text-xs text-slate-400">
              Isolate raw identifiers, enforce fit-on-train scaling boundaries, and configure reproducible test splits
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {leakageResult.leakageChecksPassed ? (
            <span className="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-semibold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Leakage Prevention Verified
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded-full bg-red-500/20 text-red-300 text-xs font-semibold flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> Leakage Risk Detected
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Feature Selection & Identifier Isolation */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-semibold text-slate-200">
                Feature Selection Matrix ({config.selectedFeatures.length} of{' '}
                {schema.columns.length - 1} selected)
              </span>
            </div>

            <div className="flex items-center gap-1.5 text-xs">
              <button
                type="button"
                onClick={handleSelectNumericOnly}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-medium transition-colors"
              >
                Numeric Only
              </button>
              <button
                type="button"
                onClick={handleSelectAllFeatures}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
              >
                Select All
              </button>
              <button
                type="button"
                onClick={handleDeselectAll}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 text-[11px] font-medium transition-colors"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Excluded Identifiers Banner */}
          {schema.identifierColumns.length > 0 && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                <Info className="w-3.5 h-3.5 shrink-0" />
                <span>Automatically Excluded Raw Identifiers ({schema.identifierColumns.length}):</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Raw network identifiers (<span className="font-mono text-amber-200">{schema.identifierColumns.join(', ')}</span>) are excluded from the ML feature input matrix.
                This prevents models from memorizing specific host IP addresses or session GUIDs rather than generalized network flow attack patterns.
                All identifiers remain fully preserved as <em>security evidence</em> for correlation and alert management.
              </p>
            </div>
          )}

          {/* Feature Checklist Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-64 overflow-y-auto pr-1 border border-slate-800 p-2.5 rounded-lg bg-slate-950/50">
            {schema.columns
              .filter(c => c.name !== schema.labelColumn)
              .map(col => {
                const isSelected = config.selectedFeatures.includes(col.name);
                const isIdentifier = schema.identifierColumns.includes(col.name);
                return (
                  <label
                    key={col.name}
                    className={`flex items-center gap-2.5 p-2 rounded-lg border text-xs cursor-pointer transition-all ${
                      isSelected
                        ? 'border-blue-500/50 bg-blue-500/10 text-slate-100'
                        : 'border-slate-800/80 bg-slate-900/40 text-slate-400 hover:bg-slate-850'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleToggleFeature(col.name)}
                      className="rounded border-slate-700 text-blue-600 focus:ring-0 w-3.5 h-3.5"
                    />
                    <div className="flex-1 truncate">
                      <span className="font-mono text-[11px] font-medium block truncate">
                        {col.name}
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        {col.dataType} • {col.missingCount === 0 ? '0 nulls' : `${col.missingCount} nulls`}
                      </span>
                    </div>
                    {isIdentifier && (
                      <span
                        className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono"
                        title="Identifier column"
                      >
                        ID
                      </span>
                    )}
                  </label>
                );
              })}
          </div>
        </div>

        {/* Right Col: Split Ratio, Seed & Leakage Checklist */}
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
              <Split className="w-4 h-4 text-purple-400" />
              <span>Train / Test Partitioning</span>
            </div>

            <div className="space-y-2">
              <label className="text-[11px] text-slate-400 block font-medium">Split Ratio:</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: '80 / 20', val: 0.8 },
                  { label: '70 / 30', val: 0.7 },
                  { label: '90 / 10', val: 0.9 }
                ].map(opt => (
                  <button
                    key={opt.val}
                    type="button"
                    onClick={() => onConfigChange({ ...config, trainSplitRatio: opt.val })}
                    className={`py-1.5 px-2 rounded text-xs font-mono font-medium border transition-colors ${
                      config.trainSplitRatio === opt.val
                        ? 'border-purple-500 bg-purple-500/20 text-purple-200'
                        : 'border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-1">
              <div>
                <span className="text-[11px] text-slate-400 block">Train Rows:</span>
                <span className="text-sm font-bold text-slate-100 font-mono">
                  {leakageResult.trainRows} ({(config.trainSplitRatio * 100).toFixed(0)}%)
                </span>
              </div>
              <div>
                <span className="text-[11px] text-slate-400 block">Test Rows:</span>
                <span className="text-sm font-bold text-slate-100 font-mono">
                  {leakageResult.testRows} ({(100 - config.trainSplitRatio * 100).toFixed(0)}%)
                </span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="text-[11px] text-slate-300 font-medium block">Reproducible Seed:</span>
                <span className="text-[10px] text-slate-500">Fixed random state</span>
              </div>
              <input
                type="number"
                value={config.randomSeed}
                onChange={e =>
                  onConfigChange({ ...config, randomSeed: parseInt(e.target.value, 10) || 42 })
                }
                className="w-16 bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2 py-1 text-center font-mono"
              />
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="text-[11px] text-slate-300 font-medium block">Stratified Split:</span>
                <span className="text-[10px] text-slate-500">Preserves class proportions</span>
              </div>
              <input
                type="checkbox"
                checked={config.useStratification}
                onChange={e => onConfigChange({ ...config, useStratification: e.target.checked })}
                className="rounded border-slate-700 text-purple-600 focus:ring-0 w-4 h-4"
              />
            </div>
          </div>

          {/* Leakage Checklist Verification */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5">
            <span className="text-xs font-semibold text-slate-200 block">
              Data Leakage Verification Checks
            </span>
            <div className="space-y-2 text-xs">
              {leakageResult.checks.map(check => {
                const isPassed = check.severity === 'PASSED';
                const isWarn = check.severity === 'WARNING';
                return (
                  <div key={check.id} className="flex items-start gap-2">
                    {isPassed ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                    ) : isWarn ? (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <span className="font-medium text-slate-200 block">{check.name}</span>
                      <span className="text-[10px] text-slate-400 leading-tight block">
                        {check.details}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
