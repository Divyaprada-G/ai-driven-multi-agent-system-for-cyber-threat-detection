import React, { useState, useRef } from 'react';
import { Upload, FileText, Check, AlertCircle, Database, Layers, Sparkles } from 'lucide-react';
import { TrainingDatasetMeta } from '../../types/threatDetection';
import { DatasetAdapter, STANDARD_DATASET_SCHEMAS } from '../../services/threatDetection/datasetAdapter';

export const TrainingDataInterface: React.FC = () => {
  const [datasetMeta, setDatasetMeta] = useState<TrainingDatasetMeta | null>(null);
  const [selectedStandard, setSelectedStandard] = useState<string>('CICIDS2017');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    setErrorMsg(null);
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = event => {
      const content = event.target?.result as string;
      try {
        if (file.name.endsWith('.csv')) {
          const meta = DatasetAdapter.parseCsv(content, file.name);
          setDatasetMeta(meta);
        } else if (file.name.endsWith('.json')) {
          const meta = DatasetAdapter.parseJson(content, file.name);
          setDatasetMeta(meta);
        } else {
          setErrorMsg('Unsupported file extension. Please upload a .csv or .json dataset.');
        }
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to parse dataset.');
      }
    };
    reader.readAsText(file);
  };

  const handleLoadSampleBenchmark = () => {
    setErrorMsg(null);
    // Academic sample dataset for demonstration
    const sampleCsv = `Flow Duration,Total Fwd Packets,SYN Flag Count,Destination Port,Average Packet Size,Label
120000,48,1,80,420,PortScan
34000,12,0,443,1240,Benign
450000,320,1,22,890,BruteForce
89000,8,0,8080,310,WebAttack
15000,4,0,53,68,Benign
670000,540,1,445,1500,Infiltration
22000,6,0,443,512,Benign
310000,180,1,80,490,PortScan
19000,5,0,80,1024,Benign
920000,410,1,3389,980,Infiltration`;

    const meta = DatasetAdapter.parseCsv(sampleCsv, 'CICIDS2017_Sample_Benchmark.csv');
    setDatasetMeta(meta);
  };

  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div>
          <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            Supervised Training Data & Benchmark Schema Interface
          </h4>
          <p className="text-[11px] text-slate-400">
            Upload CSV/JSON labeled datasets or map standardized cybersecurity schemas (CICIDS2017, UNSW-NB15, KDD Cup 99).
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={handleLoadSampleBenchmark}
            className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors border border-slate-700"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Load CICIDS2017 Sample</span>
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Dataset</span>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.json"
            onChange={handleFileUpload}
            className="hidden"
          />
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-xs font-mono text-rose-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Benchmark Standard Compatibility Selector */}
      <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300 font-bold">Standardized Benchmark Compatibility Mappings:</span>
          <span className="text-[10px] text-cyan-400">Schema Ready for Python ML</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {Object.entries(STANDARD_DATASET_SCHEMAS).map(([key, schema]) => (
            <button
              key={key}
              onClick={() => setSelectedStandard(key)}
              className={`p-2.5 rounded-lg border text-left text-xs font-mono transition-colors ${
                selectedStandard === key
                  ? 'bg-cyan-950/60 border-cyan-500 text-white'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="font-bold flex items-center justify-between">
                <span>{key}</span>
                {selectedStandard === key && <Check className="w-3.5 h-3.5 text-cyan-400" />}
              </div>
              <div className="text-[10px] text-slate-500 mt-1 line-clamp-2">
                {schema.notes}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Uploaded Dataset Meta & Inspector */}
      {datasetMeta ? (
        <div className="space-y-3 font-mono text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-cyan-800/60 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-white font-bold flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                {datasetMeta.datasetName} ({datasetMeta.format})
              </span>
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px]">
                Detected Standard: {datasetMeta.standardType}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
              <div>
                <span className="text-slate-500 block">Total Records:</span>
                <span className="text-cyan-300 font-bold">{datasetMeta.rowCount.toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Total Features:</span>
                <span className="text-indigo-300 font-bold">{datasetMeta.featureColumns.length}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Target / Label:</span>
                <span className="text-emerald-300 font-bold truncate block">{datasetMeta.targetColumn}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Missing Values:</span>
                <span className="text-amber-300 font-bold">{datasetMeta.missingValuesCount}</span>
              </div>
            </div>
          </div>

          {/* Class Distribution Breakdown */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <div className="text-slate-400 text-[11px] font-bold">Class / Label Distribution Found:</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(datasetMeta.classDistribution).map(([label, count]) => (
                <div
                  key={label}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] flex items-center gap-2"
                >
                  <span className="text-slate-200">{label}:</span>
                  <span className="text-cyan-400 font-bold">{count}</span>
                  <span className="text-slate-500 text-[10px]">
                    ({((Number(count) / datasetMeta.rowCount) * 100).toFixed(0)}%)
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/60 text-[11px] text-slate-400 flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              Dataset feature mapping prepared. To train Random Forest weights, connect the Scikit-Learn training endpoint <code className="text-cyan-300">POST /api/v1/ml/train</code>.
            </span>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 text-center text-xs font-mono text-slate-500">
          No external dataset loaded. Click "Load CICIDS2017 Sample" or upload a custom CSV/JSON to preview feature mapping.
        </div>
      )}
    </div>
  );
};
