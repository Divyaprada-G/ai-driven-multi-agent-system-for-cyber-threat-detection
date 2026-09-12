import React, { useRef, useState } from 'react';
import { Upload, FileText, Database, CheckCircle, AlertCircle, Sparkles } from 'lucide-react';
import { BENCHMARK_DATASETS, BenchmarkDatasetDef } from '../../services/datasets/benchmarkDatasets';
import { datasetService } from '../../services/datasets/datasetService';
import { DatasetSchema } from '../../types/datasetMl';

interface Props {
  activeSchema: DatasetSchema | null;
  onDatasetLoaded: (schema: DatasetSchema) => void;
}

export const DatasetUploadCard: React.FC<Props> = ({ activeSchema, onDatasetLoaded }) => {
  const [selectedBenchmark, setSelectedBenchmark] = useState<string>('cicids2017-sample');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSelectBenchmark = (datasetId: string) => {
    setSelectedBenchmark(datasetId);
    const benchmark = BENCHMARK_DATASETS.find(b => b.id === datasetId);
    if (!benchmark) return;

    setLoading(true);
    setErrorMessage(null);
    try {
      const schema = datasetService.loadDatasetFromCsv(
        benchmark.csvContent,
        benchmark.filename,
        benchmark.name,
        benchmark.standardType
      );
      onDatasetLoaded(schema);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to parse benchmark dataset.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (file: File) => {
    setErrorMessage(null);
    setLoading(true);

    try {
      // Security check
      datasetService.validateFileSafety(file);

      const reader = new FileReader();
      reader.onload = e => {
        try {
          const content = e.target?.result as string;
          const schema = datasetService.loadDatasetFromCsv(content, file.name);
          onDatasetLoaded(schema);
        } catch (parseErr: any) {
          setErrorMessage(parseErr.message || 'Error parsing CSV file content.');
        } finally {
          setLoading(false);
        }
      };

      reader.onerror = () => {
        setErrorMessage('Failed to read uploaded file.');
        setLoading(false);
      };

      reader.readAsText(file);
    } catch (secErr: any) {
      setErrorMessage(secErr.message || 'File validation failed.');
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div id="dataset-upload-card" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
              Dataset Ingestion & Benchmark Library
            </h3>
            <p className="text-xs text-slate-400">
              Select an authentic cybersecurity benchmark dataset or upload custom network flow telemetry (CSV)
            </p>
          </div>
        </div>

        {activeSchema && (
          <div className="flex items-center gap-2 self-start sm:self-auto px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs">
            <span className="text-slate-400">Active:</span>
            <span className="font-semibold text-cyan-300 font-mono">{activeSchema.fileName}</span>
            <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 text-[10px] font-bold">
              {activeSchema.standardType}
            </span>
          </div>
        )}
      </div>

      {/* Benchmark Selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {BENCHMARK_DATASETS.map(benchmark => {
          const isSelected = activeSchema?.fileName === benchmark.filename;
          return (
            <button
              key={benchmark.id}
              type="button"
              onClick={() => handleSelectBenchmark(benchmark.id)}
              className={`text-left p-3 rounded-lg border transition-all ${
                isSelected
                  ? 'border-blue-500 bg-blue-500/10 shadow-sm ring-1 ring-blue-500/40'
                  : 'border-slate-800 bg-slate-800/40 hover:bg-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">{benchmark.name}</span>
                {isSelected && <CheckCircle className="w-4 h-4 text-blue-400 shrink-0" />}
              </div>
              <p className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                {benchmark.description}
              </p>
              <div className="mt-2 flex items-center gap-2 text-[10px]">
                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  {benchmark.filename}
                </span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400">Target: {benchmark.defaultLabelColumn}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Upload Drag & Drop Area */}
      <div
        onDragOver={e => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
          isDragging
            ? 'border-blue-500 bg-blue-500/10'
            : 'border-slate-800 hover:border-slate-700 bg-slate-950/40 hover:bg-slate-950/70'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          accept=".csv,.txt"
          className="hidden"
          onChange={e => {
            if (e.target.files && e.target.files.length > 0) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />

        <div className="flex flex-col items-center justify-center gap-2">
          <div className="p-3 rounded-full bg-slate-800 text-slate-300">
            <Upload className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-200">
              <span className="text-blue-400 hover:underline">Click to browse custom dataset</span> or drag and drop CSV file here
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Supports standard CSV network telemetry (CICIDS, UNSW-NB15, KDD Cup 99, Zeek/Bro, or Suricata flows)
            </p>
          </div>
          <span className="text-[10px] text-slate-500 bg-slate-800/80 px-2 py-0.5 rounded-full mt-1">
            Treats uploaded files strictly as data • Max file size: 50MB
          </span>
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center gap-2 py-2 text-xs text-blue-400 font-medium">
          <div className="w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
          <span>Parsing and inspecting dataset schema...</span>
        </div>
      )}

      {errorMessage && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold">Dataset Ingestion Error:</span> {errorMessage}
          </div>
        </div>
      )}
    </div>
  );
};
