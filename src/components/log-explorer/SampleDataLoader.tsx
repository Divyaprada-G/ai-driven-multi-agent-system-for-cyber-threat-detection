import React, { useState } from 'react';
import { SAMPLE_DATASETS, triggerSampleDownload } from '../../services/sampleDatasets';
import { logRepository } from '../../services/logRepository';
import { Download, Play, Database, Check, Loader2 } from 'lucide-react';

interface SampleDataLoaderProps {
  onDataLoaded: () => void;
}

export const SampleDataLoader: React.FC<SampleDataLoaderProps> = ({ onDataLoaded }) => {
  const [loadingKey, setLoadingKey] = useState<string | null>(null);
  const [successKey, setSuccessKey] = useState<string | null>(null);

  const handleLoadSample = async (key: string) => {
    try {
      setLoadingKey(key);
      await logRepository.loadSample(key);
      setSuccessKey(key);
      onDataLoaded();
      setTimeout(() => setSuccessKey(null), 2500);
    } catch (err) {
      console.error('Failed to load sample dataset', err);
    } finally {
      setLoadingKey(null);
    }
  };

  const sampleList = Object.values(SAMPLE_DATASETS);

  return (
    <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3" id="sample-dataset-loader">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            Load Realistic Major Project Test Datasets
          </h3>
          <p className="text-xs text-slate-400">
            Instant sample feeds from Suricata, Sysmon, and Nginx. Load directly or download to test file drag-and-drop.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        {sampleList.map(sample => {
          const isLoading = loadingKey === sample.id;
          const isSuccess = successKey === sample.id;

          const badgeColor =
            sample.targetAgent === 'NETWORK'
              ? 'bg-blue-950/60 text-blue-400 border-blue-800'
              : sample.targetAgent === 'SYSTEM'
              ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
              : sample.targetAgent === 'APPLICATION'
              ? 'bg-purple-950/60 text-purple-400 border-purple-800'
              : 'bg-cyan-950/60 text-cyan-400 border-cyan-800';

          return (
            <div
              key={sample.id}
              className="p-3 bg-slate-950/70 border border-slate-800/90 rounded-lg flex flex-col justify-between space-y-2.5 hover:border-slate-700 transition-colors"
            >
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${badgeColor}`}>
                    {sample.targetAgent}
                  </span>
                  <span className="text-[10px] font-mono bg-slate-900 px-1.5 py-0.5 rounded text-slate-400 border border-slate-800">
                    {sample.format} • {sample.eventCount} evts
                  </span>
                </div>
                <h4 className="text-xs font-bold text-slate-100 leading-snug">
                  {sample.name}
                </h4>
                <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                  {sample.description}
                </p>
              </div>

              <div className="flex items-center gap-1.5 pt-1">
                <button
                  id={`btn-load-sample-${sample.id}`}
                  onClick={() => handleLoadSample(sample.id)}
                  disabled={isLoading}
                  className={`flex-1 px-2.5 py-1.5 text-xs font-mono rounded-md font-medium flex items-center justify-center gap-1.5 transition-colors ${
                    isSuccess
                      ? 'bg-emerald-600 text-white'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold'
                  }`}
                >
                  {isLoading ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : isSuccess ? (
                    <Check className="w-3.5 h-3.5" />
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  <span>{isLoading ? 'Ingesting...' : isSuccess ? 'Ingested' : 'Load Stream'}</span>
                </button>

                <button
                  id={`btn-download-sample-${sample.id}`}
                  onClick={() => triggerSampleDownload(sample.id)}
                  className="px-2 py-1.5 text-xs font-mono rounded-md bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:text-white transition-colors"
                  title={`Download ${sample.filename}`}
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
