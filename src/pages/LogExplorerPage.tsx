import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  UploadCloud,
  FileText,
  Trash2,
  Eye,
  CheckCircle2,
  Clock,
  Filter,
  Plus,
  RefreshCw,
  Terminal,
  ShieldAlert,
  Code,
  FileCode,
  Layers,
  Sparkles,
  AlertTriangle
} from 'lucide-react';
import { LogEvent, LogFileRecord, LogType, RepositoryStats } from '../types';
import { StatusBadge } from '../components/common/StatusBadge';
import { logRepository } from '../services/logRepository';
import { PipelineStatusBar } from '../components/log-explorer/PipelineStatusBar';
import { IngestionStatsBar } from '../components/log-explorer/IngestionStatsBar';
import { SampleDataLoader } from '../components/log-explorer/SampleDataLoader';
import { LogEventExplorerTable } from '../components/log-explorer/LogEventExplorerTable';
import { LogEventInspectorModal } from '../components/modals/LogEventInspectorModal';

interface LogExplorerPageProps {
  files: LogFileRecord[];
  onUploadFile: (file: File, logType?: LogType) => Promise<LogFileRecord>;
  onDeleteFile: (id: string) => Promise<boolean>;
}

export const LogExplorerPage: React.FC<LogExplorerPageProps> = ({
  files: propFiles,
  onUploadFile,
  onDeleteFile
}) => {
  const [selectedLogType, setSelectedLogType] = useState<LogType | 'AUTO'>('AUTO');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [rawTextInput, setRawTextInput] = useState('');
  const [showPasteBox, setShowPasteBox] = useState(false);
  const [selectedEventModal, setSelectedEventModal] = useState<LogEvent | null>(null);

  // Local repository state
  const [repoStats, setRepoStats] = useState<RepositoryStats>(logRepository.getStats());
  const [repoEvents, setRepoEvents] = useState<LogEvent[]>(logRepository.getEvents().events);
  const [repoFiles, setRepoFiles] = useState<LogFileRecord[]>(
    logRepository.hasRealData() ? logRepository.getUploadedFiles() : propFiles
  );
  const [activePreview, setActivePreview] = useState<LogFileRecord | null>(
    repoFiles[0] || null
  );

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const syncRepository = useCallback(() => {
    setRepoStats(logRepository.getStats());
    setRepoEvents(logRepository.getEvents().events);
    if (logRepository.hasRealData()) {
      const files = logRepository.getUploadedFiles();
      setRepoFiles(files);
      if (!activePreview && files.length > 0) {
        setActivePreview(files[0]);
      }
    } else {
      setRepoFiles(propFiles);
      if (propFiles.length > 0) setActivePreview(propFiles[0]);
    }
  }, [propFiles, activePreview]);

  useEffect(() => {
    syncRepository();
    const unsubscribe = logRepository.subscribe(syncRepository);
    return () => unsubscribe();
  }, [syncRepository]);

  // File Drag & Drop Handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const processFile = async (file: File) => {
    setIsUploading(true);
    try {
      const targetType = selectedLogType === 'AUTO' ? undefined : selectedLogType;
      const uploaded = await onUploadFile(file, targetType);
      setActivePreview(uploaded);
      syncRepository();
    } catch (err) {
      console.error('File ingestion failed', err);
    } finally {
      setIsUploading(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFile(e.target.files[0]);
      e.target.value = '';
    }
  };

  const handlePasteIngest = async () => {
    if (!rawTextInput.trim()) return;
    setIsUploading(true);
    try {
      const targetType = selectedLogType === 'AUTO' ? undefined : selectedLogType;
      await logRepository.ingestRawContent(
        rawTextInput.trim(),
        `pasted_stream_${Date.now().toString().slice(-4)}.log`,
        targetType
      );
      setRawTextInput('');
      setShowPasteBox(false);
      syncRepository();
    } catch (err) {
      console.error('Pasted text ingestion failed', err);
    } finally {
      setIsUploading(false);
    }
  };

  const handleDeleteFile = async (fileId: string) => {
    if (logRepository.hasRealData()) {
      logRepository.deleteFile(fileId);
    } else {
      await onDeleteFile(fileId);
    }
    syncRepository();
    if (activePreview?.id === fileId) {
      setActivePreview(null);
    }
  };

  const handleResetToDemo = () => {
    logRepository.clearAll();
    syncRepository();
  };

  const filteredFiles = repoFiles.filter(f => {
    if (filterType === 'ALL') return true;
    return f.logType === filterType;
  });

  return (
    <div className="space-y-6" id="page-log-explorer">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Stage 2 • Ingestion & Preprocessing Pipeline
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Log Explorer & Ingestion Pipeline
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Feed raw security telemetry from Network probes (Suricata JSONL), Host monitors (Sysmon/Auditd CSV), and Web App gateways (Nginx/Cloudflare) into the normalized multi-agent detection pipeline.
        </p>
      </div>

      {/* Pipeline Status Bar (honest connection & sensor labeling) */}
      <PipelineStatusBar
        hasRealData={repoStats.isRealDataActive}
        totalEvents={repoStats.totalEvents}
      />

      {/* Telemetry Stats Bar */}
      <IngestionStatsBar stats={repoStats} />

      {/* Sample Dataset Quick Loader */}
      <SampleDataLoader onDataLoaded={syncRepository} />

      {/* Drag and Drop Upload Area */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              Ingest Security Log File
            </h3>
            <p className="text-xs text-slate-400">
              Drag and drop log files (JSON, JSONL, CSV, or SYSLOG). Heuristic log domain detection assigns events automatically.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Target Agent Domain Override */}
            <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
              <span className="text-[10px] text-slate-500 uppercase px-2">Domain:</span>
              {(['AUTO', 'NETWORK', 'SYSTEM', 'APPLICATION'] as const).map(type => (
                <button
                  key={type}
                  id={`btn-select-type-${type.toLowerCase()}`}
                  onClick={() => setSelectedLogType(type)}
                  className={`px-2.5 py-1 text-xs rounded-md transition-colors ${
                    selectedLogType === type
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {type === 'AUTO' ? 'Auto-Detect' : type}
                </button>
              ))}
            </div>

            {/* Direct Paste Toggle */}
            <button
              id="btn-toggle-paste-stream"
              onClick={() => setShowPasteBox(!showPasteBox)}
              className={`px-3 py-1.5 text-xs font-mono rounded-lg border transition-colors flex items-center gap-1.5 ${
                showPasteBox
                  ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              {showPasteBox ? 'Hide Paste' : 'Paste Stream'}
            </button>
          </div>
        </div>

        {/* Dropzone */}
        {!showPasteBox ? (
          <div
            id="dropzone-log-upload"
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-200 ${
              isDragging
                ? 'border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.15)]'
                : 'border-slate-700/80 bg-slate-950/60 hover:border-slate-600 hover:bg-slate-900/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              accept=".log,.json,.jsonl,.ndjson,.csv,.txt,.syslog"
              onChange={handleFileInputChange}
            />

            <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center mb-3">
              <UploadCloud className={`w-6 h-6 ${isDragging ? 'text-cyan-400 animate-bounce' : 'text-slate-400'}`} />
            </div>

            <div className="text-sm font-semibold text-slate-200">
              {isUploading
                ? 'Parsing, normalizing and validating untrusted telemetry stream...'
                : 'Drag and drop security log files here, or click to browse'}
            </div>

            <p className="text-xs text-slate-500 font-mono mt-1">
              Domain Mode: <span className="text-cyan-400 font-bold">{selectedLogType === 'AUTO' ? 'HEURISTIC AUTO-DETECTION' : `${selectedLogType} AGENT`}</span> • Formats: JSON, JSONL, CSV, Apache/Nginx Syslog
            </p>

            <button
              type="button"
              id="btn-trigger-upload-dialog"
              className="mt-4 px-4 py-1.5 text-xs font-mono font-medium rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-colors"
            >
              Select File from Disk
            </button>
          </div>
        ) : (
          /* Direct Paste Box */
          <div className="space-y-3 p-4 bg-slate-950 border border-slate-800 rounded-xl">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Paste Raw Telemetry Lines (JSON array, JSONL, CSV, or Apache/Syslog):</span>
              <span className="text-[11px] text-slate-500">Supports untrusted inputs with error isolation</span>
            </div>
            <textarea
              id="textarea-paste-raw-stream"
              value={rawTextInput}
              onChange={e => setRawTextInput(e.target.value)}
              placeholder={`{"timestamp":"2026-09-11T22:58:14Z","src_ip":"192.168.1.105","dest_ip":"10.0.0.5","proto":"TCP","msg":"SYN scan"}\n{"timestamp":"2026-09-11T22:58:15Z","src_ip":"192.168.1.105","dest_ip":"10.0.0.5","proto":"TCP","msg":"SYN scan"}`}
              rows={5}
              className="w-full p-3 bg-black/80 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400 focus:outline-none focus:border-cyan-500"
            />
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowPasteBox(false)}
                className="px-3 py-1.5 text-xs font-mono rounded-lg bg-slate-900 text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                id="btn-submit-pasted-stream"
                onClick={handlePasteIngest}
                disabled={!rawTextInput.trim() || isUploading}
                className="px-4 py-1.5 text-xs font-mono rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-colors disabled:opacity-50 flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                {isUploading ? 'Ingesting Stream...' : 'Parse & Ingest Stream'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Ingested Files Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Ingested Telemetry Files ({repoFiles.length})
            </h3>
            <p className="text-xs text-slate-400">
              Source files mapped to specialized detection agent domain queues.
            </p>
          </div>

          {/* Filter by Log Type */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              id="select-log-file-filter"
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Log Types</option>
              <option value="NETWORK">Network Logs</option>
              <option value="SYSTEM">System Logs</option>
              <option value="APPLICATION">Application Logs</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4">Target Domain</th>
                <th className="py-3 px-4">File Size</th>
                <th className="py-3 px-4">Ingestion Time</th>
                <th className="py-3 px-4">Conformity</th>
                <th className="py-3 px-4">Events</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredFiles.map(file => {
                const isValid = file.invalidCount === 0 || !file.invalidCount;
                return (
                  <tr
                    key={file.id}
                    id={`row-file-${file.id.toLowerCase()}`}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      activePreview?.id === file.id ? 'bg-slate-800/30' : ''
                    }`}
                  >
                    <td className="py-3 px-4 font-sans font-medium text-slate-100 flex items-center gap-2">
                      <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span className="truncate max-w-xs">{file.filename}</span>
                    </td>

                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-slate-300 border border-slate-800">
                        {file.detectedFormat || 'LOG'}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                          file.logType === 'NETWORK'
                            ? 'border-blue-800/60 bg-blue-950/50 text-blue-400'
                            : file.logType === 'SYSTEM'
                            ? 'border-emerald-800/60 bg-emerald-950/50 text-emerald-400'
                            : 'border-purple-800/60 bg-purple-950/50 text-purple-400'
                        }`}
                      >
                        {file.logType}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-400">{file.fileSize}</td>

                    <td className="py-3 px-4 text-slate-400 text-[11px]">{file.uploadTime}</td>

                    <td className="py-3 px-4">
                      {isValid ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>100% Valid</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-amber-400">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>{file.invalidCount} warning(s)</span>
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 font-bold text-white">
                      {file.numberOfEvents.toLocaleString()}
                    </td>

                    <td className="py-3 px-4 text-right space-x-1">
                      <button
                        id={`btn-preview-file-${file.id.toLowerCase()}`}
                        onClick={() => setActivePreview(file)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors inline-flex items-center"
                        title="Inspect Raw Telemetry Sample"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        id={`btn-delete-file-${file.id.toLowerCase()}`}
                        onClick={() => handleDeleteFile(file.id)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors inline-flex items-center"
                        title="Purge File"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Stream Inspector Preview */}
      {activePreview && (
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 shadow-inner">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-semibold">
              <Terminal className="w-4 h-4" />
              <span>TELEMETRY STREAM SNIPPET: {activePreview.filename}</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
              {activePreview.parsingDurationMs && (
                <span>Parsing latency: {activePreview.parsingDurationMs}ms</span>
              )}
              <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                Target: {activePreview.logType}_AGENT
              </span>
            </div>
          </div>

          <div className="p-3 bg-black/90 rounded-lg border border-slate-900 font-mono text-xs text-emerald-400 space-y-1.5 overflow-x-auto max-h-48 leading-relaxed select-all">
            {activePreview.parsedPreview && activePreview.parsedPreview.length > 0 ? (
              activePreview.parsedPreview.map((line, idx) => (
                <div key={idx} className="whitespace-pre">
                  <span className="text-slate-600 select-none mr-2">[{idx + 1}]</span>
                  {line}
                </div>
              ))
            ) : (
              <div className="text-slate-500 italic">No stream snippet available.</div>
            )}
          </div>
        </div>
      )}

      {/* Unified Security Event Stream Explorer Table */}
      <LogEventExplorerTable
        events={repoEvents}
        onSelectEvent={setSelectedEventModal}
        onClearData={handleResetToDemo}
      />

      {/* Log Event Detailed Inspector Modal */}
      <LogEventInspectorModal
        event={selectedEventModal}
        onClose={() => setSelectedEventModal(null)}
      />
    </div>
  );
};
