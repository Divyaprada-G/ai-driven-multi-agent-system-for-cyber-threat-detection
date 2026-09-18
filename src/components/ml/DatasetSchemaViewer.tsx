import React, { useState } from 'react';
import {
  FileSpreadsheet,
  AlertTriangle,
  Layers,
  PieChart,
  Hash,
  ShieldAlert,
  Clock,
  Eye,
  CheckCircle2,
  AlertCircle,
  Bug,
  Filter,
  Table as TableIcon
} from 'lucide-react';
import { DatasetSchema, ColumnInspectionMeta } from '../../types/datasetMl';

interface Props {
  schema: DatasetSchema;
  onLabelChange: (newLabel: string) => void;
}

export const DatasetSchemaViewer: React.FC<Props> = ({ schema, onLabelChange }) => {
  const [activeTab, setActiveTab] = useState<'columns' | 'distribution' | 'sample' | 'errors'>('columns');
  const [searchColumn, setSearchColumn] = useState('');
  const [selectedErrorFilter, setSelectedErrorFilter] = useState<string>('ALL');

  const filteredColumns = schema.columns.filter(c =>
    c.name.toLowerCase().includes(searchColumn.toLowerCase())
  );

  const validationPercentage = schema.validationPercentage ?? 100;
  const invalidCount = schema.invalidRowCount ?? (schema.rowErrors ? schema.rowErrors.filter(r => r.status === 'INVALID').length : 0);
  const rowErrors = schema.rowErrors || [];

  const filteredRowErrors = rowErrors.filter(r => {
    if (selectedErrorFilter === 'ALL') return true;
    return r.errors.some(e => e.code === selectedErrorFilter);
  });

  return (
    <div id="dataset-schema-viewer" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Total Samples</span>
          <span className="text-base font-bold text-slate-100 font-mono">
            {schema.rowCount.toLocaleString()}
          </span>
        </div>

        {/* Schema Validation Conformity Card */}
        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50" id="metric-schema-validation">
          <span className="text-[11px] text-slate-400 block font-medium">Schema Validation</span>
          <span className={`text-base font-bold font-mono ${validationPercentage === 100 ? 'text-emerald-400' : 'text-amber-400'}`}>
            {validationPercentage}% Valid
          </span>
        </div>

        {/* Error Detection Metric Card */}
        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50" id="metric-error-detection">
          <span className="text-[11px] text-slate-400 block font-medium">Error Detection</span>
          <span className={`text-base font-bold font-mono ${invalidCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {invalidCount > 0 ? `${invalidCount} invalid` : 'No errors'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Total Columns</span>
          <span className="text-base font-bold text-slate-100 font-mono">{schema.columnCount}</span>
        </div>

        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Numeric Features</span>
          <span className="text-base font-bold text-cyan-400 font-mono">
            {schema.numericFeatureCount}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Identifiers Excluded</span>
          <span className="text-base font-bold text-amber-400 font-mono">
            {schema.identifierColumns.length}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Duplicate Rows</span>
          <span
            className={`text-base font-bold font-mono ${
              schema.duplicateRowsCount > 0 ? 'text-amber-400' : 'text-emerald-400'
            }`}
          >
            {schema.duplicateRowsCount}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
          <span className="text-[11px] text-slate-400 block font-medium">Infinite Values</span>
          <span
            className={`text-base font-bold font-mono ${
              schema.infiniteValuesCount > 0 ? 'text-red-400' : 'text-emerald-400'
            }`}
          >
            {schema.infiniteValuesCount}
          </span>
        </div>
      </div>

      {/* Schema Warnings Section */}
      <div id="dataset-schema-warnings" className="rounded-lg bg-slate-950/80 border border-slate-800 p-3.5 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className={`w-4 h-4 ${schema.schemaWarnings && schema.schemaWarnings.length > 0 ? 'text-amber-400' : 'text-slate-500'}`} />
            <span className="text-xs font-semibold text-slate-200">Schema Warnings:</span>
            {schema.schemaWarnings && schema.schemaWarnings.length > 0 ? (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-mono font-medium">
                {schema.schemaWarnings.length} Issue(s) Detected
              </span>
            ) : (
              <span className="text-xs text-slate-500 font-mono">Empty</span>
            )}
          </div>
          {rowErrors.length > 0 && (
            <button
              onClick={() => setActiveTab('errors')}
              className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono"
            >
              View {rowErrors.length} Offending Row(s)
            </button>
          )}
        </div>

        {schema.schemaWarnings && schema.schemaWarnings.length > 0 ? (
          <ul className="space-y-1 pt-1 text-xs text-amber-300 font-mono pl-6 list-disc">
            {schema.schemaWarnings.map((warn, i) => (
              <li key={i}>{warn}</li>
            ))}
          </ul>
        ) : (
          <p className="text-[11px] text-slate-500 font-mono">
            No schema warnings present. All values conform to standard network and cyber telemetry schema specifications.
          </p>
        )}
      </div>

      {/* Target Column Selector & Auto-Detection Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          <span className="text-xs font-semibold text-slate-200">Target / Label Column:</span>
          {schema.labelAutoDetected ? (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-medium flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" /> Auto-Detected
            </span>
          ) : (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-medium flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Manual Selection
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Select Ground Truth:</span>
          <select
            value={schema.labelColumn || ''}
            onChange={e => onLabelChange(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
          >
            {schema.columns.map(col => (
              <option key={col.name} value={col.name}>
                {col.name} ({col.dataType})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-2 gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('columns')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'columns'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Hash className="w-3.5 h-3.5" />
            Column Schema & Inspection ({schema.columnCount})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('distribution')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'distribution'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <PieChart className="w-3.5 h-3.5" />
            Class Distribution ({schema.classes.length} Classes)
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('sample')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'sample'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            Data Sample Preview (15 Rows)
          </button>

          <button
            type="button"
            id="tab-data-quality"
            onClick={() => setActiveTab('errors')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'errors'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : rowErrors.length > 0
                ? 'text-rose-400 hover:text-rose-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bug className="w-3.5 h-3.5" />
            Error Detection ({rowErrors.length})
          </button>
        </div>

        {activeTab === 'columns' && (
          <input
            type="text"
            placeholder="Search column..."
            value={searchColumn}
            onChange={e => setSearchColumn(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs text-slate-300 rounded-lg px-2.5 py-1 w-44 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        )}
      </div>

      {/* Tab 1: Column Schema Table */}
      {activeTab === 'columns' && (
        <div className="overflow-x-auto max-h-80 border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-950 text-slate-400 sticky top-0 border-b border-slate-800 font-semibold">
              <tr>
                <th className="py-2.5 px-3">Column Name</th>
                <th className="py-2.5 px-3">Inferred Type</th>
                <th className="py-2.5 px-3">Missing</th>
                <th className="py-2.5 px-3">Unique Values</th>
                <th className="py-2.5 px-3">ML Pipeline Role</th>
                <th className="py-2.5 px-3">Sample Values</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredColumns.map(col => {
                const isTarget = col.name === schema.labelColumn;
                return (
                  <tr key={col.name} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2 px-3 text-slate-200 font-medium">
                      {col.name}
                    </td>
                    <td className="py-2 px-3 text-slate-400">{col.dataType} ({col.inferredType})</td>
                    <td className="py-2 px-3">
                      {col.missingCount > 0 ? (
                        <span className="text-amber-400 font-semibold">
                          {col.missingCount} ({col.missingPercentage.toFixed(1)}%)
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-slate-300">{col.uniqueValuesCount}</td>
                    <td className="py-2 px-3">
                      {isTarget ? (
                        <span className="px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 font-semibold text-[10px]">
                          Target (Ground Truth)
                        </span>
                      ) : col.isPotentialIdentifier ? (
                        <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-semibold text-[10px]" title="Excluded from features to prevent leakage/overfitting">
                          Raw Identifier (Evidence Only)
                        </span>
                      ) : col.isPotentialTimestamp ? (
                        <span className="px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 font-semibold text-[10px]">
                          Timestamp (Isolated)
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-semibold text-[10px]">
                          Feature Input
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-[11px] text-slate-400 max-w-xs truncate">
                      {col.sampleValues.slice(0, 3).join(', ')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 2: Class Distribution */}
      {activeTab === 'distribution' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2.5">
              <h4 className="text-xs font-semibold text-slate-300">
                Ground Truth Class Breakdown ({schema.labelColumn})
              </h4>
              {Object.entries(schema.classDistribution).map(([className, rawCount]) => {
                const count = Number(rawCount);
                const pct = schema.rowCount > 0 ? (count / schema.rowCount) * 100 : 0;
                const isBenign = className.toLowerCase().includes('benign') || className.toLowerCase().includes('normal');
                return (
                  <div key={className} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            isBenign ? 'bg-emerald-400' : 'bg-red-400'
                          }`}
                        />
                        {className}
                      </span>
                      <span className="font-mono text-slate-300">
                        {count.toLocaleString()} samples ({pct.toFixed(1)}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-full ${isBenign ? 'bg-emerald-500' : 'bg-red-500'}`}
                        style={{ width: `${Math.max(pct, 2)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-300">Class Imbalance & Sampling Analysis</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Cybersecurity network traffic characteristically exhibits severe class imbalance, with benign traffic vastly outnumbering malicious intrusion events.
              </p>
              <div className="space-y-2 text-xs text-slate-300">
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Total Classes Detected:</span>
                  <span className="font-bold text-slate-100">{schema.classes.length}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Recommended Split:</span>
                  <span className="font-mono text-cyan-300">Stratified 80/20 Split</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Classifier Strategy:</span>
                  <span className="font-mono text-purple-300">class_weight='balanced'</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Raw Sample Preview */}
      {activeTab === 'sample' && schema.rawContentSample && (
        <div className="overflow-x-auto max-h-80 border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-950 text-slate-400 sticky top-0 border-b border-slate-800 font-semibold">
              <tr>
                {schema.columns.map(col => (
                  <th key={col.name} className="py-2.5 px-3 whitespace-nowrap">
                    {col.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {schema.rawContentSample.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                  {schema.columns.map(col => (
                    <td key={col.name} className="py-1.5 px-3 text-slate-300 whitespace-nowrap">
                      {String(row[col.name] ?? '')}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 4: Data Quality & Error Detection */}
      {activeTab === 'errors' && (
        <div className="space-y-4">
          {/* Error Controls & Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-semibold text-slate-200">Error Filter:</span>
              <select
                id="select-schema-error-filter"
                value={selectedErrorFilter}
                onChange={e => setSelectedErrorFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              >
                <option value="ALL">All Detected Errors ({rowErrors.length})</option>
                <option value="MISSING_IP">Missing IP Addresses ({schema.errorsByCode?.MISSING_IP || 0})</option>
                <option value="INVALID_IP">Invalid IP Addresses ({schema.errorsByCode?.INVALID_IP || 0})</option>
                <option value="INVALID_PROTOCOL">Invalid Protocols ({schema.errorsByCode?.INVALID_PROTOCOL || 0})</option>
                <option value="NEGATIVE_FAILED_LOGINS">Negative Failed Logins ({schema.errorsByCode?.NEGATIVE_FAILED_LOGINS || 0})</option>
                <option value="INVALID_TIMESTAMP">Invalid Timestamps ({schema.errorsByCode?.INVALID_TIMESTAMP || 0})</option>
                <option value="MISSING_LABEL">Missing Labels ({schema.errorsByCode?.MISSING_LABEL || 0})</option>
                <option value="DUPLICATE_ROW">Duplicate Records ({schema.errorsByCode?.DUPLICATE_ROW || 0})</option>
                <option value="INVALID_PORT">Port Out of Bounds ({schema.errorsByCode?.INVALID_PORT || 0})</option>
                <option value="NEGATIVE_METRIC">Negative Metric ({schema.errorsByCode?.NEGATIVE_METRIC || 0})</option>
              </select>
            </div>

            <div className="text-xs font-mono text-slate-400">
              Showing {filteredRowErrors.length} of {rowErrors.length} offending record(s)
            </div>
          </div>

          {/* Table of Offending Records */}
          <div className="overflow-x-auto max-h-96 border border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-950 text-slate-400 sticky top-0 border-b border-slate-800 font-semibold font-mono">
                <tr>
                  <th className="py-2.5 px-3">Row #</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Error Code</th>
                  <th className="py-2.5 px-3">Offending Field</th>
                  <th className="py-2.5 px-3">Original Problematic Value</th>
                  <th className="py-2.5 px-3">Diagnostic Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {filteredRowErrors.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                      {rowErrors.length === 0
                        ? 'No data quality errors detected in this dataset. Schema is 100% compliant.'
                        : 'No errors match the selected filter criterion.'}
                    </td>
                  </tr>
                ) : (
                  filteredRowErrors.map((rowErr, rIdx) => {
                    return rowErr.errors.map((err, eIdx) => (
                      <tr key={`${rIdx}-${eIdx}`} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2 px-3 text-cyan-400 font-bold whitespace-nowrap">
                          #{rowErr.rowNumber}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              err.severity === 'ERROR'
                                ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                                : 'bg-amber-950/60 text-amber-400 border-amber-800'
                            }`}
                          >
                            {rowErr.status}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-rose-300 font-bold whitespace-nowrap">
                          {err.code}
                        </td>
                        <td className="py-2 px-3 text-purple-300 whitespace-nowrap">
                          {err.field}
                        </td>
                        <td className="py-2 px-3 text-amber-300 whitespace-nowrap font-semibold">
                          {err.originalValue !== undefined && err.originalValue !== ''
                            ? String(err.originalValue)
                            : '<EMPTY / MISSING>'}
                        </td>
                        <td className="py-2 px-3 text-slate-300 max-w-md">
                          {err.message}
                        </td>
                      </tr>
                    ));
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
