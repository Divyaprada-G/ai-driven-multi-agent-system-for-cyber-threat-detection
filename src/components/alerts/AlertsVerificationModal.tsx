import React, { useState, useEffect } from 'react';
import { CheckCircle2, XCircle, RefreshCw, X, ShieldCheck, Play, Award, Clock } from 'lucide-react';
import { AlertIncidentTestSuite, TestResult } from '../../services/alertIncident/alertTests';

interface AlertsVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AlertsVerificationModal: React.FC<AlertsVerificationModalProps> = ({
  isOpen,
  onClose
}) => {
  if (!isOpen) return null;

  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<TestResult[]>([]);
  const [summary, setSummary] = useState<{ total: number; passed: number; failed: number; durationMs: number } | null>(null);

  const runTests = async () => {
    setIsRunning(true);
    try {
      const outcome = await AlertIncidentTestSuite.runAllTests();
      setResults(outcome.results);
      setSummary(outcome.summary);
    } catch (err) {
      console.error('Test suite failure', err);
    } finally {
      setIsRunning(false);
    }
  };

  useEffect(() => {
    runTests();
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
      <div
        id="modal-alerts-verification"
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-5 my-8 text-slate-200"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-600/40 text-emerald-400">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">
                Stage 9 Specification Test Runner
              </span>
              <h2 className="text-lg font-bold text-white tracking-tight">
                Alert & Incident Management Verification Suite (14 Tests)
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Summary Card */}
        {summary && (
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4 font-mono">
            <div className="flex items-center gap-4">
              <div>
                <div className="text-[11px] text-slate-400 uppercase">Test Suite Status</div>
                <div className="text-lg font-bold text-emerald-400 flex items-center gap-1.5 mt-0.5">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span>
                    {summary.passed} / {summary.total} PASSED
                  </span>
                </div>
              </div>

              <div className="h-8 w-px bg-slate-800 hidden sm:block" />

              <div>
                <div className="text-[11px] text-slate-400 uppercase">Total Execution Time</div>
                <div className="text-sm font-semibold text-slate-200 flex items-center gap-1 mt-1">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{summary.durationMs} ms</span>
                </div>
              </div>
            </div>

            <button
              onClick={runTests}
              disabled={isRunning}
              className="px-3.5 py-1.5 text-xs font-mono bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
              <span>{isRunning ? 'Running...' : 'Rerun Suite'}</span>
            </button>
          </div>
        )}

        {/* Test List */}
        <div className="max-h-96 overflow-y-auto space-y-2 pr-1">
          {results.map((test, index) => (
            <div
              key={test.id}
              className={`p-3 rounded-xl border transition-all ${
                test.passed
                  ? 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                  : 'bg-rose-950/30 border-rose-800/60'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  {test.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">
                        {test.id}
                      </span>
                      <span className="text-xs font-semibold text-slate-200">
                        {test.name}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                      {test.message}
                    </div>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                      test.passed
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                        : 'bg-rose-950 text-rose-400 border-rose-800'
                    }`}
                  >
                    {test.passed ? 'PASS' : 'FAIL'}
                  </span>
                  <div className="text-[10px] font-mono text-slate-500 mt-1">
                    {test.durationMs}ms
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
          <div>Covers all 14 Stage 9 prompt specifications.</div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors"
          >
            Close Runner
          </button>
        </div>
      </div>
    </div>
  );
};
