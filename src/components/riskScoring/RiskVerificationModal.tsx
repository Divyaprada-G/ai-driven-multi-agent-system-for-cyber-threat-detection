/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Live Risk Scoring Verification Test Suite Modal
 */

import React, { useState } from 'react';
import { X, Play, CheckCircle2, XCircle, AlertCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import { runRiskScoringTests, VerificationSuiteSummary } from '../../services/riskScoring/riskTests';

interface RiskVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const RiskVerificationModal: React.FC<RiskVerificationModalProps> = ({
  isOpen,
  onClose
}) => {
  const [suiteResult, setSuiteResult] = useState<VerificationSuiteSummary | null>(() => runRiskScoringTests());
  const [isRunning, setIsRunning] = useState(false);

  if (!isOpen) return null;

  const handleRerun = () => {
    setIsRunning(true);
    setTimeout(() => {
      setSuiteResult(runRiskScoringTests());
      setIsRunning(false);
    }, 300);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto font-mono"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                Stage 8 Verification Test Suite (8 Test Cases)
              </h3>
              <p className="text-xs text-slate-400">
                Mandatory functional verification suite for Prompt 08 specifications.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action & Stats Banner */}
        {suiteResult && (
          <div className="p-4 bg-slate-950/90 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3">
              <span
                className={`px-3 py-1 rounded-full font-bold border flex items-center gap-1.5 ${
                  suiteResult.allPassed
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : 'bg-rose-950 text-rose-300 border-rose-700'
                }`}
              >
                {suiteResult.allPassed ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                {suiteResult.passed} / {suiteResult.total} Tests Passed
              </span>
              <span className="text-slate-400">
                Completed: {new Date(suiteResult.timestamp).toLocaleTimeString()}
              </span>
            </div>

            <button
              onClick={handleRerun}
              disabled={isRunning}
              className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition-colors flex items-center gap-1.5 self-end sm:self-auto"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
              <span>Re-run Suite</span>
            </button>
          </div>
        )}

        {/* Tests List */}
        <div className="p-4 max-h-[60vh] overflow-y-auto space-y-2.5 text-xs">
          {suiteResult?.results.map(test => (
            <div
              key={test.id}
              className={`p-3 rounded-xl border ${
                test.passed
                  ? 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  : 'bg-rose-950/30 border-rose-800'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2">
                  {test.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <span className="font-bold text-white">
                      [{test.id}] {test.name}
                    </span>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Expected: <span className="text-slate-300">{test.expected}</span>
                    </div>
                    <div className="text-[11px] text-cyan-400 mt-0.5">
                      Actual: {test.actual}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      Details: {test.details}
                    </div>
                  </div>
                </div>

                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase shrink-0 ${
                    test.passed
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {test.passed ? 'PASS' : 'FAIL'}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 text-right">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
          >
            Close Verification
          </button>
        </div>
      </div>
    </div>
  );
};
