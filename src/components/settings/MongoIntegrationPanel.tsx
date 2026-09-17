/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Integration & Management Dashboard Panel
 */
import React, { useState, useEffect } from 'react';
import {
  Database,
  CheckCircle2,
  AlertTriangle,
  Play,
  RefreshCw,
  Server,
  Shield,
  FileText,
  Clock,
  Key,
  Layers,
  Terminal,
  Cpu
} from 'lucide-react';

interface MongoHealth {
  connected: boolean;
  status: string;
  database?: string;
  latencyMs?: number;
  collections?: {
    eventsCount: number;
    incidentsCount: number;
    detectionsCount: number;
    alertsCount: number;
    logsCount: number;
    modelsCount: number;
  };
  details?: string;
  timestamp: string;
}

interface TestCase {
  name: string;
  category: string;
  passed: boolean;
  durationMs: number;
  details: string;
  error?: string;
}

interface TestSuiteSummary {
  timestamp: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  databaseStatus: string;
  results: TestCase[] | null;
}

export const MongoIntegrationPanel: React.FC = () => {
  const [health, setHealth] = useState<MongoHealth | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(false);
  const [runningTests, setRunningTests] = useState(false);
  const [testResults, setTestResults] = useState<TestSuiteSummary | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'tests' | 'schema' | 'windows-setup'>('overview');

  const fetchHealth = async () => {
    setLoadingHealth(true);
    try {
      const res = await fetch('/api/mongo/health');
      const data = await res.json();
      setHealth(data);
    } catch {
      setHealth({
        connected: false,
        status: 'OFFLINE_FALLBACK',
        details: 'Unable to reach backend /api/mongo/health endpoint. Local fallback store active.',
        timestamp: new Date().toISOString()
      });
    } finally {
      setLoadingHealth(false);
    }
  };

  const handleRunTests = async () => {
    setRunningTests(true);
    try {
      const res = await fetch('/api/mongo/test-suite', { method: 'POST' });
      const data = await res.json();
      setTestResults(data);
      setActiveSubTab('tests');
      // refresh health counts after test records are created
      fetchHealth();
    } catch (err: any) {
      setTestResults({
        timestamp: new Date().toISOString(),
        totalTests: 1,
        passedTests: 0,
        failedTests: 1,
        databaseStatus: 'ERROR',
        results: [
          {
            name: 'Test Runner Network Execution',
            category: 'System',
            passed: false,
            durationMs: 0,
            details: 'Failed to contact /api/mongo/test-suite',
            error: err.message
          }
        ]
      });
    } finally {
      setRunningTests(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs" id="mongo-integration-panel">
      {/* Header & Status Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 bg-slate-950 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-lg border ${
            health?.connected
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
          }`}>
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                MongoDB Persistence Engine
              </h3>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                health?.connected
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              }`}>
                {health?.connected ? 'CONNECTED (PRIMARY)' : 'LOCAL JSON STORE (FALLBACK)'}
              </span>
            </div>
            <p className="text-slate-400 text-[11px] mt-0.5">
              {health?.connected
                ? `Connected to database: ${health.database} (${health.latencyMs}ms latency)`
                : health?.details || 'Database URI not provided in .env; automated local resilient persistence active.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchHealth}
            disabled={loadingHealth}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-lg text-xs font-bold inline-flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHealth ? 'animate-spin' : ''}`} />
            <span>Refresh Status</span>
          </button>

          <button
            onClick={handleRunTests}
            disabled={runningTests}
            className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold inline-flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Play className={`w-3.5 h-3.5 ${runningTests ? 'animate-pulse' : ''}`} />
            <span>{runningTests ? 'Executing Tests...' : 'Run MongoDB Test Suite'}</span>
          </button>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('overview')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
            activeSubTab === 'overview'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          Collections & Metrics
        </button>
        <button
          onClick={() => setActiveSubTab('tests')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'tests'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <span>Automated Test Suite</span>
          {testResults && (
            <span className={`px-1.5 py-0.2 rounded text-[10px] ${
              testResults.failedTests === 0 ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'
            }`}>
              {testResults.passedTests}/{testResults.totalTests}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveSubTab('schema')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
            activeSubTab === 'schema'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          Document Schemas & Indexes
        </button>
        <button
          onClick={() => setActiveSubTab('windows-setup')}
          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
            activeSubTab === 'windows-setup'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          Windows Setup & .env Guide
        </button>
      </div>

      {/* TAB 1: OVERVIEW & COLLECTION COUNTS */}
      {activeSubTab === 'overview' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Security Events</span>
              <span className="text-lg font-bold text-white">
                {health?.collections?.eventsCount ?? '--'}
              </span>
              <span className="text-[10px] text-cyan-400/80 block mt-1">security_events</span>
            </div>

            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Correlated Incidents</span>
              <span className="text-lg font-bold text-amber-400">
                {health?.collections?.incidentsCount ?? '--'}
              </span>
              <span className="text-[10px] text-amber-400/80 block mt-1">incidents</span>
            </div>

            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Threat Detections</span>
              <span className="text-lg font-bold text-rose-400">
                {health?.collections?.detectionsCount ?? '--'}
              </span>
              <span className="text-[10px] text-rose-400/80 block mt-1">threat_detections</span>
            </div>

            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Alert Records</span>
              <span className="text-lg font-bold text-orange-400">
                {health?.collections?.alertsCount ?? '--'}
              </span>
              <span className="text-[10px] text-orange-400/80 block mt-1">alerts</span>
            </div>

            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Agent Execution Logs</span>
              <span className="text-lg font-bold text-blue-400">
                {health?.collections?.logsCount ?? '--'}
              </span>
              <span className="text-[10px] text-blue-400/80 block mt-1">agent_logs</span>
            </div>

            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] uppercase block">Model Metadata</span>
              <span className="text-lg font-bold text-purple-400">
                {health?.collections?.modelsCount ?? '--'}
              </span>
              <span className="text-[10px] text-purple-400/80 block mt-1">model_metadata</span>
            </div>
          </div>

          {/* Security Features Architecture */}
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              Security Architecture & Defensive Hardening
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-300">
              <div className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg space-y-1">
                <span className="text-cyan-400 font-bold block">1. Sensitive Data Redaction</span>
                <p className="text-slate-400 text-[11px]">
                  Automatic regex sanitization strips plaintext passwords, bearer tokens, API keys, and authorization headers from incoming payloads prior to storage.
                </p>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg space-y-1">
                <span className="text-cyan-400 font-bold block">2. Query Injection Defense</span>
                <p className="text-slate-400 text-[11px]">
                  Keys starting with &apos;$&apos; or containing &apos;.&apos; are scrubbed during validation to completely prevent BSON query operator injection attacks.
                </p>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg space-y-1">
                <span className="text-cyan-400 font-bold block">3. Deterministic SHA-256 Deduplication</span>
                <p className="text-slate-400 text-[11px]">
                  Unique content hash index on <code className="text-cyan-300">contentHash</code> prevents duplicated network ingestion and eliminates alert fatigue.
                </p>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg space-y-1">
                <span className="text-cyan-400 font-bold block">4. Resilient Connection Fallback</span>
                <p className="text-slate-400 text-[11px]">
                  If MongoDB server is unavailable or undergoing maintenance, queries transparently route to the persistent JSON store with zero downtime.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: AUTOMATED TEST SUITE */}
      {activeSubTab === 'tests' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              Automated Integration Verification Suite
            </h4>
            <button
              onClick={handleRunTests}
              disabled={runningTests}
              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-bold inline-flex items-center gap-1.5"
            >
              <Play className="w-3 h-3" />
              <span>{runningTests ? 'Running...' : 'Re-run Tests'}</span>
            </button>
          </div>

          {!testResults ? (
            <div className="p-8 text-center bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <Database className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-slate-400 text-xs">
                No tests executed yet. Click &quot;Run MongoDB Test Suite&quot; to validate all 13 database operations.
              </p>
              <button
                onClick={handleRunTests}
                disabled={runningTests}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold inline-flex items-center gap-2"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Execute Test Suite Now</span>
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-4 p-3 bg-slate-900 border border-slate-800 rounded-xl">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Total Operations</span>
                  <span className="text-base font-bold text-white">{testResults.totalTests}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Passed</span>
                  <span className="text-base font-bold text-emerald-400">{testResults.passedTests}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Failed</span>
                  <span className="text-base font-bold text-rose-400">{testResults.failedTests}</span>
                </div>
                <div className="ml-auto text-right">
                  <span className="text-slate-500 text-[10px] block">Execution Timestamp</span>
                  <span className="text-slate-300 text-[11px]">{new Date(testResults.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="space-y-2">
                {testResults.results?.map((t, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border transition-all ${
                      t.passed
                        ? 'bg-slate-950 border-slate-800/80 hover:border-slate-700'
                        : 'bg-rose-950/30 border-rose-800/80'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {t.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span className="font-bold text-white text-xs">{t.name}</span>
                        <span className="px-1.5 py-0.2 bg-slate-800 text-slate-400 rounded text-[10px]">
                          {t.category}
                        </span>
                      </div>
                      <span className="text-slate-500 text-[10px]">{t.durationMs}ms</span>
                    </div>
                    <p className="text-slate-400 text-[11px] mt-1 pl-6">
                      {t.details}
                    </p>
                    {t.error && (
                      <p className="text-rose-400 text-[11px] mt-1 pl-6 bg-rose-950/50 p-2 rounded">
                        Error: {t.error}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: SCHEMA & INDEX DOCUMENTATION */}
      {activeSubTab === 'schema' && (
        <div className="space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Database Schema & Performance Indexes
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-cyan-400 font-bold text-xs uppercase block">1. Collection: security_events</span>
              <p className="text-slate-400 text-[11px]">
                Raw and normalized security event telemetry from Zeek, Suricata, Syslog, and Auth.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-cyan-300">contentHash: 1</code> (unique)</p>
                <p>• <code className="text-cyan-300">timestamp: -1, severity: 1</code> (compound)</p>
                <p>• <code className="text-cyan-300">sourceIp: 1, destinationIp: 1</code></p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-amber-400 font-bold text-xs uppercase block">2. Collection: incidents</span>
              <p className="text-slate-400 text-[11px]">
                Correlated security incidents with severity, priority, risk score, and SOC notes.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-amber-300">incidentId: 1</code> (unique)</p>
                <p>• <code className="text-amber-300">status: 1, severity: 1</code> (compound)</p>
                <p>• <code className="text-amber-300">riskScore: -1, createdAt: -1</code></p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-rose-400 font-bold text-xs uppercase block">3. Collection: threat_detections</span>
              <p className="text-slate-400 text-[11px]">
                ML classifier outputs (Random Forest &amp; Isolation Forest) with confidence scores.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-rose-300">detectionId: 1</code> (unique)</p>
                <p>• <code className="text-rose-300">timestamp: -1, severity: 1</code></p>
                <p>• <code className="text-rose-300">detectionEngine: 1, confidence: -1</code></p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-orange-400 font-bold text-xs uppercase block">4. Collection: alerts</span>
              <p className="text-slate-400 text-[11px]">
                High-priority alert notifications with MITRE ATT&amp;CK mappings and evidence.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-orange-300">alertId: 1</code> (unique)</p>
                <p>• <code className="text-orange-300">status: 1, severity: 1</code></p>
                <p>• <code className="text-orange-300">incidentId: 1</code></p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-blue-400 font-bold text-xs uppercase block">5. Collection: agent_logs</span>
              <p className="text-slate-400 text-[11px]">
                Execution audit trails for Network, System, and Application domain agents.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-blue-300">agentId: 1, timestamp: -1</code> (compound)</p>
                <p>• <code className="text-blue-300">level: 1</code></p>
              </div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-purple-400 font-bold text-xs uppercase block">6. Collection: model_metadata</span>
              <p className="text-slate-400 text-[11px]">
                Machine learning model versions, accuracy, F1-scores, and hyperparameters.
              </p>
              <div className="p-2 bg-slate-900 rounded text-[10px] text-slate-300 font-mono">
                <p><span className="text-slate-500">Indexes:</span></p>
                <p>• <code className="text-purple-300">modelId: 1</code> (unique)</p>
                <p>• <code className="text-purple-300">status: 1, version: -1</code></p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: WINDOWS SETUP INSTRUCTIONS */}
      {activeSubTab === 'windows-setup' && (
        <div className="space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            MongoDB Windows Setup Guide &amp; Environment Configuration
          </h4>

          <div className="space-y-3 text-slate-300 text-[11px]">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-cyan-400 font-bold block text-xs">Step 1: Download &amp; Install MongoDB Community Edition</span>
              <p className="text-slate-400">
                1. Visit the official MongoDB Download Center: <span className="text-cyan-300 underline">https://www.mongodb.com/try/download/community</span>
              </p>
              <p className="text-slate-400">
                2. Select <strong>Windows (x64)</strong> and download the <code>.msi</code> installer package.
              </p>
              <p className="text-slate-400">
                3. Run the installer, choose <strong>&quot;Complete&quot;</strong> installation, and keep <strong>&quot;Install MongoDB as a Service&quot;</strong> checked.
              </p>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-cyan-400 font-bold block text-xs">Step 2: Verify Windows Service is Running</span>
              <p className="text-slate-400">
                Open PowerShell as Administrator and run:
              </p>
              <pre className="p-2 bg-slate-900 rounded text-emerald-400 font-mono text-[11px] overflow-x-auto">
{`# Check MongoDB Service status
Get-Service MongoDB

# If not running, start it:
Start-Service MongoDB`}
              </pre>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-cyan-400 font-bold block text-xs">Step 3: Configure Environment Variables</span>
              <p className="text-slate-400">
                Update your <code>.env</code> file in the project root:
              </p>
              <pre className="p-2 bg-slate-900 rounded text-cyan-300 font-mono text-[11px] overflow-x-auto">
{`# Local Windows MongoDB instance:
MONGODB_URI="mongodb://localhost:27017"
MONGODB_DB_NAME="cyber_threat_detection"

# Or MongoDB Atlas Cloud:
# MONGODB_URI="mongodb+srv://<username>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority"
# MONGODB_DB_NAME="cyber_threat_detection"`}
              </pre>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-cyan-400 font-bold block text-xs">Step 4: Verify Connection via mongosh or Compass</span>
              <p className="text-slate-400">
                Open MongoDB Compass or terminal <code>mongosh</code> and connect to <code>mongodb://localhost:27017</code>.
                The application will automatically initialize the database, create indexes, and sync events.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
