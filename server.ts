import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';

let pythonProcess: ChildProcess | null = null;

// Helper to spawn Python uvicorn backend if not already active
async function ensurePythonBackendRunning() {
  try {
    const res = await fetch(`${ML_SERVICE_URL}/api/health`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      console.log(`[Node Server] Python ML service is already running at ${ML_SERVICE_URL}`);
      return;
    }
  } catch {
    // Service not yet responsive; spawn uvicorn
  }

  const venvPython = path.join(process.cwd(), '.venv', 'bin', 'python');
  const pythonCmd = fs.existsSync(venvPython) ? venvPython : 'python3';

  console.log(`[Node Server] Spawning Python FastAPI ML service with ${pythonCmd}...`);
  try {
    pythonProcess = spawn(
      pythonCmd,
      ['-m', 'uvicorn', 'main:app', '--app-dir', 'backend', '--host', '127.0.0.1', '--port', '8000'],
      {
        cwd: process.cwd(),
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false
      }
    );

    pythonProcess.stdout?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.log(`[Python ML] ${msg}`);
    });

    pythonProcess.stderr?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.log(`[Python ML] ${msg}`);
    });

    pythonProcess.on('exit', (code) => {
      console.log(`[Node Server] Python ML process exited with code ${code}`);
      pythonProcess = null;
    });

    // Wait up to 5 seconds for it to become ready
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const ping = await fetch(`${ML_SERVICE_URL}/api/health`, { signal: AbortSignal.timeout(1000) });
        if (ping.ok) {
          console.log(`[Node Server] Python ML service successfully verified online at ${ML_SERVICE_URL}`);
          break;
        }
      } catch {
        // Retry
      }
    }
  } catch (err) {
    console.error('[Node Server] Failed to spawn Python ML service:', err);
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Kick off Python backend check in background
  ensurePythonBackendRunning().catch((err) => {
    console.warn('[Node Server] Background ML process error:', err);
  });

  // -------------------------------------------------------------
  // ML SERVICE HEALTH ENDPOINT
  // -------------------------------------------------------------
  const handleMlHealth = async (_req: express.Request, res: express.Response) => {
    try {
      const response = await fetch(`${ML_SERVICE_URL}/api/ml/health`, { signal: AbortSignal.timeout(3000) });
      const data = await response.json();
      return res.status(response.status).json(data);
    } catch {
      return res.status(200).json({
        status: 'not_ready',
        framework: 'scikit-learn',
        backendConfigured: false,
        scikitLearnAvailable: false,
        pandasAvailable: false,
        joblibAvailable: false,
        randomForest: { available: false, modelId: null, version: null },
        isolationForest: { available: false, modelId: null, version: null },
        message: `Python ML Service is unreachable at ${ML_SERVICE_URL}`
      });
    }
  };

  app.get('/api/ml/health', handleMlHealth);

  // -------------------------------------------------------------
  // ML MODELS REGISTRY ENDPOINTS
  // -------------------------------------------------------------
  const handleGetModels = async (_req: express.Request, res: express.Response) => {
    try {
      const response = await fetch(`${ML_SERVICE_URL}/api/ml/models`, { signal: AbortSignal.timeout(3000) });
      const data = await response.json();
      return res.status(response.status).json(data);
    } catch {
      return res.status(200).json([]);
    }
  };

  app.get('/api/ml/models', handleGetModels);
  app.get('/api/models', handleGetModels);

  // -------------------------------------------------------------
  // REAL ML PREDICTION ENDPOINTS
  // -------------------------------------------------------------
  const handlePredict = async (req: express.Request, res: express.Response) => {
    const { features, modelId, rawIdentifierMeta } = req.body || {};

    if (!features || typeof features !== 'object' || Array.isArray(features) || Object.keys(features).length === 0) {
      return res.status(400).json({
        error: "Invalid input: 'features' must be a non-empty object containing feature names and numerical/categorical values.",
        status: 'BAD_REQUEST'
      });
    }

    try {
      const response = await fetch(`${ML_SERVICE_URL}/api/ml/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ modelId, features, rawIdentifierMeta }),
        signal: AbortSignal.timeout(10000)
      });

      const data = await response.json();
      return res.status(response.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        status: 'MODEL_NOT_READY',
        code: 'MODEL_NOT_READY',
        error: `ML prediction service unavailable at ${ML_SERVICE_URL}: ${err.message || err}`,
        message: 'Real ML inference is unavailable. Please ensure Python ML backend and trained artifacts are ready.'
      });
    }
  };

  app.post('/api/ml/predict', handlePredict);
  app.post('/api/predict', handlePredict);

  // -------------------------------------------------------------
  // BATCH PREDICTION ENDPOINTS
  // -------------------------------------------------------------
  const handleBatchPredict = async (req: express.Request, res: express.Response) => {
    const { records, modelId } = req.body || {};

    if (!Array.isArray(records) || records.length === 0) {
      return res.status(400).json({
        error: "Invalid input: 'records' must be a non-empty array of feature objects.",
        status: 'BAD_REQUEST'
      });
    }

    if (records.length > 500) {
      return res.status(400).json({
        error: 'Batch limit exceeded: Maximum 500 records per request.',
        status: 'BAD_REQUEST'
      });
    }

    try {
      const response = await fetch(`${ML_SERVICE_URL}/api/ml/predict/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ modelId, records }),
        signal: AbortSignal.timeout(30000)
      });

      const data = await response.json();
      return res.status(response.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        status: 'MODEL_NOT_READY',
        code: 'MODEL_NOT_READY',
        error: `ML prediction service unavailable at ${ML_SERVICE_URL}: ${err.message || err}`,
        message: 'Real ML batch inference is unavailable.'
      });
    }
  };

  app.post('/api/ml/predict/batch', handleBatchPredict);
  app.post('/api/predict/batch', handleBatchPredict);

  // -------------------------------------------------------------
  // GENERAL BACKEND PROXY (HEALTH, STATUS, EVENTS, ALERTS, INCIDENTS)
  // -------------------------------------------------------------
  const forwardToPython = async (req: express.Request, res: express.Response, targetPath: string) => {
    try {
      const options: RequestInit = {
        method: req.method,
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000)
      };
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        options.body = JSON.stringify(req.body);
      }
      const response = await fetch(`${ML_SERVICE_URL}${targetPath}`, options);
      const data = await response.json();
      return res.status(response.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        status: 'SERVICE_UNAVAILABLE',
        error: `Failed to reach Python backend: ${err.message || err}`
      });
    }
  };

  app.get('/api/health', (req, res) => forwardToPython(req, res, '/api/health'));
  app.get('/api/status', (req, res) => forwardToPython(req, res, '/api/status'));
  app.all('/api/security-events*', (req, res) => forwardToPython(req, res, req.originalUrl));
  app.all('/api/alerts*', (req, res) => forwardToPython(req, res, req.originalUrl));
  app.all('/api/incidents*', (req, res) => forwardToPython(req, res, req.originalUrl));
  app.all('/api/pipeline*', (req, res) => forwardToPython(req, res, req.originalUrl));

  // -------------------------------------------------------------
  // VITE MIDDLEWARE / STATIC ASSETS
  // -------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Node Server] Running on http://0.0.0.0:${PORT}`);
  });
}

// Clean shutdown handler
process.on('SIGINT', () => {
  if (pythonProcess) {
    pythonProcess.kill();
  }
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (pythonProcess) {
    pythonProcess.kill();
  }
  process.exit(0);
});

startServer();
