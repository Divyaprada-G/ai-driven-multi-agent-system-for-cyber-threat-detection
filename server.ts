import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { databaseService } from './src/db/databaseService.ts';
import { localStore } from './src/db/localStore.ts';

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

  const venvPythonBin = path.join(process.cwd(), '.venv', 'bin', 'python');
  const venvPythonWin = path.join(process.cwd(), '.venv', 'Scripts', 'python.exe');
  let pythonCmd = 'python';
  if (fs.existsSync(venvPythonWin)) {
    pythonCmd = venvPythonWin;
  } else if (fs.existsSync(venvPythonBin)) {
    pythonCmd = venvPythonBin;
  }

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
  app.use(express.json({ limit: '15mb' }));
  app.use(express.text({ limit: '15mb' }));
  app.use(express.urlencoded({ extended: true, limit: '15mb' }));

  // Kick off Python backend check in background
  ensurePythonBackendRunning().catch((err) => {
    console.warn('[Node Server] Background ML process error:', err);
  });

  // -------------------------------------------------------------
  // UNIFIED HEALTH CHECK ENDPOINT
  // -------------------------------------------------------------
  app.get('/api/health', async (_req, res) => {
    const dbHealth = await databaseService.checkConnection();
    let pyOnline = false;
    let pyDetails: any = null;
    try {
      const pyResp = await fetch(`${ML_SERVICE_URL}/api/health`, { signal: AbortSignal.timeout(1500) });
      if (pyResp.ok) {
        pyOnline = true;
        pyDetails = await pyResp.json();
      }
    } catch {
      pyOnline = false;
    }

    const isHealthy = pyOnline || dbHealth.connected;
    return res.status(isHealthy ? 200 : 503).json({
      status: isHealthy ? 'ONLINE' : 'DEGRADED',
      service: 'Cyber Threat Detection Platform',
      timestamp: new Date().toISOString(),
      nodeServer: 'ONLINE',
      pythonMLBackend: pyOnline ? 'ONLINE' : 'OFFLINE',
      database: dbHealth.status,
      databaseMode: (dbHealth as any).mode || (dbHealth.connected ? 'PostgreSQL' : 'JSON_STORE'),
      details: {
        python: pyDetails,
        db: dbHealth
      }
    });
  });

  // -------------------------------------------------------------
  // CORE LOG ANALYSIS ENDPOINT: POST /api/analyze
  // -------------------------------------------------------------
  app.post('/api/analyze', async (req, res) => {
    const { log_text, logs, raw_text, source_type, scenario, filename } = req.body || {};
    const textToAnalyze = log_text || logs || raw_text || '';

    try {
      const pyResp = await fetch(`${ML_SERVICE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          log_text: textToAnalyze,
          source_type: source_type || 'auto',
          scenario,
          filename
        }),
        signal: AbortSignal.timeout(30000)
      });

      if (!pyResp.ok) {
        const errData = await pyResp.json().catch(() => ({ detail: 'Analysis failed on backend' }));
        return res.status(pyResp.status).json(errData);
      }

      const result = await pyResp.json();

      // Automatically persist threat incidents and alerts
      if (result.threat_detected && result.incident) {
        try {
          const inc = result.incident;
          await databaseService.insertIncident({
            incidentId: inc.id || `INC-${Date.now()}`,
            title: inc.title || 'Multi-Agent Security Incident',
            description: inc.description || 'Threat detected during log analysis',
            severity: inc.severity || 'HIGH',
            priority: inc.priority || 'P1',
            status: 'NEW',
            riskScore: result.risk_assessment?.risk_score || 75,
            primaryIp: inc.primary_ip || (result.findings && result.findings[0]?.indicators?.find((i: string) => i.includes('.'))) || '192.168.1.100',
            affectedHost: inc.affected_host || 'server01',
            mitreTechniques: inc.mitre_techniques || [],
            investigationNotes: [
              {
                id: `note-${Date.now()}`,
                author: 'Multi-Agent Security Engine',
                note: `Auto-generated incident. Agents involved: ${(result.agents_used || []).join(', ')}. Risk Score: ${result.risk_assessment?.risk_score || 0}.`,
                timestamp: new Date().toISOString()
              }
            ]
          });

          // Also insert alerts
          if (Array.isArray(result.findings)) {
            for (const finding of result.findings) {
              await databaseService.insertAlert({
                title: `[${finding.agent || 'Agent'}] ${finding.threat_type}`,
                description: finding.description || 'Security threat detected',
                alertType: finding.threat_type || 'Security Alert',
                severity: finding.severity || 'MEDIUM',
                riskScore: Math.round((finding.confidence || 0.8) * 100),
                priority: finding.severity === 'CRITICAL' ? 'P1' : finding.severity === 'HIGH' ? 'P2' : 'P3',
                mitreTechniques: finding.mitre_technique ? [finding.mitre_technique] : [],
                evidence: finding.evidence || []
              });
            }
          }
        } catch (dbErr) {
          console.warn('[Node Server] Non-fatal incident persistence warning:', dbErr);
        }
      }

      return res.status(200).json(result);
    } catch (err: any) {
      console.error('[Node Server] /api/analyze error:', err);
      return res.status(503).json({
        status: 'BACKEND_UNAVAILABLE',
        error: `Python backend unreachable at ${ML_SERVICE_URL}: ${err.message || err}`,
        message: 'Could not connect to Python analysis engine. Ensure Python FastAPI is running.'
      });
    }
  });

  // -------------------------------------------------------------
  // LOG UPLOAD ENDPOINT: POST /api/logs/upload
  // -------------------------------------------------------------
  app.post('/api/logs/upload', async (req, res) => {
    let logText = '';
    let filename = 'uploaded_log.txt';
    let sourceType = 'auto';

    if (typeof req.body === 'string') {
      logText = req.body;
    } else if (req.body && typeof req.body === 'object') {
      logText = req.body.log_text || req.body.content || req.body.logs || req.body.raw_text || '';
      filename = req.body.filename || filename;
      sourceType = req.body.source_type || sourceType;
    }

    if (!logText.trim()) {
      return res.status(400).json({ error: 'No log content received in upload request' });
    }

    try {
      const pyResp = await fetch(`${ML_SERVICE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          log_text: logText,
          source_type: sourceType,
          filename
        }),
        signal: AbortSignal.timeout(30000)
      });

      if (!pyResp.ok) {
        const err = await pyResp.json().catch(() => ({ detail: 'Upload analysis failed' }));
        return res.status(pyResp.status).json(err);
      }

      const result = await pyResp.json();
      result.filename = filename;

      // Persist threat incident if detected
      if (result.threat_detected && result.incident) {
        try {
          await databaseService.insertIncident({
            incidentId: result.incident.id || `INC-${Date.now()}`,
            title: result.incident.title || `Threats in ${filename}`,
            description: result.incident.description || `Detected from uploaded file: ${filename}`,
            severity: result.incident.severity || 'HIGH',
            priority: result.incident.priority || 'P1',
            status: 'NEW',
            riskScore: result.risk_assessment?.risk_score || 75,
            primaryIp: result.incident.primary_ip || '192.168.1.100',
            affectedHost: result.incident.affected_host || 'server01',
            mitreTechniques: result.incident.mitre_techniques || []
          });
        } catch (e) {
          console.warn('[Node Server] Upload incident persistence warning:', e);
        }
      }

      return res.status(200).json(result);
    } catch (err: any) {
      return res.status(503).json({
        status: 'BACKEND_UNAVAILABLE',
        error: `Python backend unreachable: ${err.message || err}`
      });
    }
  });

  // -------------------------------------------------------------
  // DASHBOARD AGGREGATED STATS: GET /api/dashboard/stats
  // -------------------------------------------------------------
  app.get('/api/dashboard/stats', async (_req, res) => {
    try {
      let pyStats: any = null;
      try {
        const resp = await fetch(`${ML_SERVICE_URL}/api/dashboard/stats`, { signal: AbortSignal.timeout(1500) });
        if (resp.ok) pyStats = await resp.json();
      } catch {
        // Python temporarily offline, continue with local stats
      }

      const localStats = localStore.getStats();

      const merged = {
        status: 'ok',
        totalEvents: Math.max(localStats.totalEvents, pyStats?.totalEvents || 0),
        threatsDetected: Math.max(localStats.threatsDetected, pyStats?.threatsDetected || 0),
        criticalThreats: Math.max(localStats.criticalThreats, pyStats?.criticalThreats || 0),
        highThreats: Math.max(localStats.highThreats, pyStats?.highThreats || 0),
        mediumThreats: Math.max(localStats.mediumThreats, pyStats?.mediumThreats || 0),
        lowThreats: Math.max(localStats.lowThreats, pyStats?.lowThreats || 0),
        activeIncidents: Math.max(localStats.activeIncidents, pyStats?.activeIncidents || 0),
        totalAlerts: localStats.totalAlerts,
        pipelineStatus: pyStats?.pipelineStatus || 'READY',
        activeModel: pyStats?.activeModel || 'Multi-Agent Rule Engine + ML',
        modelStatus: pyStats?.modelStatus || 'READY',
        timestamp: new Date().toISOString()
      };

      return res.status(200).json(merged);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // -------------------------------------------------------------
  // DEMO SCENARIOS & EXECUTION
  // -------------------------------------------------------------
  app.get('/api/demo/scenarios', async (_req, res) => {
    try {
      const resp = await fetch(`${ML_SERVICE_URL}/api/demo/scenarios`, { signal: AbortSignal.timeout(1500) });
      if (resp.ok) {
        return res.status(200).json(await resp.json());
      }
    } catch {
      // Fallback scenarios list
    }
    return res.status(200).json([
      { id: 'mixed_attack', name: 'Mixed Multi-Agent Attack', source: 'auto', description: 'Network scan + brute force + web attack chain' },
      { id: 'network_port_scan', name: 'Network Port Scan', source: 'network', description: 'Port scanning from single IP' },
      { id: 'system_brute_force', name: 'System Brute Force', source: 'system', description: 'SSH brute force + privilege escalation' },
      { id: 'application_sql_injection', name: 'Application SQL Injection', source: 'application', description: 'SQL injection and XSS attempts' },
      { id: 'normal_traffic', name: 'Normal Benign Traffic', source: 'auto', description: 'Normal operations with zero false alerts' }
    ]);
  });

  app.post('/api/demo', async (req, res) => {
    const { scenario } = req.body || {};
    try {
      const pyResp = await fetch(`${ML_SERVICE_URL}/api/demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenario || 'mixed_attack' }),
        signal: AbortSignal.timeout(30000)
      });
      if (!pyResp.ok) {
        return res.status(pyResp.status).json(await pyResp.json());
      }
      const result = await pyResp.json();

      if (result.threat_detected && result.incident) {
        try {
          await databaseService.insertIncident({
            incidentId: result.incident.id || `INC-${Date.now()}`,
            title: result.incident.title || 'Demo Threat Incident',
            description: result.incident.description || 'Generated from demo attack scenario',
            severity: result.incident.severity || 'HIGH',
            priority: result.incident.priority || 'P1',
            status: 'NEW',
            riskScore: result.risk_assessment?.risk_score || 85,
            primaryIp: result.incident.primary_ip || '203.0.113.50',
            affectedHost: 'server01',
            mitreTechniques: result.incident.mitre_techniques || []
          });
        } catch (e) {
          console.warn('[Node Server] Demo incident persistence warning:', e);
        }
      }

      return res.status(200).json(result);
    } catch (err: any) {
      return res.status(503).json({ error: 'Demo execution failed: ' + err.message });
    }
  });

  // -------------------------------------------------------------
  // DATABASE HEALTH & STATUS (Task 13: DATABASE_CONNECTED vs DATABASE_UNAVAILABLE)
  // -------------------------------------------------------------
  app.get('/api/db/health', async (_req, res) => {
    const health = await databaseService.checkConnection();
    if (health.connected) {
      return res.status(200).json({
        status: 'DATABASE_CONNECTED',
        database: 'PostgreSQL',
        timestamp: new Date().toISOString()
      });
    } else {
      return res.status(503).json({
        status: 'DATABASE_UNAVAILABLE',
        database: 'PostgreSQL',
        error: health.details || 'Unable to connect to PostgreSQL',
        timestamp: new Date().toISOString()
      });
    }
  });

  // -------------------------------------------------------------
  // TASK 11: EVENTS APIS
  // POST /api/events
  // GET /api/events
  // GET /api/events/:id
  // -------------------------------------------------------------
  app.post('/api/events', async (req, res) => {
    const { source, eventType, rawPayload, normalizedFields, eventTimestamp, sourceIp, destinationIp, host, username, severity, batchId, isTestEvent } = req.body || {};

    if (!source || !eventType || rawPayload === undefined) {
      return res.status(400).json({
        error: "Missing required event fields: 'source', 'eventType', and 'rawPayload' are required."
      });
    }

    try {
      const result = await databaseService.insertRawEvent({
        source,
        eventType,
        rawPayload: typeof rawPayload === 'string' ? rawPayload : JSON.stringify(rawPayload),
        normalizedFields: normalizedFields || {},
        eventTimestamp,
        sourceIp,
        destinationIp,
        host,
        username,
        severity,
        batchId,
        isTestEvent
      });

      return res.status(result.isDuplicate ? 200 : 201).json({
        success: true,
        isDuplicate: result.isDuplicate,
        event: result.event
      });
    } catch (err: any) {
      console.error('[API] POST /api/events error:', err);
      return res.status(500).json({ error: err.message || 'Failed saving event to database' });
    }
  });

  app.get('/api/events', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;
    try {
      const events = await databaseService.getEvents(limit, offset);
      return res.json(events);
    } catch (err: any) {
      console.error('[API] GET /api/events error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving events from database' });
    }
  });

  app.get('/api/events/:id', async (req, res) => {
    try {
      const event = await databaseService.getEventById(req.params.id);
      if (!event) {
        return res.status(404).json({ error: `Event '${req.params.id}' not found` });
      }
      return res.json(event);
    } catch (err: any) {
      console.error('[API] GET /api/events/:id error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving event' });
    }
  });

  // -------------------------------------------------------------
  // TASK 5: AGENT FINDINGS PERSISTENCE
  // POST /api/findings
  // -------------------------------------------------------------
  app.post('/api/findings', async (req, res) => {
    const { eventId, agentType, threatType, severity, confidence, evidence, indicators, mitreTechnique, mitreTactic, timestamp, metadata } = req.body || {};

    if (!eventId || !agentType || !threatType || severity === undefined || confidence === undefined) {
      return res.status(400).json({
        error: "Missing required finding fields: 'eventId', 'agentType', 'threatType', 'severity', and 'confidence' are required."
      });
    }

    try {
      const finding = await databaseService.insertFinding({
        eventId,
        agentType,
        threatType,
        severity,
        confidence,
        evidence: evidence || [],
        indicators: indicators || [],
        mitreTechnique,
        mitreTactic,
        timestamp,
        metadata
      });
      return res.status(201).json(finding);
    } catch (err: any) {
      console.error('[API] POST /api/findings error:', err);
      return res.status(500).json({ error: err.message || 'Failed saving security finding' });
    }
  });

  // -------------------------------------------------------------
  // TASK 4 & 11: ML DETECTIONS APIS
  // POST /api/detections
  // GET /api/detections
  // -------------------------------------------------------------
  app.post('/api/detections', async (req, res) => {
    const {
      eventId,
      modelId,
      modelVersion,
      featureSchemaVersion,
      prediction,
      predictedClass,
      confidence,
      classProbabilities,
      anomalyScore,
      anomalyFlag,
      anomalyLabel,
      featureSummary,
      importantContributingFeatures,
      inferenceTimestamp
    } = req.body || {};

    if (!eventId || !modelId || !modelVersion || !prediction || !predictedClass || confidence === undefined || !classProbabilities) {
      return res.status(400).json({
        error: "Missing required detection fields: eventId, modelId, modelVersion, prediction, predictedClass, confidence, classProbabilities."
      });
    }

    try {
      const detection = await databaseService.insertDetection({
        eventId,
        modelId,
        modelVersion,
        featureSchemaVersion,
        prediction,
        predictedClass,
        confidence,
        classProbabilities,
        anomalyScore,
        anomalyFlag,
        anomalyLabel,
        featureSummary,
        importantContributingFeatures,
        inferenceTimestamp
      });
      return res.status(201).json(detection);
    } catch (err: any) {
      console.error('[API] POST /api/detections error:', err);
      return res.status(500).json({ error: err.message || 'Failed saving detection' });
    }
  });

  app.get('/api/detections', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;
    try {
      const dets = await databaseService.getDetections(limit, offset);
      return res.json(dets);
    } catch (err: any) {
      console.error('[API] GET /api/detections error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving detections' });
    }
  });

  // -------------------------------------------------------------
  // TASK 6 & 7: CORRELATIONS & RISK ASSESSMENTS
  // POST /api/correlations
  // POST /api/risk-assessments
  // -------------------------------------------------------------
  app.post('/api/correlations', async (req, res) => {
    try {
      const corr = await databaseService.insertCorrelation(req.body);
      return res.status(201).json(corr);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed saving correlation' });
    }
  });

  app.post('/api/risk-assessments', async (req, res) => {
    try {
      const risk = await databaseService.insertRiskAssessment(req.body);
      return res.status(201).json(risk);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed saving risk assessment' });
    }
  });

  // -------------------------------------------------------------
  // TASK 8 & 11: ALERTS APIS
  // GET /api/alerts
  // POST /api/alerts
  // PATCH /api/alerts/:id
  // -------------------------------------------------------------
  app.get('/api/alerts', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;
    try {
      const alertList = await databaseService.getAlerts(limit, offset);
      return res.json(alertList);
    } catch (err: any) {
      console.error('[API] GET /api/alerts error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving alerts' });
    }
  });

  app.post('/api/alerts', async (req, res) => {
    try {
      const created = await databaseService.insertAlert(req.body);
      return res.status(201).json(created);
    } catch (err: any) {
      console.error('[API] POST /api/alerts error:', err);
      return res.status(500).json({ error: err.message || 'Failed creating alert' });
    }
  });

  app.get('/api/alerts/:id', async (req, res) => {
    try {
      const alert = await databaseService.getAlertById(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: `Alert '${req.params.id}' not found` });
      }
      return res.json(alert);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed retrieving alert' });
    }
  });

  app.patch('/api/alerts/:id', async (req, res) => {
    const { status, actor, reason } = req.body || {};
    if (!status) {
      return res.status(400).json({ error: "Missing required 'status' field." });
    }

    const validStatuses = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'SUPPRESSED'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status '${status}'. Must be one of ${validStatuses.join(', ')}.` });
    }

    try {
      const updated = await databaseService.updateAlertStatus(req.params.id, status, actor, reason);
      if (!updated) {
        return res.status(404).json({ error: `Alert '${req.params.id}' not found` });
      }
      return res.json(updated);
    } catch (err: any) {
      console.error('[API] PATCH /api/alerts/:id error:', err);
      return res.status(500).json({ error: err.message || 'Failed updating alert' });
    }
  });

  // -------------------------------------------------------------
  // TASK 9 & 11: INCIDENTS APIS
  // GET /api/incidents
  // POST /api/incidents
  // GET /api/incidents/:id
  // PATCH /api/incidents/:id
  // -------------------------------------------------------------
  app.get('/api/incidents', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;
    try {
      const incs = await databaseService.getIncidents(limit, offset);
      return res.json(incs);
    } catch (err: any) {
      console.error('[API] GET /api/incidents error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving incidents' });
    }
  });

  app.post('/api/incidents', async (req, res) => {
    try {
      const inc = await databaseService.insertIncident(req.body);
      return res.status(201).json(inc);
    } catch (err: any) {
      console.error('[API] POST /api/incidents error:', err);
      return res.status(500).json({ error: err.message || 'Failed creating incident' });
    }
  });

  app.get('/api/incidents/:id', async (req, res) => {
    try {
      const inc = await databaseService.getIncidentById(req.params.id);
      if (!inc) {
        return res.status(404).json({ error: `Incident '${req.params.id}' not found` });
      }
      const history = await databaseService.getIncidentHistory(req.params.id);
      return res.json({ ...inc, history });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed retrieving incident' });
    }
  });

  app.patch('/api/incidents/:id', async (req, res) => {
    const { status, assignee, priority, containmentStatus, resolutionSummary, newNote, actor, reason } = req.body || {};

    if (status) {
      const validStatuses = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: `Invalid status '${status}'. Must be one of ${validStatuses.join(', ')}.` });
      }
    }

    try {
      const updated = await databaseService.updateIncident(req.params.id, {
        status,
        assignee,
        priority,
        containmentStatus,
        resolutionSummary,
        newNote,
        actor,
        reason
      });

      if (!updated) {
        return res.status(404).json({ error: `Incident '${req.params.id}' not found` });
      }
      return res.json(updated);
    } catch (err: any) {
      console.error('[API] PATCH /api/incidents/:id error:', err);
      return res.status(500).json({ error: err.message || 'Failed updating incident' });
    }
  });

  // -------------------------------------------------------------
  // TASK 11: AUDIT APIS
  // GET /api/audit
  // -------------------------------------------------------------
  app.get('/api/audit', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
    const offset = parseInt(req.query.offset as string) || 0;
    try {
      const logs = await databaseService.getAuditLogs(limit, offset);
      return res.json(logs);
    } catch (err: any) {
      console.error('[API] GET /api/audit error:', err);
      return res.status(500).json({ error: err.message || 'Failed retrieving audit logs' });
    }
  });

  // -------------------------------------------------------------
  // TASK 10: REPORTS METADATA APIS
  // POST /api/reports
  // GET /api/reports
  // -------------------------------------------------------------
  app.post('/api/reports', async (req, res) => {
    try {
      const rep = await databaseService.insertReport(req.body);
      return res.status(201).json(rep);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed creating report record' });
    }
  });

  app.get('/api/reports', async (_req, res) => {
    try {
      const reps = await databaseService.getReports();
      return res.json(reps);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Failed retrieving reports' });
    }
  });

  // -------------------------------------------------------------
  // ML SERVICE PROXIES & INFERENCE
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

  const handleGetModels = async (_req: express.Request, res: express.Response) => {
    try {
      const response = await fetch(`${ML_SERVICE_URL}/api/ml/models`, { signal: AbortSignal.timeout(3000) });
      const data = await response.json();

      // Mirror models into PostgreSQL model_registry
      if (Array.isArray(data)) {
        for (const m of data) {
          databaseService.upsertModelRegistry({
            id: m.model_id,
            modelType: m.algorithm === 'RandomForestClassifier' ? 'RANDOM_FOREST' : 'ISOLATION_FOREST',
            modelVersion: m.model_version,
            featureSchemaVersion: m.feature_schema_version || 'cicids2017-v1',
            algorithm: m.algorithm,
            trainingDataset: m.training_dataset,
            trainingTimestamp: m.training_timestamp,
            trainingMetrics: m.training_metrics,
            featureNames: m.features,
            classes: m.classes,
            status: m.status
          }).catch((err) => console.warn('[ModelSync] Error syncing model to DB:', err));
        }
      }
      return res.status(response.status).json(data);
    } catch {
      // Fallback to PostgreSQL registry
      try {
        const stored = await databaseService.getRegisteredModels();
        return res.json(stored);
      } catch {
        return res.status(200).json([]);
      }
    }
  };

  app.get('/api/ml/models', handleGetModels);
  app.get('/api/models', handleGetModels);

  // REAL ML PREDICTION with automatic DATABASE PERSISTENCE (Task 4)
  const handlePredict = async (req: express.Request, res: express.Response) => {
    const { features, modelId, rawIdentifierMeta, eventId } = req.body || {};

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

      // If successful inference and eventId provided, persist detection in PostgreSQL
      if (response.ok && data.status === 'SUCCESS' && eventId) {
        databaseService.insertDetection({
          eventId,
          modelId: data.modelId,
          modelVersion: data.modelVersion,
          featureSchemaVersion: data.featureSchemaVersion || 'cicids2017-v1',
          prediction: data.prediction,
          predictedClass: data.predictedClass,
          confidence: data.confidence,
          classProbabilities: data.classProbabilities || {},
          anomalyScore: data.anomalyScore,
          anomalyFlag: data.anomalyFlag,
          anomalyLabel: data.anomalyLabel,
          featureSummary: data.featureSummary,
          importantContributingFeatures: data.importantContributingFeatures,
          inferenceTimestamp: data.inferenceTimestamp
        }).catch((err) => console.error('[DetectionSync] Failed saving ML detection to DB:', err));
      }

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
        error: `ML prediction service unavailable at ${ML_SERVICE_URL}: ${err.message || err}`
      });
    }
  };

  app.post('/api/ml/predict/batch', handleBatchPredict);
  app.post('/api/predict/batch', handleBatchPredict);

  // General Python status endpoints
  app.get('/api/ml/model-status', async (_req, res) => {
    try {
      const resp = await fetch(`${ML_SERVICE_URL}/api/ml/model-status`, { signal: AbortSignal.timeout(2000) });
      const data = await resp.json();
      return res.status(resp.status).json(data);
    } catch {
      return res.status(503).json({ status: 'SERVICE_UNAVAILABLE' });
    }
  });

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

process.on('SIGINT', () => {
  if (pythonProcess) pythonProcess.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (pythonProcess) pythonProcess.kill();
  process.exit(0);
});

startServer();
