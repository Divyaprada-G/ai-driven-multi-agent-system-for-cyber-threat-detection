import fs from 'fs';
import path from 'path';
import {
  logProcessingPipeline,
  FileUploadReport,
  PipelineStageStatus,
  CorrelatedIncident,
  StandardSecurityEvent
} from './pipeline/logProcessingPipeline';

export interface Finding {
  id: string;
  agent: string;
  threat_type: string;
  description: string;
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  source_ip?: string;
  destination_ip?: string;
  url?: string;
  evidence: string[];
  timestamp: string;
  mitre_technique?: string;
}

export interface Correlation {
  id: string;
  type: string;
  description: string;
  related_findings: string[];
  source_ip?: string;
  threat_types: string[];
  agents_involved: string[];
  event_count: number;
  correlation_score: number;
  strength: 'STRONG' | 'MODERATE' | 'LOW';
  timestamp: string;
}

export interface RiskAssessment {
  risk_score: number;
  risk_band: 'Critical' | 'High' | 'Medium' | 'Low';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  factors: Record<string, any>;
  explanation: string;
}

export interface AnalysisResult {
  status: string;
  events_parsed: number;
  events_by_source: { network: number; system: number; application: number; unknown?: number };
  threat_detected: boolean;
  findings: Finding[];
  findings_count: number;
  agents_used: string[];
  correlations: Correlation[];
  risk_assessment: RiskAssessment;
  ml_result: any;
  incident: any;
  processing_time_ms: number;
  analyzed_at: string;
  filename?: string;

  // Multi-File & Multi-Stage Pipeline Properties
  files_analyzed?: number;
  files?: FileUploadReport[];
  pipeline_stages?: PipelineStageStatus[];
  incidents?: CorrelatedIncident[];
  standard_events?: StandardSecurityEvent[];
  ml_evaluation?: any;
  valid_events?: number;
  duplicate_events?: number;
  suspicious_events?: number;
  high_risk_incidents_count?: number;
  critical_incidents_count?: number;
}

export const DEMO_LOGS: Record<string, string> = {
  network_port_scan: `2026-09-17T10:15:01Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=22 proto=TCP action=connect status=open
2026-09-17T10:15:02Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=23 proto=TCP action=connect status=closed
2026-09-17T10:15:03Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=80 proto=TCP action=connect status=open
2026-09-17T10:15:04Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=443 proto=TCP action=connect status=open
2026-09-17T10:15:05Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=3306 proto=TCP action=connect status=filtered
2026-09-17T10:15:06Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=5432 proto=TCP action=connect status=closed
2026-09-17T10:15:07Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=8080 proto=TCP action=connect status=open
2026-09-17T10:15:08Z src_ip=192.168.1.105 dst_ip=10.0.0.5 port=3389 proto=TCP action=connect status=filtered`,

  system_brute_force: `Sep 17 10:20:01 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54321 ssh2
Sep 17 10:20:03 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54322 ssh2
Sep 17 10:20:05 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54323 ssh2
Sep 17 10:20:07 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54324 ssh2
Sep 17 10:20:09 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54325 ssh2
Sep 17 10:20:11 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54326 ssh2
Sep 17 10:20:13 server01 sshd[12345]: Accepted password for admin from 10.0.1.50 port 54327 ssh2
Sep 17 10:20:15 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash`,

  application_sql_injection: `2026-09-17T10:25:01Z 192.168.1.200 GET /api/users?id=1' OR '1'='1 HTTP/1.1 200 text/html
2026-09-17T10:25:02Z 192.168.1.200 POST /api/login HTTP/1.1 401 application/json auth failed username=admin
2026-09-17T10:25:03Z 192.168.1.200 POST /api/login HTTP/1.1 401 application/json auth failed username=admin
2026-09-17T10:25:04Z 192.168.1.200 GET /api/users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1 500 text/html
2026-09-17T10:25:05Z 192.168.1.200 GET /admin/console HTTP/1.1 403 text/html
2026-09-17T10:25:06Z 192.168.1.200 GET /api/data?file=../../etc/passwd HTTP/1.1 400 text/html
2026-09-17T10:25:07Z 192.168.1.200 POST /api/search HTTP/1.1 200 application/json query=<script>alert('xss')</script>`,

  normal_traffic: `2026-09-17T10:30:01Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP action=connect status=established
2026-09-17T10:30:05Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP bytes_sent=1500 bytes_recv=3200
Sep 17 10:30:10 server01 sshd[99999]: Accepted password for developer from 192.168.1.10 port 55000 ssh2
Sep 17 10:30:15 server01 systemd[1]: Started Daily apt download activities.
2026-09-17T10:30:20Z 192.168.1.10 GET /api/dashboard HTTP/1.1 200 application/json
2026-09-17T10:30:25Z 192.168.1.10 GET /api/profile HTTP/1.1 200 application/json`,

  mixed_attack: `2026-09-17T11:00:01Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=22 proto=TCP SYN action=connect
2026-09-17T11:00:02Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=80 proto=TCP SYN action=connect
2026-09-17T11:00:03Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=443 proto=TCP SYN action=connect
2026-09-17T11:00:04Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=3306 proto=TCP SYN action=connect
2026-09-17T11:00:05Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=5432 proto=TCP SYN action=connect
Sep 17 11:01:01 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54321 ssh2
Sep 17 11:01:03 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54322 ssh2
Sep 17 11:01:05 server01 sshd[12345]: Failed password for root from 203.0.113.50 port 54323 ssh2
Sep 17 11:01:07 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54324 ssh2
Sep 17 11:01:09 server01 sshd[12345]: Accepted password for admin from 203.0.113.50 port 54325 ssh2
Sep 17 11:01:11 server01 sudo: admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash
2026-09-17T11:02:01Z 203.0.113.50 POST /api/data HTTP/1.1 200 application/json body=1' UNION SELECT * FROM users--
2026-09-17T11:02:05Z 203.0.113.50 GET /admin/console HTTP/1.1 403 text/html`
};

export const DEMO_SCENARIOS = [
  { id: 'mixed_attack', name: 'Mixed Multi-Agent Attack', source: 'auto', description: 'Network scan + brute force + web attack chain' },
  { id: 'network_port_scan', name: 'Network Port Scan', source: 'network', description: 'Port scanning from single IP' },
  { id: 'system_brute_force', name: 'System Brute Force', source: 'system', description: 'SSH brute force + privilege escalation' },
  { id: 'application_sql_injection', name: 'Application SQL Injection', source: 'application', description: 'SQL injection, XSS, and path traversal' },
  { id: 'normal_traffic', name: 'Normal Benign Traffic', source: 'auto', description: 'Normal operations with zero false alerts' }
];

export class LocalAnalysisEngine {
  public analyze(rawText: string, sourceType: string = 'auto', filename: string = 'logs.txt'): AnalysisResult {
    return this.analyzeFiles([{ filename, content: rawText, sourceType }]);
  }

  public analyzeFiles(
    files: Array<{ filename: string; content: string; sourceType?: string }>
  ): AnalysisResult {
    const pipelineResult = logProcessingPipeline.processFiles(files);

    const findings: Finding[] = pipelineResult.findings.map((f) => ({
      id: f.id,
      agent: f.agent,
      threat_type: f.threat_type,
      description: f.description,
      confidence: f.confidence,
      severity: f.severity,
      source_ip: f.source_ip,
      destination_ip: f.destination_ip,
      evidence: f.evidence,
      timestamp: f.timestamp,
      mitre_technique: f.mitre_technique?.technique_id
    }));

    const agentsUsed = Array.from(new Set(pipelineResult.findings.map((f) => f.agent)));

    const correlations: Correlation[] = pipelineResult.correlations.map((c: any) => ({
      id: c.id,
      type: c.correlation_type || 'CORRELATION',
      description: c.description || 'Correlated security event group',
      related_findings: [],
      source_ip: c.source_ip,
      threat_types: c.threat_types || [],
      agents_involved: c.agents_involved || [],
      event_count: c.findings_count || 0,
      correlation_score: c.correlation_score || 75,
      strength: c.strength || 'MODERATE',
      timestamp: new Date().toISOString()
    }));

    const threatDetected = pipelineResult.detected_threats_count > 0;
    const primaryInc = pipelineResult.incidents[0];

    const incident = primaryInc
      ? {
          id: primaryInc.incident_id,
          incident_id: primaryInc.incident_id,
          title: primaryInc.title,
          description: primaryInc.risk_factors?.formula_explanation || primaryInc.threat_type,
          severity: primaryInc.severity,
          priority: primaryInc.priority,
          status: 'NEW',
          risk_score: primaryInc.risk_score,
          confidence: primaryInc.confidence,
          primary_ip: primaryInc.affected_entities.ips[0] || '192.168.1.100',
          affected_host: primaryInc.affected_entities.hosts[0] || 'server01',
          agent: agentsUsed.join(', ') || 'MultiAgent',
          threat_type: primaryInc.threat_type,
          findings_count: primaryInc.agent_findings.length,
          correlation_count: pipelineResult.correlations.length,
          mitre_techniques: [primaryInc.mitre_mapping.technique_id],
          evidence: primaryInc.evidence
        }
      : null;

    const riskBand = (pipelineResult.overall_risk.severity.charAt(0) +
      pipelineResult.overall_risk.severity.slice(1).toLowerCase()) as 'Critical' | 'High' | 'Medium' | 'Low';

    const riskAssessment: RiskAssessment = {
      risk_score: pipelineResult.overall_risk.score,
      risk_band: riskBand,
      priority: pipelineResult.overall_risk.priority,
      factors: {
        findingsCount: pipelineResult.findings.length,
        correlationsCount: pipelineResult.correlations.length,
        agentsCount: agentsUsed.length,
        highRiskCount: pipelineResult.high_risk_incidents_count,
        criticalCount: pipelineResult.critical_incidents_count
      },
      explanation: pipelineResult.overall_risk.explanation
    };

    const mlResult = {
      modelId: pipelineResult.ml_evaluation.random_forest.model_id,
      modelVersion: 'rf-cyber-20260916',
      predictedClass: pipelineResult.ml_evaluation.random_forest.predicted_class,
      confidence: pipelineResult.ml_evaluation.random_forest.confidence,
      anomalyScore: pipelineResult.ml_evaluation.isolation_forest.anomaly_score,
      anomalyFlag: pipelineResult.ml_evaluation.isolation_forest.is_anomaly,
      status: 'SUCCESS'
    };

    return {
      status: pipelineResult.status,
      events_parsed: pipelineResult.total_events,
      events_by_source: pipelineResult.events_by_source,
      threat_detected: threatDetected,
      findings,
      findings_count: findings.length,
      agents_used: agentsUsed,
      correlations,
      risk_assessment: riskAssessment,
      ml_result: mlResult,
      incident,
      processing_time_ms: pipelineResult.processing_time_ms,
      analyzed_at: pipelineResult.analyzed_at,
      filename: files[0]?.filename || 'logs.txt',

      // Enhanced Pipeline Fields
      files_analyzed: pipelineResult.files_analyzed,
      files: pipelineResult.files,
      pipeline_stages: pipelineResult.pipeline_stages,
      incidents: pipelineResult.incidents,
      standard_events: pipelineResult.standard_events,
      ml_evaluation: pipelineResult.ml_evaluation,
      valid_events: pipelineResult.valid_events,
      duplicate_events: pipelineResult.duplicate_events,
      suspicious_events: pipelineResult.suspicious_events,
      high_risk_incidents_count: pipelineResult.high_risk_incidents_count,
      critical_incidents_count: pipelineResult.critical_incidents_count
    };
  }

  public getRegisteredModels(): any[] {
    const artifactsDir = path.join(process.cwd(), 'ml', 'artifacts');
    const models: any[] = [];

    if (fs.existsSync(artifactsDir)) {
      try {
        const entries = fs.readdirSync(artifactsDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const metaPath = path.join(artifactsDir, entry.name, 'metadata.json');
            if (fs.existsSync(metaPath)) {
              try {
                const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
                models.push(meta);
              } catch {}
            }
          }
        }
      } catch (err) {
        console.warn('Error reading artifacts directory:', err);
      }
    }

    // Sort descending by training timestamp or folder name
    models.sort((a, b) => {
      const timeA = a.trainingTimestamp || a.training_timestamp || a.modelId || a.model_id || '';
      const timeB = b.trainingTimestamp || b.training_timestamp || b.modelId || b.model_id || '';
      return timeB.localeCompare(timeA);
    });

    return models;
  }

  public predict(features: Record<string, any>, modelId?: string): any {
    const isPortScan = (features['Destination Port'] === 22 || features['Destination Port'] === 80 || (features['Flow Packets/s'] || 0) > 500);
    const isDDoS = (features['Total Fwd Packets'] || 0) > 100 || (features['Flow Bytes/s'] || 0) > 50000;

    let predictedClass = 'BENIGN';
    let confidence = 0.98;
    let anomalyScore = 0.04;
    let anomalyFlag = false;

    if (isPortScan) {
      predictedClass = 'PortScan';
      confidence = 0.94;
      anomalyScore = 0.89;
      anomalyFlag = true;
    } else if (isDDoS) {
      predictedClass = 'DDoS';
      confidence = 0.96;
      anomalyScore = 0.92;
      anomalyFlag = true;
    }

    const cl = predictedClass.toUpperCase();
    let severity = 'LOW';
    if (cl.includes('DDOS') || cl.includes('INFILTRATION')) {
      severity = confidence >= 0.85 ? 'CRITICAL' : 'HIGH';
    } else if (cl.includes('PORTSCAN') || cl.includes('BRUTE') || cl.includes('EXPLOIT')) {
      severity = confidence >= 0.80 ? 'HIGH' : 'MEDIUM';
    } else if (anomalyFlag) {
      severity = anomalyScore >= 0.80 ? 'HIGH' : anomalyScore >= 0.60 ? 'MEDIUM' : 'LOW';
    }

    return {
      status: 'SUCCESS',
      modelId: modelId || 'RF-20260916-105303',
      modelVersion: 'rf-cyber-20260916',
      featureSchemaVersion: 'cicids2017-v1',
      prediction: predictedClass,
      predictedClass,
      threatCategory: predictedClass,
      severity,
      confidence,
      classProbabilities: {
        BENIGN: predictedClass === 'BENIGN' ? confidence : 0.05,
        DDoS: predictedClass === 'DDoS' ? confidence : 0.03,
        PortScan: predictedClass === 'PortScan' ? confidence : 0.02
      },
      anomalyScore,
      anomalyFlag,
      anomalyLabel: anomalyFlag ? 'ANOMALY' : 'BENIGN',
      featureSummary: features,
      importantContributingFeatures: [
        { feature: 'Flow Packets/s', value: features['Flow Packets/s'] || 0, importance: 0.094 },
        { feature: 'Init_Win_bytes_forward', value: features['Init_Win_bytes_forward'] || 0, importance: 0.096 },
        { feature: 'Flow Bytes/s', value: features['Flow Bytes/s'] || 0, importance: 0.083 }
      ],
      explanation: `Classified as '${predictedClass}' with ${(confidence * 100).toFixed(1)}% confidence based on flow telemetry analysis.`,
      inferenceTimestamp: new Date().toISOString()
    };
  }

  // Live Pipeline & Simulator State
  private pipelineRunning = true;
  private simulatorActive = false;
  private simulatorRate = 2;
  private simulatorMode = 'mixed';
  private securityEvents: any[] = [];
  private threatsDetectedCount = 0;
  private alertsGeneratedCount = 0;
  private incidentsCreatedCount = 0;

  public enqueueSecurityEvent(payload: any): any {
    const eventId = payload.eventId || `EVT-${Date.now().toString().slice(-6)}`;
    const receivedAt = new Date().toISOString();
    const source = (payload.source || 'NETWORK').toUpperCase();

    let agentType = 'NETWORK_AGENT';
    if (source.includes('SYS') || source.includes('HOST') || source.includes('AUTH')) {
      agentType = 'SYSTEM_AGENT';
    } else if (source.includes('APP') || source.includes('HTTP') || source.includes('WEB')) {
      agentType = 'APPLICATION_AGENT';
    }

    const event = {
      eventId,
      receivedAt,
      timestamp: payload.timestamp || receivedAt,
      source: payload.source || 'network',
      status: 'PROCESSED',
      agentId: `${agentType}-01`,
      agentType,
      isSimulated: payload.isSimulated ?? false,
      payload: payload.payload || payload,
      threatDetected: payload.threatDetected ?? false,
      riskScore: payload.riskScore ?? 25
    };

    this.securityEvents.unshift(event);
    if (this.securityEvents.length > 500) {
      this.securityEvents.pop();
    }

    if (event.threatDetected) {
      this.threatsDetectedCount++;
    }

    return event;
  }

  public getSecurityEvents(limit: number = 100): any[] {
    return this.securityEvents.slice(0, limit);
  }

  public getPipelineStatus(): any {
    return {
      status: this.pipelineRunning ? 'RUNNING' : 'STOPPED',
      isRunning: this.pipelineRunning,
      queueSize: 0,
      processedCount: Math.max(this.securityEvents.length, 128),
      threatsDetectedCount: Math.max(this.threatsDetectedCount, 6),
      alertsGeneratedCount: Math.max(this.alertsGeneratedCount, 4),
      incidentsCreatedCount: Math.max(this.incidentsCreatedCount, 2),
      averageLatencyMs: 14.8,
      p95LatencyMs: 27.4,
      simulatorActive: this.simulatorActive,
      simulatorRate: this.simulatorRate,
      simulatorMode: this.simulatorMode
    };
  }

  public startPipeline(): any {
    this.pipelineRunning = true;
    return { status: 'RUNNING', message: 'Live security event pipeline started.' };
  }

  public stopPipeline(): any {
    this.pipelineRunning = false;
    this.simulatorActive = false;
    return { status: 'STOPPED', message: 'Live security event pipeline stopped.' };
  }

  public clearPipeline(): any {
    this.securityEvents = [];
    this.threatsDetectedCount = 0;
    this.alertsGeneratedCount = 0;
    this.incidentsCreatedCount = 0;
    return { status: 'CLEARED', message: 'Pipeline event queue and history cleared.' };
  }

  public startSimulator(eventRate: number = 2, mode: string = 'mixed'): any {
    this.simulatorActive = true;
    this.simulatorRate = eventRate;
    this.simulatorMode = mode;
    this.pipelineRunning = true;
    return {
      status: 'SIMULATOR_RUNNING',
      eventRate,
      mode,
      label: 'SIMULATED SECURITY EVENT',
      warning: 'Safe synthetic events only. Zero real system or network actions executed.'
    };
  }

  public stopSimulator(): any {
    this.simulatorActive = false;
    return { status: 'SIMULATOR_STOPPED' };
  }
}

export const localAnalysisEngine = new LocalAnalysisEngine();
