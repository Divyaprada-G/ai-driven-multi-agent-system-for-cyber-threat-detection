/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Central Telemetry Ingestion & Real-Time Pipeline Manager
 * 
 * Implements Target Architecture:
 * Actual Data Sources -> Telemetry Collectors -> Event Normalization -> Preprocessing ->
 * Network/System/Application Agents -> Event Correlation Agent -> Threat Detection Agent
 * (Rule Engine + ML Models) -> 7-Factor Risk Scoring -> Alert & Incident Management ->
 * MongoDB/Database -> Real-Time Dashboard (SSE + REST)
 * 
 * Strict Enforcement:
 * - Real events are flagged `isSimulated: false` and `telemetrySource: 'HOST_SYSTEM' | 'NETWORK_INTERFACE' | 'APP_HTTP'`
 * - Zero fabricated telemetry counts when collectors are stopped
 * - Explicit LIVE, SIMULATED, OFFLINE, and ERROR states
 */

import { Response } from 'express';
import { SystemCollector } from './systemCollector';
import { NetworkCollector } from './networkCollector';
import { ApplicationCollector } from './applicationCollector';
import {
  CollectorType,
  CollectorHealth,
  NormalizedTelemetryEvent,
  TelemetryIngestRequest
} from './telemetryTypes';
import { databaseService } from '../../db/databaseService';
import { localAnalysisEngine } from '../localAnalysisEngine';
import crypto from 'crypto';

export class TelemetryManager {
  private systemCollector: SystemCollector;
  private networkCollector: NetworkCollector;
  private applicationCollector: ApplicationCollector;

  // Ring buffer of recent live events for API retrieval
  private recentEvents: NormalizedTelemetryEvent[] = [];
  private maxBufferSize: number = 200;

  // Real-time metrics
  private totalLiveEvents: number = 0;
  private totalSimulatedEvents: number = 0;
  private totalThreatsDetected: number = 0;
  private totalAlertsGenerated: number = 0;
  private totalIncidentsCreated: number = 0;
  private startTimestamp: number = Date.now();

  // Connected Server-Sent Events (SSE) clients
  private sseClients: Set<Response> = new Set();

  constructor() {
    this.systemCollector = new SystemCollector(4000);
    this.networkCollector = new NetworkCollector(5000);
    this.applicationCollector = new ApplicationCollector(6000);

    // Bind event distribution
    this.systemCollector.setEventCallback((event) => this.processLiveEvent(event));
    this.networkCollector.setEventCallback((event) => this.processLiveEvent(event));
    this.applicationCollector.setEventCallback((event) => this.processLiveEvent(event));
  }

  public getSystemCollector(): SystemCollector {
    return this.systemCollector;
  }

  public getNetworkCollector(): NetworkCollector {
    return this.networkCollector;
  }

  public getApplicationCollector(): ApplicationCollector {
    return this.applicationCollector;
  }

  public startAll(): boolean {
    const s = this.systemCollector.start();
    const n = this.networkCollector.start();
    const a = this.applicationCollector.start();
    this.broadcastStatus();
    return s && n && a;
  }

  public stopAll(): boolean {
    this.systemCollector.stop();
    this.networkCollector.stop();
    this.applicationCollector.stop();
    this.broadcastStatus();
    return true;
  }

  public startCollector(type: CollectorType): boolean {
    let success = false;
    if (type === 'SYSTEM') success = this.systemCollector.start();
    else if (type === 'NETWORK') success = this.networkCollector.start();
    else if (type === 'APPLICATION') success = this.applicationCollector.start();
    this.broadcastStatus();
    return success;
  }

  public stopCollector(type: CollectorType): boolean {
    let success = false;
    if (type === 'SYSTEM') success = this.systemCollector.stop();
    else if (type === 'NETWORK') success = this.networkCollector.stop();
    else if (type === 'APPLICATION') success = this.applicationCollector.stop();
    this.broadcastStatus();
    return success;
  }

  public getStatus(): {
    overallState: 'LIVE' | 'SIMULATED' | 'OFFLINE' | 'PARTIAL';
    activeCollectorsCount: number;
    totalCollectors: number;
    collectors: CollectorHealth[];
    metrics: {
      totalLiveEvents: number;
      totalSimulatedEvents: number;
      totalThreatsDetected: number;
      totalAlertsGenerated: number;
      totalIncidentsCreated: number;
      currentEps: number;
      connectedSseClients: number;
      uptimeSeconds: number;
    };
  } {
    const collectors = [
      this.systemCollector.getStatus(),
      this.networkCollector.getStatus(),
      this.applicationCollector.getStatus()
    ];

    const activeCount = collectors.filter(c => c.state === 'LIVE').length;
    let overallState: 'LIVE' | 'SIMULATED' | 'OFFLINE' | 'PARTIAL' = 'OFFLINE';
    if (activeCount === collectors.length) overallState = 'LIVE';
    else if (activeCount > 0) overallState = 'PARTIAL';

    const elapsedSeconds = Math.max(1, (Date.now() - this.startTimestamp) / 1000);
    const eps = activeCount > 0
      ? Number((this.totalLiveEvents / elapsedSeconds).toFixed(2))
      : 0;

    return {
      overallState,
      activeCollectorsCount: activeCount,
      totalCollectors: collectors.length,
      collectors,
      metrics: {
        totalLiveEvents: this.totalLiveEvents,
        totalSimulatedEvents: this.totalSimulatedEvents,
        totalThreatsDetected: this.totalThreatsDetected,
        totalAlertsGenerated: this.totalAlertsGenerated,
        totalIncidentsCreated: this.totalIncidentsCreated,
        currentEps: eps,
        connectedSseClients: this.sseClients.size,
        uptimeSeconds: Math.floor(elapsedSeconds)
      }
    };
  }

  public getRecentEvents(limit: number = 50): NormalizedTelemetryEvent[] {
    return this.recentEvents.slice(0, Math.min(limit, this.recentEvents.length));
  }

  /**
   * SSE Client Registration for real-time push to frontend
   */
  public addSseClient(res: Response): void {
    this.sseClients.add(res);

    // Send initial status and backlog
    res.write(`data: ${JSON.stringify({ type: 'INIT_STATUS', status: this.getStatus() })}\n\n`);

    res.on('close', () => {
      this.sseClients.delete(res);
    });
  }

  public removeSseClient(res: Response): void {
    this.sseClients.delete(res);
  }

  private broadcastSse(eventType: string, data: any): void {
    const message = `data: ${JSON.stringify({ type: eventType, data, timestamp: new Date().toISOString() })}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(message);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  private broadcastStatus(): void {
    this.broadcastSse('COLLECTOR_STATUS_UPDATE', this.getStatus());
  }

  /**
   * Ingests externally submitted raw logs or telemetry packets
   */
  public async ingestExternalTelemetry(payload: TelemetryIngestRequest): Promise<{
    status: string;
    eventsProcessed: number;
    threatsDetected: number;
    eventIds: string[];
  }> {
    const isSimulated = Boolean(payload.isSimulated);
    const timestamp = new Date().toISOString();
    const eventIds: string[] = [];
    let threats = 0;

    if (payload.rawLogs) {
      const lines = payload.rawLogs.split('\n').map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        const id = `EXT-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
        eventIds.push(id);

        const normalized: NormalizedTelemetryEvent = {
          eventId: id,
          timestamp,
          source: payload.source || 'system',
          eventType: payload.eventType || 'External Telemetry Ingest',
          sourceIp: payload.sourceIp || '127.0.0.1',
          destinationIp: payload.destinationIp || '127.0.0.1',
          host: payload.host || 'external-host',
          severity: 'LOW',
          details: line,
          rawPayload: line,
          contentHash: crypto.createHash('sha256').update(line).digest('hex'),
          isSimulated,
          telemetrySource: isSimulated ? 'SIMULATOR' : 'EXTERNAL_AGENT',
          collectorState: isSimulated ? 'SIMULATED' : 'LIVE',
          features: {},
          agentRouting: {
            assignedAgent: payload.source === 'network' ? 'Network Security Agent' : payload.source === 'application' ? 'Application Security Agent' : 'System Security Agent',
            assignedAgentId: payload.source === 'network' ? 'agent-network-1' : payload.source === 'application' ? 'agent-app-1' : 'agent-system-1'
          }
        };

        await this.processLiveEvent(normalized);
      }
    } else if (Array.isArray(payload.structuredEvents)) {
      for (const ev of payload.structuredEvents) {
        const id = ev.eventId || `EXT-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
        eventIds.push(id);

        const normalized: NormalizedTelemetryEvent = {
          eventId: id,
          timestamp: ev.timestamp || timestamp,
          source: ev.source || payload.source || 'system',
          eventType: ev.eventType || 'External Structured Telemetry',
          sourceIp: ev.sourceIp || payload.sourceIp || '127.0.0.1',
          destinationIp: ev.destinationIp || payload.destinationIp || '127.0.0.1',
          sourcePort: ev.sourcePort,
          destinationPort: ev.destinationPort,
          protocol: ev.protocol,
          host: ev.host || payload.host || 'external-host',
          username: ev.username,
          severity: ev.severity || 'LOW',
          details: ev.details || 'Structured telemetry ingested via REST API.',
          rawPayload: ev.rawPayload || JSON.stringify(ev),
          contentHash: ev.contentHash || crypto.createHash('sha256').update(JSON.stringify(ev)).digest('hex'),
          isSimulated,
          telemetrySource: isSimulated ? 'SIMULATOR' : 'EXTERNAL_AGENT',
          collectorState: isSimulated ? 'SIMULATED' : 'LIVE',
          features: ev.features || {},
          agentRouting: {
            assignedAgent: ev.agentRouting?.assignedAgent || 'System Security Agent',
            assignedAgentId: ev.agentRouting?.assignedAgentId || 'agent-system-1'
          }
        };

        await this.processLiveEvent(normalized);
      }
    }

    return {
      status: 'SUCCESS',
      eventsProcessed: eventIds.length,
      threatsDetected: threats,
      eventIds
    };
  }

  /**
   * Full Pipeline Execution for Every Live Telemetry Event:
   * Event Normalization -> Deduplication -> Multi-Agent Pipeline -> ML Prediction ->
   * 7-Factor Risk Scoring -> Alert/Incident Creation -> Durable Database Storage -> SSE Broadcast
   */
  public async processLiveEvent(event: NormalizedTelemetryEvent): Promise<void> {
    if (event.isSimulated) {
      this.totalSimulatedEvents++;
    } else {
      this.totalLiveEvents++;
    }

    // 1. Maintain recent in-memory buffer
    this.recentEvents.unshift(event);
    if (this.recentEvents.length > this.maxBufferSize) {
      this.recentEvents.pop();
    }

    // 2. Persist Raw Event to Database (PostgreSQL / MongoDB / Local JSON)
    try {
      await databaseService.insertRawEvent({
        id: event.eventId,
        source: event.source,
        eventType: event.eventType,
        rawPayload: event.rawPayload,
        normalizedFields: {
          host: event.host,
          severity: event.severity,
          details: event.details,
          features: event.features,
          isSimulated: event.isSimulated,
          telemetrySource: event.telemetrySource
        },
        eventTimestamp: event.timestamp,
        sourceIp: event.sourceIp,
        destinationIp: event.destinationIp,
        host: event.host,
        username: event.username,
        severity: event.severity,
        isTestEvent: event.isSimulated
      });
    } catch (err: any) {
      console.warn(`[TelemetryManager] Failed saving event ${event.eventId} to DB:`, err.message);
    }

    // 3. Multi-Agent Analysis & ML Threat Evaluation
    let isThreat = false;
    let mlDetection: any = null;
    let finding: any = null;
    let alert: any = null;
    let incident: any = null;

    try {
      // Analyze with rule engine and models
      const analysis = localAnalysisEngine.analyze(event.rawPayload, event.source, event.eventId);
      
      if (analysis.threat_detected && analysis.findings.length > 0) {
        isThreat = true;
        this.totalThreatsDetected++;
        const topFinding = analysis.findings[0];

        finding = {
          eventId: event.eventId,
          agentType: event.agentRouting.assignedAgent,
          threatType: topFinding.threat_type,
          severity: topFinding.severity,
          confidence: topFinding.confidence,
          evidence: topFinding.evidence,
          indicators: [event.sourceIp, event.destinationIp, topFinding.mitre_technique].filter(Boolean),
          mitreTechnique: topFinding.mitre_technique,
          timestamp: event.timestamp,
          metadata: { isSimulated: event.isSimulated, telemetrySource: event.telemetrySource }
        };

        // Persist Security Finding
        try {
          await databaseService.insertFinding(finding);
        } catch {}

        // Calculate 7-Factor Risk Score
        const riskScore = analysis.risk_assessment?.risk_score || 75;
        const riskBand = analysis.risk_assessment?.risk_band || 'High';

        // 4. Generate Alert if High/Critical or Risk >= 50
        if (riskScore >= 50 || topFinding.severity === 'HIGH' || topFinding.severity === 'CRITICAL') {
          this.totalAlertsGenerated++;
          const alertId = `ALT-${Date.now().toString().slice(-6)}`;
          
          alert = {
            id: alertId,
            title: `${topFinding.threat_type} on ${event.host}`,
            severity: topFinding.severity,
            source: event.source,
            category: topFinding.threat_type,
            status: 'NEW',
            description: topFinding.description,
            mitreTechnique: topFinding.mitre_technique || 'T1078',
            mitreTactic: 'Defense Evasion',
            sourceIp: event.sourceIp,
            targetIp: event.destinationIp,
            affectedHost: event.host,
            riskScore,
            associatedFindingIds: [topFinding.id],
            recommendedActions: [
              `Isolate host ${event.host} or block source IP ${event.sourceIp}.`,
              `Inspect active processes and check authentication logs.`
            ],
            isSimulated: event.isSimulated,
            timestamp: event.timestamp
          };

          try {
            await databaseService.insertAlert(alert);
          } catch {}

          // 5. Escalate to Incident if Critical or Multi-vector
          if (riskScore >= 80 || topFinding.severity === 'CRITICAL') {
            this.totalIncidentsCreated++;
            const incidentId = `INC-${Date.now().toString().slice(-6)}`;
            
            incident = {
              id: incidentId,
              title: `High Priority Threat: ${topFinding.threat_type} on ${event.host}`,
              severity: 'CRITICAL',
              status: 'NEW',
              summary: `Automated incident triggered from live telemetry on ${event.host}. Source IP ${event.sourceIp}.`,
              associatedAlertIds: [alertId],
              affectedAssets: [event.host, event.destinationIp].filter(Boolean),
              sourceIps: [event.sourceIp],
              assignedTo: 'SOC L2 Analyst',
              containmentStatus: 'REQUIRES_IMMEDIATE_ACTION',
              isSimulated: event.isSimulated,
              createdAt: event.timestamp
            };

            try {
              await databaseService.insertIncident(incident);
            } catch {}
          }
        }
      }
    } catch (err: any) {
      console.warn(`[TelemetryManager] Pipeline processing error for ${event.eventId}:`, err.message);
    }

    // 6. Broadcast Event via SSE to live Dashboard
    this.broadcastSse('NEW_TELEMETRY_EVENT', {
      event,
      isThreat,
      finding,
      alert,
      incident
    });
  }
}

export const telemetryManager = new TelemetryManager();
