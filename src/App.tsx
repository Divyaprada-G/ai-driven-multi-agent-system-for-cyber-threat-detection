import React, { useState, useEffect, useCallback } from 'react';
import { Layout } from './components/layout/Layout';
import { NavPageId } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { AnalyzeLogsPage } from './pages/AnalyzeLogsPage';
import { LivePipelinePage } from './pages/LivePipelinePage';
import { LogExplorerPage } from './pages/LogExplorerPage';
import { NetworkAgentPage } from './pages/NetworkAgentPage';
import { SystemAgentPage } from './pages/SystemAgentPage';
import { ApplicationAgentPage } from './pages/ApplicationAgentPage';
import { EventCorrelationPage } from './pages/EventCorrelationPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { DatasetsMlTrainingPage } from './pages/DatasetsMlTrainingPage';
import { RiskAnalysisPage } from './pages/RiskAnalysisPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { AlertsPage } from './pages/AlertsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

import { metricsService } from './services/metricsService';
import { logService } from './services/logService';
import { logRepository } from './services/logRepository';
import { networkAgentService } from './services/networkAgentService';
import { systemAgentService } from './services/systemAgentService';
import { applicationAgentService } from './services/applicationAgentService';
import { alertManager } from './services/alertIncident/alertManager';
import { incidentManager } from './services/alertIncident/incidentManager';
import { realtimeTelemetryStream } from './services/telemetry/realtimeTelemetryStream';
import { apiClient } from './services/apiClient';

import {
  DashboardMetrics,
  AgentStatusInfo,
  TimeSeriesPoint,
  SeverityDistributionPoint,
  SourceDistributionPoint,
  AgentActivityPoint,
  ThreatCategoryPoint,
  LogFileRecord,
  LogType
} from './types';
import { RecentEventItem } from './components/tables/RecentEventsTable';

export default function App() {
  const [currentPage, setCurrentPage] = useState<NavPageId>('dashboard');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [targetIncidentId, setTargetIncidentId] = useState<string | undefined>(undefined);

  // Core SOC State
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [agents, setAgents] = useState<AgentStatusInfo[]>([]);
  const [eventsOverTime, setEventsOverTime] = useState<TimeSeriesPoint[]>([]);
  const [severityDistribution, setSeverityDistribution] = useState<SeverityDistributionPoint[]>([]);
  const [eventsBySource, setEventsBySource] = useState<SourceDistributionPoint[]>([]);
  const [agentActivity, setAgentActivity] = useState<AgentActivityPoint[]>([]);
  const [threatCategories, setThreatCategories] = useState<ThreatCategoryPoint[]>([]);
  const [recentEvents, setRecentEvents] = useState<RecentEventItem[]>([]);
  const [logFiles, setLogFiles] = useState<LogFileRecord[]>([]);

  // Inter-page cross-navigation handlers
  const handleNavigateToIncident = (incidentId: string) => {
    setTargetIncidentId(incidentId);
    setCurrentPage('incidents');
  };

  const handleNavigateToAlert = (_alertId: string) => {
    setCurrentPage('alerts');
  };

  // Telemetry Fetcher
  const fetchTelemetry = useCallback(async () => {
    try {
      const [
        m,
        ag,
        eot,
        sev,
        ebs,
        act,
        tc,
        recEvts,
        files
      ] = await Promise.all([
        metricsService.getDashboardMetrics(),
        metricsService.getAgentStatuses(),
        metricsService.getEventsOverTime(),
        metricsService.getSeverityDistribution(),
        metricsService.getEventsBySource(),
        metricsService.getAgentActivity(),
        metricsService.getThreatCategories(),
        metricsService.getRecentSecurityEvents(),
        logService.getUploadedFiles()
      ]);

      setMetrics(m);
      setAgents(ag);
      setEventsOverTime(eot);
      setSeverityDistribution(sev);
      setEventsBySource(ebs);
      setAgentActivity(act);
      setThreatCategories(tc);
      setRecentEvents(recEvts);
      setLogFiles(files);
      alertManager.syncWithBackend();
      incidentManager.syncWithBackend();
    } catch (err) {
      console.error('Failed to load telemetry state', err);
    }
  }, []);

  useEffect(() => {
    // Ensure active authenticated session exists before querying protected APIs
    apiClient.ensureAuthenticated().then(() => {
      fetchTelemetry();
    });

    const unsubAuth = apiClient.subscribeAuth(() => {
      fetchTelemetry();
    });

    const unsubLog = logRepository.subscribe(() => {
      fetchTelemetry();
    });

    // Real-Time Telemetry Stream: Live reactive dashboard updates without manual refresh
    const unsubComposite = realtimeTelemetryStream.onCompositeEvent((composite) => {
      const { event, isThreat, finding, alert, incident, riskAssessment } = composite;
      if (!event) return;

      // 1. Prepend to Recent Events
      const newItem: RecentEventItem = {
        id: event.eventId,
        timestamp: event.timestamp.replace('T', ' ').substring(0, 19),
        source: event.sourceIp || event.host || event.source,
        agent: event.agentRouting?.assignedAgent || `${event.source.toUpperCase()} Agent`,
        eventType: event.eventType || 'Telemetry Event Ingested',
        severity: (event.severity || 'LOW') as any,
        riskScore: riskAssessment?.risk_score || (isThreat ? 75 : 20),
        status: isThreat ? 'Threat Flagged' : 'Normalized',
        action: finding ? `Detected: ${finding.threatType || finding.threat_type}` : 'Parsed & Ingested',
        detail: event.details || (typeof event.rawPayload === 'string' ? event.rawPayload.slice(0, 100) : '')
      };

      setRecentEvents(prev => [newItem, ...prev.slice(0, 49)]);

      // 2. Increment Dashboard Metrics
      setMetrics(prev => {
        if (!prev) return prev;
        const isNet = event.source === 'network';
        const isSys = event.source === 'system';
        const isApp = event.source === 'application';
        return {
          ...prev,
          totalEvents: prev.totalEvents + 1,
          suspiciousEvents: prev.suspiciousEvents + (isThreat ? 1 : 0),
          activeThreats: prev.activeThreats + (finding ? 1 : 0),
          criticalIncidents: prev.criticalIncidents + (incident ? 1 : 0),
          networkEvents: prev.networkEvents + (isNet ? 1 : 0),
          systemEvents: prev.systemEvents + (isSys ? 1 : 0),
          applicationEvents: prev.applicationEvents + (isApp ? 1 : 0),
          lastUpdated: new Date().toISOString()
        };
      });

      // 3. Update Severity Distribution
      if (event.severity) {
        setSeverityDistribution(prev =>
          prev.map(p => p.severity === event.severity ? { ...p, count: p.count + 1 } : p)
        );
      }

      // 4. Update Events by Source
      setEventsBySource(prev => {
        const src = event.source;
        return prev.map(p => {
          const match = (src === 'network' && p.source.toLowerCase().includes('network')) ||
                        (src === 'system' && p.source.toLowerCase().includes('host')) ||
                        (src === 'application' && p.source.toLowerCase().includes('app'));
          return match ? { ...p, count: p.count + 1, threats: p.threats + (isThreat ? 1 : 0) } : p;
        });
      });

      // 5. Update Agent Activity Timeline
      setAgentActivity(prev => {
        if (prev.length === 0) return prev;
        const copy = [...prev];
        const last = { ...copy[copy.length - 1] };
        if (event.source === 'network') last.networkAgent = (last.networkAgent || 0) + 1;
        else if (event.source === 'system') last.systemAgent = (last.systemAgent || 0) + 1;
        else if (event.source === 'application') last.applicationAgent = (last.applicationAgent || 0) + 1;
        copy[copy.length - 1] = last;
        return copy;
      });

      // 6. Sync Alerts and Incidents if triggered
      if (alert) {
        alertManager.syncWithBackend();
      }
      if (incident) {
        incidentManager.syncWithBackend();
      }
    });

    // Real-Time Agent Status listener
    const unsubAgent = realtimeTelemetryStream.onAgentStatus((agentUpdate) => {
      if (!agentUpdate || !agentUpdate.agentId) return;
      setAgents(prev =>
        prev.map(ag => ag.agentId === agentUpdate.agentId ? {
          ...ag,
          status: agentUpdate.status || ag.status,
          eventsProcessed: agentUpdate.eventsProcessed ?? ag.eventsProcessed,
          threatsDetected: agentUpdate.threatsDetected ?? ag.threatsDetected,
          lastActivity: agentUpdate.lastActivity || new Date().toISOString()
        } : ag)
      );
    });

    return () => {
      unsubAuth();
      unsubLog();
      unsubComposite();
      unsubAgent();
    };
  }, [fetchTelemetry]);

  // Refresh handler (simulates live poll)
  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchTelemetry();
    setTimeout(() => setIsRefreshing(false), 600);
  };

  // Toggle Agent Status Handler
  const handleToggleAgentStatus = async (agentId: string) => {
    if (agentId === 'NETWORK_AGENT') {
      await networkAgentService.toggleAgentStatus();
    } else if (agentId === 'SYSTEM_AGENT') {
      await systemAgentService.toggleAgentStatus();
    } else if (agentId === 'APPLICATION_AGENT') {
      await applicationAgentService.toggleAgentStatus();
    }
    const updatedAgents = await metricsService.getAgentStatuses();
    setAgents(updatedAgents);
  };

  // File Upload Handler
  const handleUploadFile = async (file: File, logType?: LogType) => {
    const uploaded = await logService.uploadLogFile(file, logType);
    await fetchTelemetry();
    return uploaded;
  };

  // File Delete Handler
  const handleDeleteFile = async (id: string) => {
    const success = await logService.deleteLogFile(id);
    if (success) {
      await fetchTelemetry();
    }
    return success;
  };

  return (
    <Layout
      currentPage={currentPage}
      onNavigate={setCurrentPage}
      onRefresh={handleRefresh}
      isRefreshing={isRefreshing}
      onNavigateToAlerts={() => setCurrentPage('alerts')}
    >
      {/* Page Routing */}
      {currentPage === 'dashboard' && metrics && (
        <DashboardPage
          metrics={metrics}
          agents={agents}
          eventsOverTime={eventsOverTime}
          severityDistribution={severityDistribution}
          eventsBySource={eventsBySource}
          agentActivity={agentActivity}
          threatCategories={threatCategories}
          recentEvents={recentEvents}
          onNavigate={setCurrentPage}
          onToggleAgentStatus={handleToggleAgentStatus}
        />
      )}

      {currentPage === 'system-status' && (
        <SystemStatusPage />
      )}

      {currentPage === 'analyze-logs' && (
        <AnalyzeLogsPage
          onNavigate={setCurrentPage}
          onNavigateToIncident={handleNavigateToIncident}
        />
      )}

      {currentPage === 'live-pipeline' && (
        <LivePipelinePage onNavigate={setCurrentPage} />
      )}

      {currentPage === 'log-explorer' && (
        <LogExplorerPage
          files={logFiles}
          onUploadFile={handleUploadFile}
          onDeleteFile={handleDeleteFile}
        />
      )}

      {currentPage === 'network-agent' && (
        <NetworkAgentPage onNavigate={setCurrentPage} />
      )}

      {currentPage === 'system-agent' && (
        <SystemAgentPage onNavigate={setCurrentPage} />
      )}

      {currentPage === 'application-agent' && (
        <ApplicationAgentPage onNavigate={setCurrentPage} />
      )}

      {(currentPage === 'correlation' || (currentPage as string) === 'event-correlation') && (
        <EventCorrelationPage />
      )}

      {currentPage === 'threat-detection' && (
        <ThreatDetectionPage onNavigate={setCurrentPage} />
      )}

      {currentPage === 'datasets-ml' && (
        <DatasetsMlTrainingPage onNavigate={setCurrentPage} />
      )}

      {currentPage === 'risk-analysis' && <RiskAnalysisPage />}

      {currentPage === 'incidents' && (
        <IncidentsPage
          initialIncidentId={targetIncidentId}
          onNavigateToAlert={handleNavigateToAlert}
        />
      )}

      {currentPage === 'alerts' && (
        <AlertsPage
          onNavigate={setCurrentPage}
          onNavigateToIncident={handleNavigateToIncident}
        />
      )}

      {currentPage === 'reports' && <ReportsPage />}

      {currentPage === 'settings' && <SettingsPage />}
    </Layout>
  );
}
