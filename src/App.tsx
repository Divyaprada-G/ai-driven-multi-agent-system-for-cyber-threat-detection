import React, { useState, useEffect, useCallback } from 'react';
import { Layout } from './components/layout/Layout';
import { NavPageId } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { LogExplorerPage } from './pages/LogExplorerPage';
import { NetworkAgentPage } from './pages/NetworkAgentPage';
import { SystemAgentPage } from './pages/SystemAgentPage';
import { ApplicationAgentPage } from './pages/ApplicationAgentPage';
import { EventCorrelationPage } from './pages/EventCorrelationPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
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
    } catch (err) {
      console.error('Failed to load telemetry state', err);
    }
  }, []);

  useEffect(() => {
    fetchTelemetry();
    const unsubscribe = logRepository.subscribe(() => {
      fetchTelemetry();
    });
    return () => unsubscribe();
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
