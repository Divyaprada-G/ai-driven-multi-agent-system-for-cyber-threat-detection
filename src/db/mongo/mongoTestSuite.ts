/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * MongoDB Test Suite - Validates all required CRUD, Sanitization, and Aggregation operations
 */
import { mongoService } from './mongoService';
import { mongoConnection } from './connection';
import { sanitizeSensitiveData } from './validation';

export interface TestCaseResult {
  name: string;
  category: string;
  passed: boolean;
  durationMs: number;
  details: string;
  error?: string;
}

export interface TestSuiteSummary {
  timestamp: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  databaseStatus: string;
  results: TestCaseResult[];
}

export async function runMongoTestSuite(): Promise<TestSuiteSummary> {
  const results: TestCaseResult[] = [];
  const health = await mongoConnection.checkHealth();
  const testRunId = Date.now().toString().slice(-6);

  async function executeTest(
    name: string,
    category: string,
    testFn: () => Promise<string>
  ) {
    const start = Date.now();
    try {
      const details = await testFn();
      results.push({
        name,
        category,
        passed: true,
        durationMs: Date.now() - start,
        details
      });
    } catch (err: any) {
      results.push({
        name,
        category,
        passed: false,
        durationMs: Date.now() - start,
        details: 'Test failed with error',
        error: err.message || String(err)
      });
    }
  }

  // 1. Sanitization & Sensitive Data Redaction
  await executeTest('Sensitive Data Redaction', 'Security', async () => {
    const rawPayload = 'user=admin password=SuperSecretPassword123! token=bearer_xyz987';
    const sanitized = sanitizeSensitiveData(rawPayload);
    if (sanitized.includes('SuperSecretPassword123!')) {
      throw new Error('Plaintext password was not redacted from string.');
    }
    const objPayload = {
      user: 'analyst',
      secretToken: 'secret_value_123',
      apiKey: 'key_abc',
      nested: { password: 'another_password' }
    };
    const sanitizedObj = sanitizeSensitiveData(objPayload);
    if (sanitizedObj.secretToken !== '[REDACTED]' || sanitizedObj.nested?.password !== '[REDACTED]') {
      throw new Error('Sensitive object keys were not redacted.');
    }
    return 'Credentials and secret tokens successfully replaced with [REDACTED].';
  });

  // 2. Create Security Event
  let createdEventId = '';
  await executeTest('Create Security Event', 'Security Events', async () => {
    const res = await mongoService.createSecurityEvent({
      source: 'Zeek-Bro',
      eventType: 'NETWORK_PORT_SCAN',
      severity: 'HIGH',
      rawPayload: `2026-09-17T12:00:00Z src_ip=192.168.1.50 dst_ip=10.0.0.1 port=22 action=SYN_FLOOD password=plainPass`,
      sourceIp: '192.168.1.50',
      destinationIp: '10.0.0.1',
      host: 'dmz-fw01',
      normalizedFields: { protocol: 'TCP', port: 22, attack: 'PortScan' }
    });

    if (!res.event || !res.event.id) {
      throw new Error('Event was not returned with valid ID.');
    }
    if (res.event.rawPayload.includes('plainPass')) {
      throw new Error('Sensitive password in rawPayload was not redacted.');
    }

    createdEventId = res.event.id;
    return `Event created with ID: ${createdEventId} (Duplicate: ${res.isDuplicate})`;
  });

  // 3. Event Deduplication Check
  await executeTest('Event Deduplication by Content Hash', 'Security Events', async () => {
    const duplicateRes = await mongoService.createSecurityEvent({
      source: 'Zeek-Bro',
      eventType: 'NETWORK_PORT_SCAN',
      severity: 'HIGH',
      rawPayload: `2026-09-17T12:00:00Z src_ip=192.168.1.50 dst_ip=10.0.0.1 port=22 action=SYN_FLOOD password=plainPass`,
      sourceIp: '192.168.1.50',
      destinationIp: '10.0.0.1'
    });

    if (!duplicateRes.isDuplicate) {
      throw new Error('Duplicate event was not detected via contentHash.');
    }
    return `Duplicate event recognized successfully (Content Hash: ${duplicateRes.event.contentHash}).`;
  });

  // 4. Retrieve Security Events with Filter and Pagination
  await executeTest('Retrieve Security Events (Filtered & Paginated)', 'Security Events', async () => {
    const paginated = await mongoService.getSecurityEvents(
      { severity: 'HIGH' },
      { limit: 10, page: 1, sortBy: 'timestamp', sortOrder: 'desc' }
    );

    if (!Array.isArray(paginated.data)) {
      throw new Error('Paginated result data is not an array.');
    }
    return `Retrieved ${paginated.data.length} events out of ${paginated.total} total matching severity HIGH.`;
  });

  // 5. Create Incident
  const incidentId = `INC-TEST-${testRunId}`;
  await executeTest('Create Correlated Incident', 'Incidents', async () => {
    const inc = await mongoService.createIncident({
      incidentId,
      title: 'Automated Multi-Vector Reconnaissance Attack',
      description: 'Distributed port scan followed by SSH credential brute force attempt.',
      severity: 'CRITICAL',
      priority: 'P1',
      status: 'NEW',
      riskScore: 88,
      primaryIp: '192.168.1.50',
      affectedHost: 'dmz-fw01',
      mitreTechniques: ['T1046', 'T1110.001'],
      correlatedEvents: [createdEventId]
    });

    if (inc.incidentId !== incidentId || inc.status !== 'NEW') {
      throw new Error('Incident creation mismatch.');
    }
    return `Created incident ${inc.incidentId} with Risk Score ${inc.riskScore}.`;
  });

  // 6. Retrieve Incidents
  await executeTest('Retrieve Incidents (Filtered & Paginated)', 'Incidents', async () => {
    const res = await mongoService.getIncidents({ minRisk: 50 }, { limit: 5 });
    if (!res.data.some((i) => i.incidentId === incidentId)) {
      throw new Error(`Recently created incident ${incidentId} not found in listing.`);
    }
    return `Successfully listed incidents (Found test incident ${incidentId}).`;
  });

  // 7. Update Incident Status
  await executeTest('Update Incident Status with Audit Log', 'Incidents', async () => {
    const updated = await mongoService.updateIncidentStatus(
      incidentId,
      'INVESTIGATING',
      'Lead Security Engineer',
      'Containment protocols initiated on host dmz-fw01'
    );

    if (!updated || updated.status !== 'INVESTIGATING') {
      throw new Error(`Expected status INVESTIGATING, received: ${updated?.status}`);
    }
    return `Updated incident status to INVESTIGATING by Lead Security Engineer.`;
  });

  // 8. Add Investigation Note
  await executeTest('Add Investigation Note', 'Incidents', async () => {
    const noteText = 'Firewall ACL rules applied to isolate source IP 192.168.1.50.';
    const updated = await mongoService.addInvestigationNote(incidentId, noteText, 'Incident Responder');

    if (!updated || !updated.investigationNotes?.some((n) => n.note.includes('Firewall ACL'))) {
      throw new Error('Investigation note was not appended to incident.');
    }
    return `Added investigation note to incident ${incidentId}. Total notes: ${updated.investigationNotes.length}.`;
  });

  // 9. Create Threat Detection & Retrieval
  const detectionId = `DET-TEST-${testRunId}`;
  await executeTest('Create and Retrieve Threat Detection', 'Detections', async () => {
    const det = await mongoService.createThreatDetection({
      detectionId,
      eventId: createdEventId,
      threatType: 'DDoS - SYN Flood',
      severity: 'CRITICAL',
      confidence: 0.94,
      detectionEngine: 'RANDOM_FOREST',
      features: { flowDuration: 1200, synPackets: 850, flowBytesSec: 92400 },
      explanation: 'Rapid burst of SYN packets with no corresponding ACK handshakes.'
    });

    if (det.detectionId !== detectionId) {
      throw new Error('Threat detection creation mismatch.');
    }

    const listed = await mongoService.getThreatDetections({ detectionEngine: 'RANDOM_FOREST' }, { limit: 5 });
    if (!listed.data.some((d) => d.detectionId === detectionId)) {
      throw new Error('Created detection not found in query.');
    }
    return `Created and verified detection ${detectionId} (Confidence: 94%).`;
  });

  // 10. Create Alert & Retrieve Alert History
  const alertId = `ALT-TEST-${testRunId}`;
  await executeTest('Create Alert & Retrieve Alert History', 'Alerts', async () => {
    const alt = await mongoService.createAlert({
      alertId,
      incidentId,
      title: 'High-Volume Port Scan Detected',
      description: 'Single IP probed more than 20 ports within 5 seconds.',
      alertType: 'NETWORK_RECON',
      severity: 'HIGH',
      priority: 'P2',
      riskScore: 78,
      mitreTechniques: ['T1046']
    });

    if (alt.alertId !== alertId) {
      throw new Error('Alert creation mismatch.');
    }

    const history = await mongoService.getAlerts({ incidentId }, { limit: 10 });
    if (!history.data.some((a) => a.alertId === alertId)) {
      throw new Error('Alert not found in incident history.');
    }

    // Update alert status
    await mongoService.updateAlertStatus(alertId, 'ACKNOWLEDGED', 'Tier-1 Analyst');
    return `Alert ${alertId} created and status transitioned to ACKNOWLEDGED.`;
  });

  // 11. Create Agent Execution Log & Retrieval
  const logId = `LOG-TEST-${testRunId}`;
  await executeTest('Create Agent Execution Log & Retrieval', 'Agent Logs', async () => {
    const log = await mongoService.createAgentLog({
      logId,
      agentId: 'NetworkMonitoringAgent',
      action: 'PROCESS_PACKET_BATCH',
      level: 'INFO',
      message: 'Batch of 500 network flows ingested and parsed cleanly.',
      executionTimeMs: 14.8,
      eventsProcessedCount: 500,
      metadata: { interface: 'eth0', pcapCaptureRate: '98.5%' }
    });

    if (log.logId !== logId) {
      throw new Error('Agent log creation mismatch.');
    }

    const logs = await mongoService.getAgentLogs({ agentId: 'NetworkMonitoringAgent' }, { limit: 5 });
    if (!logs.data.some((l) => l.logId === logId)) {
      throw new Error('Agent log not found in query.');
    }
    return `Agent log ${logId} stored and verified.`;
  });

  // 12. Create Model Metadata & Retrieval
  const modelId = `RF-MODEL-${testRunId}`;
  await executeTest('Create Model Metadata & Retrieval', 'Model Registry', async () => {
    const model = await mongoService.createOrUpdateModelMetadata({
      modelId,
      modelName: 'Random Forest Threat Classifier v2',
      algorithm: 'RandomForestClassifier',
      version: '2.1.0',
      status: 'ACTIVE',
      datasetUsed: 'CICIDS2017_BENCHMARK',
      metrics: { accuracy: 0.978, f1Score: 0.965, precision: 0.981, recall: 0.952 },
      featureNames: ['Flow Duration', 'Total Fwd Packets', 'Flow Bytes/s', 'SYN Flag Count']
    });

    if (model.modelId !== modelId) {
      throw new Error('Model metadata creation mismatch.');
    }

    const retrieved = await mongoService.getModelMetadata(modelId);
    if (!retrieved || retrieved.modelId !== modelId) {
      throw new Error('Failed to retrieve model metadata by ID.');
    }
    return `Model ${modelId} registered with Accuracy 97.8% and F1 96.5%.`;
  });

  // 13. Dashboard Statistics Aggregation
  await executeTest('Retrieve Dashboard Statistics Aggregation', 'Dashboard Stats', async () => {
    const stats = await mongoService.getDashboardStatistics();
    if (typeof stats.totalEvents !== 'number' || typeof stats.activeIncidents !== 'number') {
      throw new Error('Dashboard stats returned invalid metric counts.');
    }
    return `Stats computed from source '${stats.source}': ${stats.totalEvents} events, ${stats.activeIncidents} active incidents, ${stats.totalAlerts} alerts.`;
  });

  const passedTests = results.filter((r) => r.passed).length;
  const failedTests = results.filter((r) => !r.passed).length;

  return {
    timestamp: new Date().toISOString(),
    totalTests: results.length,
    passedTests,
    failedTests,
    databaseStatus: health.status,
    results
  };
}
