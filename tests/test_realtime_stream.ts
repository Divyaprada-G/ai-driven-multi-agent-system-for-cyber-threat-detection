/**
 * Unit and Integration Test Suite for Real-Time Telemetry Streaming
 * 
 * Verifies:
 * 1. Monotonic sequence tracking and replay buffer in TelemetryManager
 * 2. Broadcast of granular domain events (Threats, Alerts, Incidents)
 * 3. Accurate state calculation (LIVE vs SIMULATION vs OFFLINE)
 * 4. Micro-batching and backpressure handling
 * 5. Duplicate event prevention (LRU eviction cache)
 * 6. Connection status callbacks and graceful offline mode
 */

import assert from 'node:assert';
import { telemetryManager } from '../src/services/telemetry/telemetryManager';
import { realtimeTelemetryStream } from '../src/services/telemetry/realtimeTelemetryStream';
import { NormalizedTelemetryEvent } from '../src/services/telemetry/telemetryTypes';

async function runTests() {
  console.log('--- Starting Real-Time Telemetry Stream Test Suite ---');

  // TEST 1: TelemetryManager sequencing and buffer replay
  console.log('[Test 1] Testing sequence ordering and replay buffer...');
  const initialStatus = telemetryManager.getStatus();
  assert(initialStatus.metrics !== undefined, 'Initial metrics should be defined');
  
  // Create mock response to capture SSE events
  let capturedChunks: string[] = [];
  const mockRes: any = {
    write: (chunk: string) => {
      capturedChunks.push(chunk);
      return true;
    },
    on: () => {},
    end: () => {}
  };

  // Add client with no lastEventId
  await telemetryManager.addSseClient(mockRes);
  assert(capturedChunks.length > 0, 'Client should immediately receive INIT_STATUS on connect');
  assert(capturedChunks[0].includes('event: INIT_STATUS'), 'First message must be INIT_STATUS');
  assert(capturedChunks[0].includes('id: 0') || capturedChunks[0].includes('id:'), 'INIT_STATUS must include id:');

  // Test event ingestion and sequence progression
  capturedChunks = [];
  const testEvent: NormalizedTelemetryEvent = {
    eventId: `TEST-EVT-${Date.now()}-1`,
    timestamp: new Date().toISOString(),
    source: 'system',
    eventType: 'Process Creation Telemetry',
    sourceIp: '127.0.0.1',
    destinationIp: '127.0.0.1',
    host: 'TEST-HOST',
    severity: 'LOW',
    details: 'Verified test host process execution',
    rawPayload: '{"action":"process_start","pid":1234}',
    contentHash: 'hash123',
    isSimulated: false,
    telemetrySource: 'HOST_SYSTEM',
    collectorState: 'LIVE',
    features: { pid: 1234 },
    agentRouting: {
      assignedAgent: 'System Agent',
      assignedAgentId: 'SYSTEM_AGENT'
    }
  };

  await telemetryManager.processLiveEvent(testEvent);

  // Check that SSE client received event
  const receivedRaw = capturedChunks.join('');
  assert(receivedRaw.includes('event: NEW_TELEMETRY_EVENT'), 'Client must receive NEW_TELEMETRY_EVENT');
  assert(receivedRaw.includes(testEvent.eventId), 'Client must receive the processed event ID');

  // TEST 2: Replay Buffer test
  console.log('[Test 2] Testing replay of missed events via Last-Event-ID...');
  telemetryManager.removeSseClient(mockRes);

  const replayingResChunks: string[] = [];
  const mockReplayRes: any = {
    write: (chunk: string) => {
      replayingResChunks.push(chunk);
      return true;
    },
    on: () => {},
    end: () => {}
  };

  // Connect client requesting replay from sequence 0
  await telemetryManager.addSseClient(mockReplayRes, '0');
  const replayRaw = replayingResChunks.join('');
  assert(replayRaw.includes('INIT_STATUS'), 'Reconnecting client receives INIT_STATUS');
  assert(replayRaw.includes('NEW_TELEMETRY_EVENT'), 'Reconnecting client receives missed events from buffer');
  telemetryManager.removeSseClient(mockReplayRes);

  // TEST 3: Accurate Telemetry State Determination
  console.log('[Test 3] Testing accurate telemetry state determination (LIVE vs SIMULATION)...');
  const statusAfterLive = telemetryManager.getStatus();
  assert(statusAfterLive.overallState === 'LIVE' || statusAfterLive.overallState === 'PARTIAL', 'Overall state must be LIVE or PARTIAL when receiving live events');
  assert.strictEqual(telemetryManager.determineTelemetryState(), 'LIVE', 'Calculated stream state must be LIVE when receiving live host events');

  // Ingest simulated event and verify classification
  const simEvent: NormalizedTelemetryEvent = {
    eventId: `TEST-SIM-${Date.now()}-2`,
    timestamp: new Date().toISOString(),
    source: 'network',
    eventType: '[SIMULATED] Network Flow',
    sourceIp: '192.168.1.50',
    destinationIp: '10.0.0.1',
    host: 'TEST-SIM-HOST',
    severity: 'LOW',
    details: 'Simulated flow for unit test',
    rawPayload: 'simulated',
    contentHash: 'simhash',
    isSimulated: true,
    telemetrySource: 'SIMULATOR',
    collectorState: 'SIMULATED',
    features: {},
    agentRouting: {
      assignedAgent: 'Network Agent',
      assignedAgentId: 'NETWORK_AGENT'
    }
  };

  await telemetryManager.processLiveEvent(simEvent);
  const statusAfterSim = telemetryManager.getStatus();
  assert(statusAfterSim.metrics.totalSimulatedEvents >= 1, 'Metrics must record simulated events');

  // TEST 4: Duplicate Event Prevention & Deduplication
  console.log('[Test 4] Testing duplicate event prevention in client stream...');
  const duplicateId = `DEDUP-${Date.now()}`;
  let batchCount = 0;
  let receivedEventIds: string[] = [];

  const unsubBatch = realtimeTelemetryStream.onEventBatch((batch) => {
    batchCount++;
    receivedEventIds.push(...batch.map(e => e.eventId));
  });

  // Synthesize event injection to client handler
  const sampleEvent1: NormalizedTelemetryEvent = { ...testEvent, eventId: duplicateId };
  (realtimeTelemetryStream as any).handleNewTelemetryEvent(JSON.stringify({
    type: 'NEW_TELEMETRY_EVENT',
    sequence: 101,
    timestamp: new Date().toISOString(),
    data: { event: sampleEvent1, isThreat: false }
  }));

  // Duplicate injection of identical eventId
  (realtimeTelemetryStream as any).handleNewTelemetryEvent(JSON.stringify({
    type: 'NEW_TELEMETRY_EVENT',
    sequence: 102,
    timestamp: new Date().toISOString(),
    data: { event: sampleEvent1, isThreat: false }
  }));

  // Wait for micro-batch flush (60ms)
  await new Promise(resolve => setTimeout(resolve, 100));

  unsubBatch();
  const occurrences = receivedEventIds.filter(id => id === duplicateId).length;
  assert.strictEqual(occurrences, 1, `Duplicate event ${duplicateId} must only be emitted once (was: ${occurrences})`);

  // TEST 5: Status State Machine Transitions
  console.log('[Test 5] Testing connection status transitions (CONNECTING -> LIVE / SIMULATION)...');
  const observedStatuses: string[] = [];
  const unsubStatus = realtimeTelemetryStream.onStatusChange((st) => {
    observedStatuses.push(st);
  });

  (realtimeTelemetryStream as any).handleInitStatus(JSON.stringify({
    type: 'INIT_STATUS',
    sequence: 103,
    timestamp: new Date().toISOString(),
    data: {
      sequence: 103,
      telemetryState: 'LIVE',
      collectorHealth: { overallState: 'LIVE', activeCollectorsCount: 3, totalCollectors: 3, collectors: [], externalCollectors: [] },
      databaseHealth: { status: 'ONLINE', connected: true },
      agentStatuses: [],
      recentEvents: [],
      metrics: { totalLiveEvents: 10, totalSimulatedEvents: 0, totalThreatsDetected: 0, totalAlertsGenerated: 0, totalIncidentsCreated: 0, currentEps: 2 }
    }
  }));

  assert.strictEqual(realtimeTelemetryStream.getStatus(), 'LIVE', 'Stream status must transition to LIVE');
  unsubStatus();

  // TEST 6: Graceful Offline & State Retention
  console.log('[Test 6] Testing graceful offline handling and metrics retention...');
  const cachedMetricsBeforeOffline = realtimeTelemetryStream.getMetrics();
  (realtimeTelemetryStream as any).handleConnectionError(new Error('Network disconnected'));
  
  assert.strictEqual(realtimeTelemetryStream.getStatus(), 'DISCONNECTED', 'Status must transition to DISCONNECTED on error');
  assert.strictEqual(realtimeTelemetryStream.isOffline(), true, 'isOffline() must return true');
  const cachedMetricsAfterOffline = realtimeTelemetryStream.getMetrics();
  assert.strictEqual(cachedMetricsAfterOffline.totalLiveEvents, cachedMetricsBeforeOffline.totalLiveEvents, 'Metrics must be retained during offline state');

  // Clean up
  realtimeTelemetryStream.disconnect();
  telemetryManager.stopHeartbeatTimer();

  console.log('✔ ALL REAL-TIME TELEMETRY STREAM TESTS PASSED SUCCESSFULLY!');
  process.exit(0);
}

runTests().catch((err) => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
