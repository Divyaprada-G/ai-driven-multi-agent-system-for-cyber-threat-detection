/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Scoring Engine Verification Test Suite
 *
 * Implements the 8 mandatory test cases defined in Prompt 08:
 * - Test 1: LOW severity + low confidence -> should produce low risk.
 * - Test 2: HIGH severity + high confidence -> should produce high risk.
 * - Test 3: CRITICAL severity + strong multi-agent correlation -> should produce critical/high risk.
 * - Test 4: Missing optional data -> system should still calculate a safe result.
 * - Test 5: Invalid confidence value -> system should handle it safely.
 * - Test 6: No correlated events -> system should not crash.
 * - Test 7: Multiple agents involved -> agent involvement should affect the score.
 * - Test 8: Same input repeated -> result must be deterministic.
 */

import { RiskScoringEngine } from './riskScoringEngine';
import { ThreatDetectionResult } from '../../types/threatDetection';
import { CorrelatedEvent } from '../../types/correlation';
import { AgentType } from '../../types';

export interface TestResultItem {
  id: string;
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
  details: string;
}

export interface VerificationSuiteSummary {
  timestamp: string;
  total: number;
  passed: number;
  failed: number;
  allPassed: boolean;
  results: TestResultItem[];
}

export function runRiskScoringTests(): VerificationSuiteSummary {
  const engine = new RiskScoringEngine();
  const results: TestResultItem[] = [];

  // -------------------------------------------------------------
  // Test 1: LOW severity + low confidence -> should produce low risk
  // -------------------------------------------------------------
  try {
    const threat: Partial<ThreatDetectionResult> = {
      id: 'TD-TEST-01',
      severity: 'LOW',
      confidence: 0.20,
      classification: 'BENIGN'
    };
    const assessment = engine.evaluate(threat);
    const passed = assessment.riskScore <= 35 && (assessment.riskBand === 'LOW' || assessment.priority === 'P4');
    results.push({
      id: 'TEST-1',
      name: 'LOW severity + low confidence produces low risk',
      passed,
      expected: 'Risk score <= 35 (LOW / P4)',
      actual: `Risk score = ${assessment.riskScore} (${assessment.riskBand} / ${assessment.priority})`,
      details: `Severity factor: ${assessment.riskFactors[0].rawScore}, Confidence factor: ${assessment.riskFactors[1].rawScore}`
    });
  } catch (err) {
    results.push({
      id: 'TEST-1',
      name: 'LOW severity + low confidence produces low risk',
      passed: false,
      expected: 'Risk score <= 35 (LOW / P4)',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed during evaluation.'
    });
  }

  // -------------------------------------------------------------
  // Test 2: HIGH severity + high confidence -> should produce high risk
  // -------------------------------------------------------------
  try {
    const threat: Partial<ThreatDetectionResult> = {
      id: 'TD-TEST-02',
      severity: 'HIGH',
      confidence: 0.90,
      classification: 'WEB_THREAT'
    };
    const assessment = engine.evaluate(threat);
    const passed = assessment.riskScore >= 55;
    results.push({
      id: 'TEST-2',
      name: 'HIGH severity + high confidence produces elevated/high risk',
      passed,
      expected: 'Risk score >= 55 (Elevated/High Band)',
      actual: `Risk score = ${assessment.riskScore} (${assessment.riskBand} / ${assessment.priority})`,
      details: `Severity contribution: ${assessment.riskFactors[0].weightedScore}, Confidence contribution: ${assessment.riskFactors[1].weightedScore}`
    });
  } catch (err) {
    results.push({
      id: 'TEST-2',
      name: 'HIGH severity + high confidence produces elevated/high risk',
      passed: false,
      expected: 'Risk score >= 55',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed during evaluation.'
    });
  }

  // -------------------------------------------------------------
  // Test 3: CRITICAL severity + strong multi-agent correlation -> should produce critical/high risk
  // -------------------------------------------------------------
  try {
    const correlation = {
      id: 'CORR-TEST-03',
      correlationId: 'CORR-TEST-03',
      createdAt: new Date().toISOString(),
      startTime: new Date().toISOString(),
      endTime: new Date().toISOString(),
      duration: '5m',
      findingIds: ['F-01', 'F-02', 'F-03'],
      eventIds: ['EVT-01', 'EVT-02'],
      eventsCount: 6,
      title: 'Distributed Multi-Stage Attack Sequence',
      attackPattern: 'MULTI_STAGE_KILL_CHAIN',
      summary: 'Multi-stage kill chain across network and system',
      description: 'Multi-stage kill chain across network and system',
      confidence: 98,
      correlationConfidence: 0.98,
      correlationStrength: 'HIGH' as const,
      severity: 'CRITICAL' as const,
      status: 'CORRELATED' as const,
      participatingAgents: ['NETWORK_AGENT', 'SYSTEM_AGENT', 'APPLICATION_AGENT'] as AgentType[],
      sources: ['suricata', 'sysmon', 'nginx'],
      sourceIps: ['192.168.1.105'],
      destinationIps: ['10.0.0.12'],
      hosts: ['domain-controller-01'],
      users: ['svc_admin'],
      eventTypes: ['PORT_SCAN', 'SQL_INJECTION', 'AUTH_FAILURE'],
      threatTypes: ['RECON', 'EXPLOIT', 'PRIV_ESC'],
      evidence: ['Port scan', 'SQL Injection', 'Token Impersonation'],
      indicators: ['192.168.1.105', 'svc_admin'],
      explanation: 'Temporal and identity overlap across endpoints',
      agentContributions: {
        network: 'Inbound port scan detected',
        system: 'Elevation token observed',
        application: 'SQL injection payload'
      }
    } as unknown as CorrelatedEvent;
    const threat: Partial<ThreatDetectionResult> = {
      id: 'TD-TEST-03',
      severity: 'CRITICAL',
      confidence: 0.96,
      classification: 'MULTI_STAGE_THREAT',
      correlationId: correlation.id
    };
    const assessment = engine.evaluate(threat, correlation);
    const passed = assessment.riskScore >= 80 && (assessment.riskBand === 'CRITICAL' || assessment.priority === 'P1');
    results.push({
      id: 'TEST-3',
      name: 'CRITICAL severity + strong multi-agent correlation produces critical risk',
      passed,
      expected: 'Risk score >= 80 (CRITICAL / P1)',
      actual: `Risk score = ${assessment.riskScore} (${assessment.riskBand} / ${assessment.priority})`,
      details: `Full multi-agent chain across 3 agents with ${assessment.evidenceVolume} evidence points`
    });
  } catch (err) {
    results.push({
      id: 'TEST-3',
      name: 'CRITICAL severity + strong multi-agent correlation produces critical risk',
      passed: false,
      expected: 'Risk score >= 80',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed during evaluation.'
    });
  }

  // -------------------------------------------------------------
  // Test 4: Missing optional data -> system should still calculate a safe result
  // -------------------------------------------------------------
  try {
    const emptyThreat: Partial<ThreatDetectionResult> = {};
    const assessment = engine.evaluate(emptyThreat, undefined);
    const passed =
      typeof assessment.riskScore === 'number' &&
      !isNaN(assessment.riskScore) &&
      assessment.riskScore >= 0 &&
      assessment.riskScore <= 100 &&
      assessment.riskFactors.length === 7;
    results.push({
      id: 'TEST-4',
      name: 'Missing optional data calculates safe non-null result without crashing',
      passed,
      expected: 'Valid numerical risk score 0..100 with 7 factors populated',
      actual: `Risk score = ${assessment.riskScore} (${assessment.riskBand}), Factors = ${assessment.riskFactors.length}`,
      details: 'Gracefully handled empty object {} with no fields provided'
    });
  } catch (err) {
    results.push({
      id: 'TEST-4',
      name: 'Missing optional data calculates safe non-null result without crashing',
      passed: false,
      expected: 'Safe fallback result',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Crash on missing optional data'
    });
  }

  // -------------------------------------------------------------
  // Test 5: Invalid confidence value -> system should handle it safely
  // -------------------------------------------------------------
  try {
    const threatNegative: Partial<ThreatDetectionResult> = { confidence: -50 };
    const threatOver100: Partial<ThreatDetectionResult> = { confidence: 999 };
    const threatNaN: Partial<ThreatDetectionResult> = { confidence: NaN };

    const a1 = engine.evaluate(threatNegative);
    const a2 = engine.evaluate(threatOver100);
    const a3 = engine.evaluate(threatNaN);

    const passed =
      !isNaN(a1.confidence) &&
      a1.confidence >= 0 &&
      !isNaN(a2.confidence) &&
      a2.confidence <= 100 &&
      !isNaN(a3.confidence);
    results.push({
      id: 'TEST-5',
      name: 'Invalid confidence values handled safely (-50, 999, NaN)',
      passed,
      expected: 'Sanitized confidence scores clamped to 0..100 without NaN',
      actual: `[-50 -> ${a1.confidence}], [999 -> ${a2.confidence}], [NaN -> ${a3.confidence}]`,
      details: 'All out-of-range and invalid confidence inputs safely normalized'
    });
  } catch (err) {
    results.push({
      id: 'TEST-5',
      name: 'Invalid confidence values handled safely',
      passed: false,
      expected: 'Safe sanitation',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed handling invalid confidence'
    });
  }

  // -------------------------------------------------------------
  // Test 6: No correlated events -> system should not crash
  // -------------------------------------------------------------
  try {
    const threat: Partial<ThreatDetectionResult> = {
      id: 'TD-ISOLATED',
      severity: 'MEDIUM',
      confidence: 0.70
    };
    const assessment = engine.evaluate(threat, undefined);
    const passed =
      assessment.correlationId === 'CORR-ISOLATED' &&
      assessment.riskFactors.find(f => f.name === 'correlationStrength')?.rawScore === 20;
    results.push({
      id: 'TEST-6',
      name: 'No correlated events evaluates with baseline factor without crashing',
      passed,
      expected: 'Fallback correlationId and nominal baseline factor (20 pts)',
      actual: `Correlation ID = ${assessment.correlationId}, Factor = ${assessment.riskFactors.find(f => f.name === 'correlationStrength')?.rawScore}`,
      details: 'Isolated event successfully processed without multi-agent correlation cluster'
    });
  } catch (err) {
    results.push({
      id: 'TEST-6',
      name: 'No correlated events evaluates with baseline factor without crashing',
      passed: false,
      expected: 'No crash',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Crash on undefined correlation'
    });
  }

  // -------------------------------------------------------------
  // Test 7: Multiple agents involved -> agent involvement affects score
  // -------------------------------------------------------------
  try {
    const singleAgentThreat: Partial<ThreatDetectionResult> = {
      severity: 'HIGH',
      confidence: 0.85,
      features: {
        networkInvolvement: 1,
        systemInvolvement: 0,
        applicationInvolvement: 0
      } as any
    };

    const multiAgentThreat: Partial<ThreatDetectionResult> = {
      severity: 'HIGH',
      confidence: 0.85,
      features: {
        networkInvolvement: 1,
        systemInvolvement: 1,
        applicationInvolvement: 1
      } as any
    };

    const singleAssessment = engine.evaluate(singleAgentThreat);
    const multiAssessment = engine.evaluate(multiAgentThreat);

    const singleAgentFactor = singleAssessment.riskFactors.find(f => f.name === 'agentInvolvement')?.rawScore || 0;
    const multiAgentFactor = multiAssessment.riskFactors.find(f => f.name === 'agentInvolvement')?.rawScore || 0;

    const passed = multiAgentFactor > singleAgentFactor && multiAssessment.riskScore > singleAssessment.riskScore;
    results.push({
      id: 'TEST-7',
      name: 'Multiple agents involved proportionally increases risk score',
      passed,
      expected: '3 Agents Risk Score > 1 Agent Risk Score',
      actual: `1 Agent Score = ${singleAssessment.riskScore} (factor: ${singleAgentFactor}) vs 3 Agents Score = ${multiAssessment.riskScore} (factor: ${multiAgentFactor})`,
      details: `Score differential: +${multiAssessment.riskScore - singleAssessment.riskScore} pts due to multi-agent corroboration`
    });
  } catch (err) {
    results.push({
      id: 'TEST-7',
      name: 'Multiple agents involved proportionally increases risk score',
      passed: false,
      expected: 'Higher score for 3 agents',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed comparing agent involvement'
    });
  }

  // -------------------------------------------------------------
  // Test 8: Same input repeated -> result must be deterministic
  // -------------------------------------------------------------
  try {
    const testThreat: Partial<ThreatDetectionResult> = {
      id: 'TD-DETERMINISTIC',
      severity: 'HIGH',
      confidence: 0.88,
      classification: 'AUTHENTICATION_THREAT'
    };

    const run1 = engine.evaluate(testThreat);
    const run2 = engine.evaluate(testThreat);
    const run3 = engine.evaluate(testThreat);

    const isDeterministic =
      run1.riskScore === run2.riskScore &&
      run2.riskScore === run3.riskScore &&
      run1.priority === run2.priority &&
      run1.riskBand === run2.riskBand &&
      JSON.stringify(run1.riskFactors) === JSON.stringify(run2.riskFactors);

    results.push({
      id: 'TEST-8',
      name: 'Same input repeated produces identical deterministic output',
      passed: isDeterministic,
      expected: 'Exact identical scores and factors across multiple runs',
      actual: `Run 1: ${run1.riskScore}, Run 2: ${run2.riskScore}, Run 3: ${run3.riskScore}`,
      details: 'Verified no random numbers or fluctuating state affects risk evaluation'
    });
  } catch (err) {
    results.push({
      id: 'TEST-8',
      name: 'Same input repeated produces identical deterministic output',
      passed: false,
      expected: 'Deterministic outputs',
      actual: `Threw error: ${err instanceof Error ? err.message : String(err)}`,
      details: 'Failed deterministic test'
    });
  }

  const passedCount = results.filter(r => r.passed).length;

  return {
    timestamp: new Date().toISOString(),
    total: results.length,
    passed: passedCount,
    failed: results.length - passedCount,
    allPassed: passedCount === results.length,
    results
  };
}
