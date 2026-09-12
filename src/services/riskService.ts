/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Scoring & Prioritization Service Layer
 */

import { SeverityLevel } from '../types';
import { ThreatDetectionResult } from '../types/threatDetection';
import { CorrelatedEvent } from '../types/correlation';
import {
  RiskAssessment,
  RiskModelConfig,
  RiskStatus
} from '../types/riskScoring';
import { RISK_CONFIG } from './riskScoring/riskConfig';
import { RiskScoringEngine, riskScoringEngine } from './riskScoring/riskScoringEngine';
import { INITIAL_THREAT_DETECTIONS, INITIAL_CORRELATIONS } from './mockData';

export interface IRiskService {
  getRiskAssessments(): Promise<RiskAssessment[]>;
  getRiskById(id: string): Promise<RiskAssessment | undefined>;
  assessThreatDetections(
    threats?: ThreatDetectionResult[],
    correlations?: CorrelatedEvent[]
  ): Promise<RiskAssessment[]>;
  updateAssessmentStatus(id: string, newStatus: RiskStatus): Promise<boolean>;
  recalculateWithCustomConfig(newConfig: RiskModelConfig): Promise<RiskAssessment[]>;
  getRiskConfig(): RiskModelConfig;
  calculateRiskScore(factors: {
    assetCriticality: number;
    exploitability: number;
    lateralMovementPotential: number;
    dataLossExposure: number;
  }): Promise<{ score: number; severity: SeverityLevel }>;
}

class RiskServiceImpl implements IRiskService {
  private engine: RiskScoringEngine;
  private assessments: RiskAssessment[] = [];
  private isInitialized = false;

  constructor() {
    this.engine = riskScoringEngine;
    this.initializeAssessments();
  }

  private initializeAssessments(): void {
    if (this.isInitialized && this.assessments.length > 0) return;

    // Evaluate initial threats with their respective correlation clusters
    const initialList: RiskAssessment[] = [];

    INITIAL_THREAT_DETECTIONS.forEach((threat, idx) => {
      const corr = INITIAL_CORRELATIONS.find(c => c.id === threat.correlationId) || INITIAL_CORRELATIONS[idx % INITIAL_CORRELATIONS.length];
      const assessment = this.engine.evaluate(threat, corr);
      initialList.push(assessment);
    });

    // Also evaluate remaining correlations if any don't have detections yet
    INITIAL_CORRELATIONS.forEach((corr, idx) => {
      if (!initialList.some(a => a.correlationId === corr.id)) {
        const dummyThreat: Partial<ThreatDetectionResult> = {
          id: `TD-CORR-${idx + 500}`,
          correlationId: corr.id,
          timestamp: corr.timestamp,
          threatDetected: true,
          classification: 'MULTI_STAGE_THREAT',
          confidence: corr.confidence,
          severity: corr.severity,
          model: 'Rule-Based Demo Engine (Heuristic Simulator)',
          evidence: corr.evidence || []
        };
        const assessment = this.engine.evaluate(dummyThreat, corr);
        initialList.push(assessment);
      }
    });

    this.assessments = initialList;
    this.isInitialized = true;
  }

  async getRiskAssessments(): Promise<RiskAssessment[]> {
    this.initializeAssessments();
    // Return sorted by priority (P1 first, then highest risk score)
    return [...this.assessments].sort((a, b) => {
      const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 };
      if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      }
      return b.riskScore - a.riskScore;
    });
  }

  async getRiskById(id: string): Promise<RiskAssessment | undefined> {
    this.initializeAssessments();
    return this.assessments.find(a => a.id === id || a.threatDetectionId === id);
  }

  async assessThreatDetections(
    threats: ThreatDetectionResult[] = INITIAL_THREAT_DETECTIONS,
    correlations: CorrelatedEvent[] = INITIAL_CORRELATIONS
  ): Promise<RiskAssessment[]> {
    const computed = threats.map(threat => {
      const matchingCorr = correlations.find(c => c.id === threat.correlationId);
      return this.engine.evaluate(threat, matchingCorr);
    });

    // Merge or update local assessments cache
    computed.forEach(newAss => {
      const existingIdx = this.assessments.findIndex(a => a.id === newAss.id || a.threatDetectionId === newAss.threatDetectionId);
      if (existingIdx >= 0) {
        // preserve user modified status if already touched
        const prevStatus = this.assessments[existingIdx].status;
        this.assessments[existingIdx] = { ...newAss, status: prevStatus !== 'NEW' ? prevStatus : newAss.status };
      } else {
        this.assessments.push(newAss);
      }
    });

    return this.getRiskAssessments();
  }

  async updateAssessmentStatus(id: string, newStatus: RiskStatus): Promise<boolean> {
    this.initializeAssessments();
    const target = this.assessments.find(a => a.id === id);
    if (!target) return false;
    target.status = newStatus;
    return true;
  }

  async recalculateWithCustomConfig(newConfig: RiskModelConfig): Promise<RiskAssessment[]> {
    this.engine.setConfig(newConfig);
    // Re-evaluate all current assessments using existing threat/corr links
    this.assessments = this.assessments.map(item => {
      const threat: Partial<ThreatDetectionResult> = {
        id: item.threatDetectionId,
        correlationId: item.correlationId,
        timestamp: item.timestamp,
        threatDetected: true,
        severity: item.severity,
        confidence: item.confidence / 100,
        classification: item.threatClassification as any
      };
      const matchingCorr = INITIAL_CORRELATIONS.find(c => c.id === item.correlationId);
      const reevaluated = this.engine.evaluate(threat, matchingCorr, item.status);
      return {
        ...reevaluated,
        id: item.id, // maintain stable id
        status: item.status // maintain status
      };
    });

    return this.getRiskAssessments();
  }

  getRiskConfig(): RiskModelConfig {
    return this.engine.getConfig();
  }

  /**
   * Backward-compatible calculator for interactive sliders in RiskAnalysisPage
   */
  async calculateRiskScore(factors: {
    assetCriticality: number;
    exploitability: number;
    lateralMovementPotential: number;
    dataLossExposure: number;
  }): Promise<{ score: number; severity: SeverityLevel }> {
    const score = Math.round(
      factors.assetCriticality * 0.35 +
      factors.exploitability * 0.25 +
      factors.lateralMovementPotential * 0.20 +
      factors.dataLossExposure * 0.20
    );

    let severity: SeverityLevel = 'LOW';
    if (score >= 81) severity = 'CRITICAL';
    else if (score >= 61) severity = 'HIGH';
    else if (score >= 31) severity = 'MEDIUM';

    return { score, severity };
  }
}

export const riskService: IRiskService = new RiskServiceImpl();
