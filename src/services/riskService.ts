import { RiskAssessment, SeverityLevel } from '../types';
import { INITIAL_RISK_ASSESSMENTS } from './mockData';

export interface IRiskService {
  getRiskAssessments(): Promise<RiskAssessment[]>;
  getRiskById(id: string): Promise<RiskAssessment | undefined>;
  calculateRiskScore(factors: {
    assetCriticality: number;
    exploitability: number;
    lateralMovementPotential: number;
    dataLossExposure: number;
  }): Promise<{ score: number; severity: SeverityLevel }>;
}

class RiskServiceImpl implements IRiskService {
  private assessments: RiskAssessment[] = [...INITIAL_RISK_ASSESSMENTS];

  async getRiskAssessments(): Promise<RiskAssessment[]> {
    return [...this.assessments];
  }

  async getRiskById(id: string): Promise<RiskAssessment | undefined> {
    return this.assessments.find(a => a.id === id);
  }

  async calculateRiskScore(factors: {
    assetCriticality: number;
    exploitability: number;
    lateralMovementPotential: number;
    dataLossExposure: number;
  }): Promise<{ score: number; severity: SeverityLevel }> {
    // Weighted risk formula placeholder
    const score = Math.round(
      factors.assetCriticality * 0.35 +
      factors.exploitability * 0.25 +
      factors.lateralMovementPotential * 0.20 +
      factors.dataLossExposure * 0.20
    );

    let severity: SeverityLevel = 'LOW';
    if (score >= 90) severity = 'CRITICAL';
    else if (score >= 75) severity = 'HIGH';
    else if (score >= 50) severity = 'MEDIUM';

    return { score, severity };
  }
}

export const riskService: IRiskService = new RiskServiceImpl();
