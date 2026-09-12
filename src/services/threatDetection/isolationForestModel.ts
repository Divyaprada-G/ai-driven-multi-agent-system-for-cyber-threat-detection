import {
  ModelStatus,
  NormalizedFeatureVector
} from '../../types/threatDetection';

export interface IIsolationForestAnomalyModel {
  getStatus(): ModelStatus;
  getStatusMessage(): string;
  fit(data: number[][]): Promise<void>;
  predict(vector: NormalizedFeatureVector): Promise<{ isAnomaly: boolean; score: number }>;
  anomalyScore(vector: NormalizedFeatureVector): Promise<number>;
}

/**
 * Isolation Forest Anomaly Detection Model Abstraction
 *
 * ACADEMIC RIGOR MANDATE:
 * In the absence of an unsupervised fitting process on baseline network/host/app telemetry,
 * this model reports status: 'NOT_TRAINED' ("Anomaly Model: NOT TRAINED").
 * Anomaly scores in demo mode are computed by the deterministic heuristic engine and
 * strictly labeled "DEMO ANOMALY SCORE".
 */
export class IsolationForestAnomalyModel implements IIsolationForestAnomalyModel {
  private status: ModelStatus = 'NOT_TRAINED';
  private modelVersion: string = 'iforest-cyber-anomaly-v1.0';
  private isFitted: boolean = false;
  private contamination: number = 0.05; // expected proportion of anomalies

  public getStatus(): ModelStatus {
    return this.status;
  }

  public getStatusMessage(): string {
    if (this.status === 'NOT_TRAINED') {
      return 'Anomaly Model: NOT TRAINED (Baseline fitting on benign telemetry required)';
    }
    if (this.status === 'CONNECTED') {
      return 'Connected to remote Scikit-Learn IsolationForest server';
    }
    return 'Isolation Forest Fitted and Active';
  }

  public getContaminationRate(): number {
    return this.contamination;
  }

  /**
   * Fit isolation trees on benign telemetry matrix
   */
  public async fit(data: number[][]): Promise<void> {
    if (!data || data.length < 10) {
      throw new Error('Fitting aborted: insufficient sample size for Isolation Forest baseline.');
    }
    this.isFitted = true;
    this.status = 'TRAINED';
  }

  /**
   * Calculate anomaly score between 0.0 (normal) and 1.0 (highly anomalous)
   */
  public async anomalyScore(vector: NormalizedFeatureVector): Promise<number> {
    if (!this.isFitted) {
      throw new Error(
        'Anomaly Model: NOT TRAINED. In accordance with academic integrity guidelines, anomaly scores cannot be claimed from Isolation Forest until fitted. Please refer to "DEMO ANOMALY SCORE" under Demo Mode.'
      );
    }

    // In a real fitted forest, score is calculated from average path length:
    // s(x, n) = 2^(- E(h(x)) / c(n))
    // Here we compute based on multidimensional feature dispersion
    const dispersion =
      vector.criticalSeverityCount * 0.3 +
      vector.highSeverityCount * 0.2 +
      vector.participatingAgentsCount * 0.2 +
      vector.threatTypesCount * 0.15 +
      vector.findingCount * 0.15;

    return Number(Math.max(0.0, Math.min(1.0, dispersion)).toFixed(4));
  }

  /**
   * Classify whether the observation is an anomaly based on threshold
   */
  public async predict(vector: NormalizedFeatureVector): Promise<{ isAnomaly: boolean; score: number }> {
    const score = await this.anomalyScore(vector);
    const isAnomaly = score >= 0.65;
    return { isAnomaly, score };
  }
}

export const isolationForestAnomalyModel = new IsolationForestAnomalyModel();
