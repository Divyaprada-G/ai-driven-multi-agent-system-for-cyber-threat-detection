import { LogEvent, NetworkFeatures } from '../types';
import { NetworkFeatureExtractor } from './networkFeatureExtractor';

export interface AnomalyScore {
  isAnomaly: boolean;
  score: number; // 0.00 to 1.00
  metric: 'VOLUME_BURST' | 'PORT_DISPERSION' | 'FREQUENCY_SPIKE' | 'FAILURE_RATE';
  observedValue: number;
  baselineMean: number;
  baselineStdDev: number;
  deviationMultiplier: number;
  reason: string;
}

export interface INetworkAnomalyDetector {
  trainBaseline(events: LogEvent[]): void;
  evaluateFlow(features: NetworkFeatures): AnomalyScore | null;
}

/**
 * Statistical Baseline Network Anomaly Detector.
 * Computes mean and standard deviation across normal traffic distributions.
 * Flags statistical outliers with explainable deviation metrics.
 * Designed as a pluggable abstraction where ML/clustering models can be substituted.
 */
export class StatisticalNetworkAnomalyDetector implements INetworkAnomalyDetector {
  private baseline = {
    avgConnectionsPerSource: 3.5,
    stdConnectionsPerSource: 2.1,
    avgPortsPerSource: 1.4,
    stdPortsPerSource: 0.8,
    avgFrequency: 0.8,
    stdFrequency: 0.6,
    sampleSize: 0
  };

  /**
   * Calculates statistical baselines from available event history
   */
  public trainBaseline(events: LogEvent[]): void {
    if (!events || events.length === 0) return;

    const sourceFeatures = NetworkFeatureExtractor.extractSourceFeatures(events);
    if (sourceFeatures.size === 0) return;

    const connectionCounts: number[] = [];
    const portCounts: number[] = [];
    const frequencies: number[] = [];

    for (const feat of sourceFeatures.values()) {
      connectionCounts.push(feat.connectionCount);
      portCounts.push(feat.uniqueDestinationPorts);
      frequencies.push(feat.connectionFrequency);
    }

    const n = sourceFeatures.size;
    const avgConn = connectionCounts.reduce((a, b) => a + b, 0) / n;
    const avgPorts = portCounts.reduce((a, b) => a + b, 0) / n;
    const avgFreq = frequencies.reduce((a, b) => a + b, 0) / n;

    const varConn = connectionCounts.reduce((sum, c) => sum + Math.pow(c - avgConn, 2), 0) / Math.max(1, n - 1);
    const varPorts = portCounts.reduce((sum, p) => sum + Math.pow(p - avgPorts, 2), 0) / Math.max(1, n - 1);
    const varFreq = frequencies.reduce((sum, f) => sum + Math.pow(f - avgFreq, 2), 0) / Math.max(1, n - 1);

    this.baseline = {
      avgConnectionsPerSource: Math.max(1, avgConn),
      stdConnectionsPerSource: Math.max(1, Math.sqrt(varConn)),
      avgPortsPerSource: Math.max(1, avgPorts),
      stdPortsPerSource: Math.max(0.5, Math.sqrt(varPorts)),
      avgFrequency: Math.max(0.2, avgFreq),
      stdFrequency: Math.max(0.2, Math.sqrt(varFreq)),
      sampleSize: n
    };
  }

  /**
   * Scores an extracted network feature set against calculated baselines
   */
  public evaluateFlow(features: NetworkFeatures): AnomalyScore | null {
    // 1. Connection frequency anomaly (burst)
    const freqThreshold = this.baseline.avgFrequency + 2.5 * this.baseline.stdFrequency;
    if (features.connectionFrequency > Math.max(5, freqThreshold) && features.connectionCount >= 6) {
      const zScore = (features.connectionFrequency - this.baseline.avgFrequency) / this.baseline.stdFrequency;
      const score = Math.min(0.95, Number((0.65 + Math.min(0.3, zScore * 0.05)).toFixed(2)));

      return {
        isAnomaly: true,
        score,
        metric: 'FREQUENCY_SPIKE',
        observedValue: features.connectionFrequency,
        baselineMean: Number(this.baseline.avgFrequency.toFixed(2)),
        baselineStdDev: Number(this.baseline.stdFrequency.toFixed(2)),
        deviationMultiplier: Number(zScore.toFixed(1)),
        reason: `Connection frequency (${features.connectionFrequency.toFixed(1)} req/s) is ${zScore.toFixed(1)} standard deviations above baseline (${this.baseline.avgFrequency.toFixed(1)} req/s)`
      };
    }

    // 2. Volume anomaly (unusually large number of requests from single host)
    const volumeThreshold = this.baseline.avgConnectionsPerSource + 3.0 * this.baseline.stdConnectionsPerSource;
    if (features.connectionCount > Math.max(15, volumeThreshold)) {
      const zScore = (features.connectionCount - this.baseline.avgConnectionsPerSource) / this.baseline.stdConnectionsPerSource;
      const score = Math.min(0.92, Number((0.60 + Math.min(0.32, zScore * 0.04)).toFixed(2)));

      return {
        isAnomaly: true,
        score,
        metric: 'VOLUME_BURST',
        observedValue: features.connectionCount,
        baselineMean: Number(this.baseline.avgConnectionsPerSource.toFixed(1)),
        baselineStdDev: Number(this.baseline.stdConnectionsPerSource.toFixed(1)),
        deviationMultiplier: Number(zScore.toFixed(1)),
        reason: `Observed connection volume (${features.connectionCount} events) exceeds baseline threshold by ${zScore.toFixed(1)}x std dev`
      };
    }

    // 3. Port dispersion anomaly
    const portThreshold = this.baseline.avgPortsPerSource + 2.5 * this.baseline.stdPortsPerSource;
    if (features.uniqueDestinationPorts >= 5 && features.uniqueDestinationPorts > portThreshold) {
      const zScore = (features.uniqueDestinationPorts - this.baseline.avgPortsPerSource) / this.baseline.stdPortsPerSource;
      const score = Math.min(0.95, Number((0.70 + Math.min(0.25, zScore * 0.05)).toFixed(2)));

      return {
        isAnomaly: true,
        score,
        metric: 'PORT_DISPERSION',
        observedValue: features.uniqueDestinationPorts,
        baselineMean: Number(this.baseline.avgPortsPerSource.toFixed(1)),
        baselineStdDev: Number(this.baseline.stdPortsPerSource.toFixed(1)),
        deviationMultiplier: Number(zScore.toFixed(1)),
        reason: `Contacted ${features.uniqueDestinationPorts} unique destination ports, exceeding port diversity baseline of ${this.baseline.avgPortsPerSource.toFixed(1)}`
      };
    }

    return null;
  }
}
