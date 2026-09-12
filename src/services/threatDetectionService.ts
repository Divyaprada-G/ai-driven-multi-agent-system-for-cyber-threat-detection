import { ThreatDetectionResult } from '../types';
import { INITIAL_THREAT_DETECTIONS } from './mockData';

export interface ThreatModelConfig {
  modelName: string;
  version: string;
  algorithm: string;
  status: 'ONLINE' | 'TRAINING' | 'OFFLINE';
  accuracy: number;
  f1Score: number;
  falsePositiveRate: number;
  eventsAnalyzedCount: number;
  threatsDetectedCount: number;
}

export interface IThreatDetectionService {
  getActiveModelInfo(): Promise<ThreatModelConfig>;
  getDetectionResults(): Promise<ThreatDetectionResult[]>;
  analyzeAnomaly(eventPayload: string): Promise<ThreatDetectionResult>;
}

class ThreatDetectionServiceImpl implements IThreatDetectionService {
  private detections: ThreatDetectionResult[] = [...INITIAL_THREAT_DETECTIONS];

  private modelInfo: ThreatModelConfig = {
    modelName: 'Multi-Agent Cyber Threat Ensemble (MA-CTE)',
    version: 'v2.4.1-rc',
    algorithm: 'Isolation Forest + LightGBM + Attention Sequence Classifier',
    status: 'ONLINE',
    accuracy: 97.4,
    f1Score: 96.1,
    falsePositiveRate: 1.8,
    eventsAnalyzedCount: 428950,
    threatsDetectedCount: 37
  };

  async getActiveModelInfo(): Promise<ThreatModelConfig> {
    return { ...this.modelInfo };
  }

  async getDetectionResults(): Promise<ThreatDetectionResult[]> {
    return [...this.detections];
  }

  async analyzeAnomaly(eventPayload: string): Promise<ThreatDetectionResult> {
    const newDetection: ThreatDetectionResult = {
      id: `TD-${Date.now().toString().slice(-3)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      threatDetected: true,
      threatType: 'Synthetic Behavioral Anomaly',
      category: 'Defense Evasion',
      confidence: 93.4,
      evidence: [
        'Payload length anomaly detected',
        'High entropy substring',
        'Signature pattern matched classifier heuristic'
      ],
      model: this.modelInfo.modelName,
      anomalyScore: 0.91,
      baselineDeviation: 4.1,
      predictedImpact: 'HIGH'
    };
    this.detections.unshift(newDetection);
    return newDetection;
  }
}

export const threatDetectionService: IThreatDetectionService = new ThreatDetectionServiceImpl();
