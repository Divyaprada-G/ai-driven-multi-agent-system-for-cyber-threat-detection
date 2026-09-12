/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Prepared n8n Automation Webhook Payload Generator
 *
 * NOTE: As explicitly mandated, this is ONLY payload structure preparation.
 * No external network requests, n8n webhook triggers, or automated remediation
 * workflows are dispatched in this stage.
 */

import { RiskAssessment, N8nPreparedPayload } from '../../types/riskScoring';

export class N8nPayloadGenerator {
  /**
   * Generates clean, normalized JSON payload ready for future n8n Webhook / Dispatcher ingestion.
   */
  public static generatePayload(assessment: RiskAssessment): N8nPreparedPayload {
    return {
      riskAssessmentId: assessment.id,
      threatDetectionId: assessment.threatDetectionId,
      correlationId: assessment.correlationId,
      riskScore: assessment.riskScore,
      severity: assessment.severity,
      priority: assessment.priority,
      threatClassification: String(assessment.threatClassification),
      // Scale confidence back to 0.0 - 1.0 probability float for standard webhook schema
      confidence: Math.round((assessment.confidence / 100) * 1000) / 1000,
      timestamp: assessment.timestamp,
      recommendedAction: assessment.recommendedAction,
      participatingAgents: assessment.participatingAgents,
      affectedSource: assessment.affectedSource,
      status: assessment.status,
      exportTimestamp: new Date().toISOString(),
      systemVersion: 'CyberSOC-Stage8-v1.0'
    };
  }

  /**
   * Generates formatted, indented JSON string for preview / copy in UI.
   */
  public static generatePrettyJson(assessment: RiskAssessment): string {
    const payload = this.generatePayload(assessment);
    return JSON.stringify(payload, null, 2);
  }
}
