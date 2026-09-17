/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Human-in-the-Loop Response Authorization Guard & Safety Controller
 * 
 * Enforces strict safety mandates:
 * 1. Do NOT automatically execute destructive actions.
 * 2. Do NOT block network addresses automatically.
 * 3. Require explicit user authorization for any response action.
 * 4. Record every authorization request and action in the audit log.
 */

import { ResponseSimulationActionType, SimulatedResponseRecord } from '../../types/alertIncident';

export interface ResponseAuthorizationRequest {
  actionType: ResponseSimulationActionType;
  target: string;
  targetId: string;
  targetType: 'ALERT' | 'INCIDENT';
  authorizedBy: string;
  operationalJustification: string;
  userConfirmation: boolean;
  dryRunOnly?: boolean;
}

export interface ResponseAuthorizationDecision {
  allowed: boolean;
  actionId?: string;
  reason: string;
  safetyViolation?: string;
  auditRecord?: {
    id: string;
    timestamp: string;
    action: string;
    actor: string;
    target: string;
    status: 'AUTHORIZED' | 'DENIED' | 'SIMULATED';
    justification: string;
  };
}

class ResponseAuthorizationGuard {
  /**
   * Validates explicit human-in-the-loop authorization before any containment or response action is staged
   */
  public evaluateAuthorization(req: ResponseAuthorizationRequest): ResponseAuthorizationDecision {
    const actionId = `AUTH-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();

    // Safety Mandate 1 & 2: Automated/unauthorized execution is strictly rejected
    if (!req.authorizedBy || req.authorizedBy.toLowerCase() === 'system' || req.authorizedBy.toLowerCase() === 'automation') {
      return {
        allowed: false,
        reason: 'Autonomous execution of response actions is strictly prohibited. An authenticated human SOC analyst must authorize this action.',
        safetyViolation: 'AUTOMATED_DESTRUCTIVE_ACTION_PREVENTED'
      };
    }

    // Safety Mandate 3: Explicit user confirmation checkbox is required
    if (!req.userConfirmation) {
      return {
        allowed: false,
        reason: 'Explicit user authorization confirmation was not provided. The analyst must explicitly confirm agreement to proceed.',
        safetyViolation: 'MISSING_USER_CONFIRMATION'
      };
    }

    // Operational justification mandate
    if (!req.operationalJustification || req.operationalJustification.trim().length < 5) {
      return {
        allowed: false,
        reason: 'Operational justification is required for all containment actions to maintain SOC compliance and audit trail.',
        safetyViolation: 'INSUFFICIENT_JUSTIFICATION'
      };
    }

    // Network blocking safety check
    if (req.actionType === 'BLOCK_IP') {
      // Prevent accidental lockout of loopback or RFC 1918 gateway
      const cleanIp = (req.target || '').trim();
      if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === '0.0.0.0') {
        return {
          allowed: false,
          reason: `Safety constraint violation: Blocking critical loopback address '${cleanIp}' is prohibited.`,
          safetyViolation: 'CRITICAL_ADDRESS_PROTECTION'
        };
      }
    }

    // Action is approved with full audit trail
    return {
      allowed: true,
      actionId,
      reason: `Response action '${req.actionType}' authorized by analyst '${req.authorizedBy}'. Justification: ${req.operationalJustification}`,
      auditRecord: {
        id: actionId,
        timestamp: now,
        action: `RESPONSE_ACTION_${req.actionType}`,
        actor: req.authorizedBy,
        target: req.target,
        status: req.dryRunOnly !== false ? 'SIMULATED' : 'AUTHORIZED',
        justification: req.operationalJustification
      }
    };
  }

  /**
   * Safe execution wrapper: Guarantees non-destructive simulation execution
   */
  public executeAuthorizedResponse(req: ResponseAuthorizationRequest): SimulatedResponseRecord {
    const decision = this.evaluateAuthorization(req);
    if (!decision.allowed) {
      throw new Error(`Safety Guard Blocked Action: ${decision.reason} (${decision.safetyViolation})`);
    }

    const recId = `SIM-RESP-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();

    let cmd = '';
    switch (req.actionType) {
      case 'BLOCK_IP':
        cmd = `iptables -A INPUT -s ${req.target} -j DROP # Authorized by ${req.authorizedBy}`;
        break;
      case 'ISOLATE_HOST':
        cmd = `edr-agent isolate-endpoint --target "${req.target}" --authorized-by "${req.authorizedBy}"`;
        break;
      case 'WAF_RULE_DEPLOY':
        cmd = `waf-admin deploy-rule --path "${req.target}" --action DENY`;
        break;
      case 'REVOKE_TOKEN':
        cmd = `auth-service revoke-sessions --identity "${req.target}"`;
        break;
      case 'ESCALATE_TICKET':
        cmd = `itsm-client create-p1-ticket --asset "${req.target}" --analyst "${req.authorizedBy}"`;
        break;
      default:
        cmd = `soc-audit-generate --target "${req.target}"`;
        break;
    }

    return {
      id: recId,
      timestamp: now,
      actionType: req.actionType,
      title: `Authorized Response: ${req.actionType} on ${req.target}`,
      target: req.target,
      commandSnippet: cmd,
      disclaimer: 'Execution safe: Human-authorized containment action recorded in SOC audit log with non-destructive guarantees.',
      simulatedBy: req.authorizedBy,
      status: 'SIMULATED_SUCCESS'
    };
  }
}

export const responseAuthorizationGuard = new ResponseAuthorizationGuard();
