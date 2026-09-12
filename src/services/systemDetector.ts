import {
  LogEvent,
  SystemAgentResult,
  SeverityLevel,
  SystemThreatType,
  SystemAgentClassification
} from '../types';
import { SystemFeatureExtractor } from './systemFeatureExtractor';

// Known suspicious LOLBIN and credential dumping signatures
const SUSPICIOUS_PROCESS_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  severity: SeverityLevel;
  confidence: number;
  reason: string;
}> = [
  {
    pattern: /mimikatz|sekurlsa|kerberos::list|lsadump/i,
    name: 'Credential Dumping Tool (Mimikatz signature)',
    severity: 'CRITICAL',
    confidence: 0.95,
    reason: 'Tool commonly used for extracting plaintext passwords, Kerberos tickets, and hashes from LSASS memory.'
  },
  {
    pattern: /procdump.*lsass/i,
    name: 'LSASS Memory Dump via ProcDump',
    severity: 'CRITICAL',
    confidence: 0.95,
    reason: 'Process memory dumping utility targeting Local Security Authority Subsystem Service (LSASS).'
  },
  {
    pattern: /vssadmin(?:\.exe)?\s+delete\s+shadows/i,
    name: 'Shadow Copy Deletion (vssadmin)',
    severity: 'CRITICAL',
    confidence: 0.95,
    reason: 'Volume Shadow Copy deletion typically performed by ransomware prior to file encryption.'
  },
  {
    pattern: /powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)\s+[a-zA-Z0-9+/=]{15,}/i,
    name: 'Encoded PowerShell Execution',
    severity: 'HIGH',
    confidence: 0.90,
    reason: 'Base64-encoded command execution used to evade script-block logging and string inspection.'
  },
  {
    pattern: /certutil(?:\.exe)?\s+-(?:urlcache|f)\s+-split/i,
    name: 'Certutil Living-off-the-Land Ingress Tool',
    severity: 'HIGH',
    confidence: 0.88,
    reason: 'Abuse of native Windows certificate utility to download remote malicious binaries.'
  },
  {
    pattern: /(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh)/i,
    name: 'Direct Remote Script Piping to Shell',
    severity: 'HIGH',
    confidence: 0.90,
    reason: 'Executing untrusted shell scripts directly from remote web endpoints without local verification.'
  },
  {
    pattern: /nc(?:\.traditional)?\s+.*-e\s+(?:\/bin\/sh|\/bin\/bash|cmd\.exe)/i,
    name: 'Netcat Reverse / Bind Shell',
    severity: 'CRITICAL',
    confidence: 0.94,
    reason: 'Netcat command configured with interactive executable attachment providing remote shell access.'
  },
  {
    pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp\//i,
    name: 'Bash Native Reverse TCP Shell',
    severity: 'CRITICAL',
    confidence: 0.94,
    reason: 'Direct interactive bash redirection to remote IP socket typical of remote web application exploit payloads.'
  },
  {
    pattern: /whoami(?:\.exe)?\s+\/priv/i,
    name: 'Privilege Enumeration (whoami /priv)',
    severity: 'MEDIUM',
    confidence: 0.80,
    reason: 'User privilege enumeration frequently executed during initial post-exploitation reconnaissance.'
  },
  {
    pattern: /net(?:\.exe)?\s+(?:user\s+.*\/add|localgroup\s+administrators\s+.*\/add)/i,
    name: 'Local Administrator Account Creation',
    severity: 'CRITICAL',
    confidence: 0.95,
    reason: 'Command creating unauthorized user or adding account directly to local Administrators group.'
  },
  {
    pattern: /(?:\/tmp\/|\/dev\/shm\/)[a-zA-Z0-9._-]+\.(?:sh|py|pl|elf|bin)/i,
    name: 'Executable Script in Volatile/World-Writable Directory',
    severity: 'HIGH',
    confidence: 0.84,
    reason: 'Execution from /tmp or /dev/shm directory frequently used to bypass standard write restrictions.'
  }
];

// Suspicious parent-child process execution pairs
const SUSPICIOUS_PARENTS: Array<{
  parent: RegExp;
  child: RegExp;
  name: string;
  severity: SeverityLevel;
  confidence: number;
  reason: string;
}> = [
  {
    parent: /w3wp\.exe|nginx|httpd|apache2|tomcat/i,
    child: /cmd\.exe|powershell\.exe|sh|bash/i,
    name: 'Web Server Spawning Interactive Shell',
    severity: 'CRITICAL',
    confidence: 0.95,
    reason: 'Web daemon process spawned a command shell, indicating potential remote code execution (web shell).'
  },
  {
    parent: /sqlservr\.exe|mysqld|postgres/i,
    child: /cmd\.exe|powershell\.exe|sh|bash/i,
    name: 'Database Engine Spawning Shell',
    severity: 'HIGH',
    confidence: 0.90,
    reason: 'Database process invoked command shell, indicating potential SQL injection with xp_cmdshell or equivalent.'
  },
  {
    parent: /WINWORD\.EXE|EXCEL\.EXE|POWERPNT\.EXE/i,
    child: /powershell\.exe|cmd\.exe|cscript\.exe|wscript\.exe/i,
    name: 'Office Application Spawning Command Interpreter',
    severity: 'CRITICAL',
    confidence: 0.93,
    reason: 'Document editor initiated script execution, characteristic of weaponized malicious macro attachment.'
  }
];

export class SystemDetector {
  /**
   * Main system security analysis pipeline.
   * Consumes normalized LogEvents, extracts system features, evaluates heuristics,
   * and produces explainable SystemAgentResult records.
   */
  public analyze(events: LogEvent[]): SystemAgentResult[] {
    if (!events || events.length === 0) {
      return [];
    }

    const results: SystemAgentResult[] = [];
    const processedEventIds = new Set<string>();

    const userMap = SystemFeatureExtractor.extractUserAuthFeatures(events);
    const hostMap = SystemFeatureExtractor.extractHostTelemetryFeatures(events);

    // -------------------------------------------------------------
    // RULE 1: SUSPICIOUS AUTHENTICATION SEQUENCE (SUCCESS AFTER FAILURES)
    // Multiple failed logins followed by a successful login within window
    // -------------------------------------------------------------
    for (const [username, userFeat] of userMap.entries()) {
      if (userFeat.hasSuccessAfterFailures && userFeat.successAfterFailuresDetails) {
        const details = userFeat.successAfterFailuresDetails;
        const resultId = `sys-seq-${username}-${details.successTime}`;

        // Find the event ID of the success event
        const successEventId = userFeat.eventIds[userFeat.eventIds.length - 1];
        processedEventIds.add(successEventId);

        results.push({
          id: resultId,
          agentId: 'SYSTEM_AGENT',
          eventId: successEventId,
          timestamp: details.successTime,
          detection: 'Suspicious Authentication Sequence (Success After Failures)',
          threatDetected: true,
          threatType: 'SUSPICIOUS_AUTH_SEQUENCE',
          severity: 'HIGH',
          confidence: 0.88,
          classification: 'THREAT',
          username,
          host: details.host || 'unknown_host',
          sourceIp: details.sourceIp,
          eventType: 'AUTH_SUCCESS',
          evidence: [
            `User "${username}" experienced ${details.failedCount} consecutive failed login attempts before a successful authentication.`,
            `First recorded failure at ${details.firstFailureTime}. Successful authentication at ${details.successTime}.`,
            `Time elapsed between first failure and success: ${details.timeDeltaSeconds} seconds.`,
            details.sourceIp ? `Authentication source IP: ${details.sourceIp}.` : 'Source IP not specified in log payload.',
            `Host targeted: ${details.host || 'unknown_host'}.`
          ],
          indicators: [
            'Consecutive Authentication Failures',
            'Subsequent Successful Authentication',
            `Failed Count: ${details.failedCount}`,
            `Time Window: ${details.timeDeltaSeconds}s`
          ],
          observedActivity: `Account "${username}" recorded ${details.failedCount} failed logins immediately followed by successful logon on host "${details.host || 'unknown_host'}".`,
          detectedPattern: `Sequence of repeated authentication failures culminating in successful access within ${details.timeDeltaSeconds} seconds.`,
          securityFinding: 'Potential brute-force attack or credential guessing sequence resulting in successful system access.',
          recommendedAction: 'Verify legitimacy with account owner immediately; audit active session commands; review source IP address.',
          status: 'NEW'
        });
      }
    }

    // -------------------------------------------------------------
    // RULE 2: REPEATED AUTHENTICATION FAILURES & BRUTE FORCE
    // High volume of failed login attempts for a single user or targeting a host
    // -------------------------------------------------------------
    for (const [username, userFeat] of userMap.entries()) {
      // Exclude if already flagged under success-after-failures or if failures < 3
      if (userFeat.failedAttempts >= 3) {
        const isHighVolume = userFeat.failedAttempts >= 5;
        const threatType: SystemThreatType = isHighVolume ? 'BRUTE_FORCE' : 'REPEATED_AUTH_FAILURES';
        const severity: SeverityLevel = isHighVolume ? 'HIGH' : 'MEDIUM';
        const confidence = isHighVolume ? 0.90 : 0.78;
        const classification: SystemAgentClassification = isHighVolume ? 'THREAT' : 'SUSPICIOUS';
        const detectionName = isHighVolume ? 'Potential Brute Force Activity' : 'Repeated Authentication Failures';

        const lastFailTime = userFeat.failureTimestamps[userFeat.failureTimestamps.length - 1];
        const lastFailIso = lastFailTime ? new Date(lastFailTime).toISOString() : new Date().toISOString();
        const hostsList = Array.from(userFeat.hosts).join(', ') || 'unknown_host';
        const ipsList = Array.from(userFeat.sourceIps).join(', ') || 'unknown_ip';

        // Check if there's already a sequence detection for this user
        const alreadyFlagged = results.some(r => r.username === username && r.threatType === 'SUSPICIOUS_AUTH_SEQUENCE');
        if (!alreadyFlagged) {
          results.push({
            id: `sys-auth-fail-${username}-${Date.now()}`,
            agentId: 'SYSTEM_AGENT',
            eventId: userFeat.eventIds[0] || `evt-auth-${username}`,
            timestamp: lastFailIso,
            detection: detectionName,
            threatDetected: true,
            threatType,
            severity,
            confidence,
            classification,
            username,
            host: hostsList,
            sourceIp: ipsList !== 'unknown_ip' ? ipsList : undefined,
            eventType: 'AUTH_FAILURE',
            evidence: [
              `User account "${username}" accumulated ${userFeat.failedAttempts} failed login attempts.`,
              `Total authentication attempts evaluated: ${userFeat.totalAuthAttempts}.`,
              `Targeted endpoint hosts: ${hostsList}.`,
              `Originating client IP addresses: ${ipsList}.`,
              `Observed failure timestamps span from ${new Date(userFeat.firstSeen).toISOString()} to ${new Date(userFeat.lastSeen).toISOString()}.`
            ],
            indicators: [
              `Failed Logins: ${userFeat.failedAttempts}`,
              `Target Hosts: ${hostsList}`,
              `Source IPs: ${ipsList}`,
              isHighVolume ? 'High-Frequency Failure Burst' : 'Multiple Sequential Failures'
            ],
            observedActivity: `Repeated authentication rejections observed for user "${username}" across ${userFeat.failedAttempts} attempts.`,
            detectedPattern: isHighVolume
              ? `High-velocity authentication failure bursts typical of automated password spraying or brute force dictionary attacks.`
              : `Sequential login authentication failures exceeding normal user error thresholds.`,
            securityFinding: isHighVolume
              ? 'Active credential attack against host authentication endpoint.'
              : 'Suspicious authentication anomalies indicating potential unauthorized access attempts.',
            recommendedAction: 'Apply temporary IP / account rate limiting; enforce MFA; inspect source IP reputation.',
            status: 'NEW'
          });
        }
      }
    }

    // -------------------------------------------------------------
    // RULE 3 & 4: PROCESS ACTIVITY & PRIVILEGE ESCALATION (Single event analysis)
    // -------------------------------------------------------------
    for (const event of events) {
      const fields = SystemFeatureExtractor.extractSingleEventFields(event);
      const combinedText = `${fields.message} ${fields.commandLine || ''} ${fields.processName || ''} ${fields.action || ''}`.trim();

      // Check Suspicious Process Patterns
      for (const sig of SUSPICIOUS_PROCESS_PATTERNS) {
        if (sig.pattern.test(combinedText)) {
          const isPrivilegeSig = sig.name.includes('Privilege') || sig.name.includes('Administrator Account Creation');
          const threatType: SystemThreatType = isPrivilegeSig ? 'PRIVILEGE_ESCALATION' : 'SUSPICIOUS_PROCESS';
          const detection = isPrivilegeSig ? 'Potential Privilege Escalation' : 'Suspicious Process Activity';

          results.push({
            id: `sys-proc-${event.id}`,
            agentId: 'SYSTEM_AGENT',
            eventId: event.id,
            timestamp: event.timestamp,
            detection,
            threatDetected: true,
            threatType,
            severity: sig.severity,
            confidence: sig.confidence,
            classification: 'THREAT',
            username: fields.username || 'SYSTEM',
            host: fields.host || 'unknown_host',
            sourceIp: fields.sourceIp,
            eventType: fields.eventType,
            processName: fields.processName,
            commandLine: fields.commandLine,
            evidence: [
              `Observed execution pattern matched rule: ${sig.name}.`,
              fields.commandLine ? `Command Line: "${fields.commandLine}"` : `Process Name: "${fields.processName || 'unspecified'}"`,
              fields.parentProcess ? `Parent Process: "${fields.parentProcess}"` : 'Parent process not recorded.',
              `Executing User Context: ${fields.username || 'SYSTEM/Root'}.`,
              `Host: ${fields.host || 'unknown_host'}.`,
              `Heuristic Justification: ${sig.reason}`
            ],
            indicators: [
              sig.name,
              fields.processName || 'command_execution',
              `User: ${fields.username || 'SYSTEM'}`
            ],
            observedActivity: `Process execution matching "${sig.name}" observed on host "${fields.host || 'unknown_host'}".`,
            detectedPattern: `Command line or binary signature: "${sig.name}".`,
            securityFinding: `Potential malicious host activity: ${sig.reason}`,
            recommendedAction: 'Terminate suspicious process tree, collect memory forensics, inspect child processes, isolate endpoint if necessary.',
            status: 'NEW',
            rawEvent: event
          });
          processedEventIds.add(event.id);
          break; // Stop evaluating patterns for this event
        }
      }

      // Check Suspicious Parent-Child Process relationships
      if (fields.parentProcess && fields.processName) {
        for (const rel of SUSPICIOUS_PARENTS) {
          if (rel.parent.test(fields.parentProcess) && rel.child.test(fields.processName)) {
            results.push({
              id: `sys-spawn-${event.id}`,
              agentId: 'SYSTEM_AGENT',
              eventId: event.id,
              timestamp: event.timestamp,
              detection: 'Suspicious Process Activity (Anomalous Parent-Child)',
              threatDetected: true,
              threatType: 'SUSPICIOUS_PROCESS',
              severity: rel.severity,
              confidence: rel.confidence,
              classification: 'THREAT',
              username: fields.username || 'SYSTEM',
              host: fields.host || 'unknown_host',
              sourceIp: fields.sourceIp,
              eventType: 'PROCESS_EXEC',
              processName: fields.processName,
              commandLine: fields.commandLine,
              evidence: [
                `Parent process "${fields.parentProcess}" spawned command interpreter "${fields.processName}".`,
                `Detection Rule: ${rel.name}.`,
                fields.commandLine ? `Command Line arguments: "${fields.commandLine}"` : 'No command arguments supplied.',
                `Context user: ${fields.username || 'SYSTEM'}.`,
                `Analysis: ${rel.reason}`
              ],
              indicators: [
                rel.name,
                `Parent: ${fields.parentProcess}`,
                `Child: ${fields.processName}`
              ],
              observedActivity: `Parent process "${fields.parentProcess}" spawned child shell "${fields.processName}" on host "${fields.host || 'unknown_host'}".`,
              detectedPattern: `Anomalous process tree hierarchy characteristic of application exploit or web shell payload.`,
              securityFinding: `Potential remote command injection or web shell execution on host.`,
              recommendedAction: 'Inspect web/database logs corresponding to parent process, inspect network outbound connections, isolate host.',
              status: 'NEW',
              rawEvent: event
            });
            processedEventIds.add(event.id);
            break;
          }
        }
      }

      // Generic Privilege Escalation detection from eventType or special privileges
      if (fields.eventType === 'PRIVILEGE_CHANGE' && !processedEventIds.has(event.id)) {
        const isSudo = combinedText.toLowerCase().includes('sudo');
        const isGroupAdd = combinedText.toLowerCase().includes('added to group') || combinedText.toLowerCase().includes('administrators');
        const severity: SeverityLevel = isGroupAdd ? 'CRITICAL' : 'HIGH';

        results.push({
          id: `sys-priv-${event.id}`,
          agentId: 'SYSTEM_AGENT',
          eventId: event.id,
          timestamp: event.timestamp,
          detection: 'Potential Privilege Escalation',
          threatDetected: true,
          threatType: 'PRIVILEGE_ESCALATION',
          severity,
          confidence: 0.86,
          classification: 'THREAT',
          username: fields.username || 'unknown_user',
          host: fields.host || 'unknown_host',
          sourceIp: fields.sourceIp,
          eventType: 'PRIVILEGE_CHANGE',
          processName: fields.processName,
          commandLine: fields.commandLine,
          evidence: [
            `Privilege elevation event recorded on host "${fields.host || 'unknown_host'}".`,
            `User context: ${fields.username || 'unknown_user'}.`,
            isSudo ? 'Sudo elevation command executed.' : 'Security-enabled group membership or special privileges assigned.',
            fields.commandLine ? `Command Line: "${fields.commandLine}"` : `Event summary: "${fields.message}"`,
            fields.integrityLevel ? `Reported integrity level: ${fields.integrityLevel}` : 'Integrity level unstated.'
          ],
          indicators: [
            'Privilege Context Modification',
            isSudo ? 'sudo_elevation' : 'security_group_elevation',
            `User: ${fields.username || 'unknown_user'}`
          ],
          observedActivity: `Privilege elevation or administrative rights assignment detected for user "${fields.username || 'unknown_user'}".`,
          detectedPattern: `Elevation activity modifying administrative rights or creating root/admin privileged context.`,
          securityFinding: 'Observable privilege transition to administrative/root capabilities on host.',
          recommendedAction: 'Verify authorized administrative change ticket; audit commands run during privileged session.',
          status: 'NEW',
          rawEvent: event
        });
        processedEventIds.add(event.id);
      }
    }

    // -------------------------------------------------------------
    // RULE 5: UNUSUAL HOST ACTIVITY (Statistical anomaly)
    // Host with abnormal failure ratio or massive disproportionate event count
    // -------------------------------------------------------------
    for (const [host, hostFeat] of hostMap.entries()) {
      if (hostFeat.totalEvents >= 8 && hostFeat.failedLogins / hostFeat.totalEvents > 0.6) {
        // High failure concentration on this host
        const alreadyFlaggedHost = results.some(r => r.host.includes(host) && r.threatType === 'UNUSUAL_HOST_ACTIVITY');
        if (!alreadyFlaggedHost) {
          results.push({
            id: `sys-host-anom-${host}-${Date.now()}`,
            agentId: 'SYSTEM_AGENT',
            eventId: hostFeat.eventIds[0] || `evt-host-${host}`,
            timestamp: new Date().toISOString(),
            detection: 'Unusual Host Activity (High Failure Ratio)',
            threatDetected: true,
            threatType: 'UNUSUAL_HOST_ACTIVITY',
            severity: 'MEDIUM',
            confidence: 0.76,
            classification: 'SUSPICIOUS',
            username: Array.from(hostFeat.users).join(', ') || 'multiple_users',
            host,
            eventType: 'SYSTEM_ANOMALY',
            evidence: [
              `Host "${host}" recorded ${hostFeat.totalEvents} total events with ${hostFeat.failedLogins} authentication failures.`,
              `Authentication failure ratio: ${Math.round((hostFeat.failedLogins / hostFeat.totalEvents) * 100)}%.`,
              `Unique user accounts affected: ${Array.from(hostFeat.users).join(', ') || 'none specified'}.`,
              `Unique remote source IPs: ${Array.from(hostFeat.sourceIps).join(', ') || 'internal/local'}.`
            ],
            indicators: [
              `High Failure Ratio: ${Math.round((hostFeat.failedLogins / hostFeat.totalEvents) * 100)}%`,
              `Host: ${host}`,
              `Total Events: ${hostFeat.totalEvents}`
            ],
            observedActivity: `Abnormally elevated proportion of authentication failures recorded on host "${host}".`,
            detectedPattern: `System event failure rate significantly diverges from typical operational baseline.`,
            securityFinding: `Host anomaly indicating potential brute-force target or internal network scan targeting authentication services.`,
            recommendedAction: 'Inspect host event logs, check network firewall rules for host, confirm service availability.',
            status: 'NEW'
          });
        }
      }
    }

    return results;
  }
}
