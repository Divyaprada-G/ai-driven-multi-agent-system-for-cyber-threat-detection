import { LogEvent, SingleSystemEventFields, UserAuthFeatures, HostTelemetryFeatures, AuthStatus, SystemEventType } from '../types';

export class SystemFeatureExtractor {
  /**
   * Extract standardized system/host fields from a LogEvent safely.
   * If a field is missing, leave it undefined without inventing values.
   */
  public static extractSingleEventFields(event: LogEvent): SingleSystemEventFields {
    const nf = event.normalizedFields || {};
    const meta = (event.metadata || {}) as Record<string, unknown>;

    // Host extraction
    const host = nf.hostName ||
      (typeof meta.host === 'string' ? meta.host : undefined) ||
      (typeof meta.hostname === 'string' ? meta.hostname : undefined) ||
      (typeof meta.computer_name === 'string' ? meta.computer_name : undefined) ||
      (event.source && !event.source.includes('/') && !event.source.includes('.') ? event.source : undefined);

    // User extraction
    let username = nf.userName ||
      (typeof meta.username === 'string' ? meta.username : undefined) ||
      (typeof meta.user === 'string' ? meta.user : undefined) ||
      (typeof meta.account === 'string' ? meta.account : undefined) ||
      (typeof meta.TargetUserName === 'string' ? meta.TargetUserName : undefined);

    // Source IP extraction (for remote logins)
    let sourceIp = nf.sourceIp ||
      (typeof meta.sourceIp === 'string' ? meta.sourceIp : undefined) ||
      (typeof meta.src_ip === 'string' ? meta.src_ip : undefined) ||
      (typeof meta.client_ip === 'string' ? meta.client_ip : undefined) ||
      (typeof meta.IpAddress === 'string' ? meta.IpAddress : undefined);

    // Process attributes
    const processName = nf.processName ||
      (typeof meta.processName === 'string' ? meta.processName : undefined) ||
      (typeof meta.process === 'string' ? meta.process : undefined) ||
      (typeof meta.image === 'string' ? meta.image : undefined) ||
      (typeof meta.NewProcessName === 'string' ? meta.NewProcessName : undefined);

    const processId = typeof nf.processId === 'number' ? nf.processId :
      (typeof meta.processId === 'number' ? meta.processId :
      (typeof meta.pid === 'number' ? meta.pid : undefined));

    const commandLine = nf.commandLine ||
      (typeof meta.commandLine === 'string' ? meta.commandLine : undefined) ||
      (typeof meta.cmdline === 'string' ? meta.cmdline : undefined) ||
      (typeof meta.CommandLine === 'string' ? meta.CommandLine : undefined) ||
      (typeof meta.command === 'string' ? meta.command : undefined);

    const parentProcess = nf.parentProcess ||
      (typeof meta.parentProcess === 'string' ? meta.parentProcess : undefined) ||
      (typeof meta.ParentProcessName === 'string' ? meta.ParentProcessName : undefined);

    const integrityLevel = nf.integrityLevel ||
      (typeof meta.integrityLevel === 'string' ? meta.integrityLevel : undefined) ||
      (typeof meta.MandatoryLabel === 'string' ? meta.MandatoryLabel : undefined);

    // Text parsing fallback from raw message / syslog
    const msg = event.message || '';
    const raw = event.rawData || '';
    const combined = `${msg} ${raw}`;

    // Regex extraction if user wasn't in structured fields
    if (!username) {
      const userMatch = combined.match(/(?:user|for user|for invalid user|account|logname)[=:\s]+(["']?)([\w.\-_$]+)\1/i) ||
                        combined.match(/(?:Failed|Accepted) password for (?:invalid user )?([\w.\-_$]+)/i) ||
                        combined.match(/TargetUserName:\s*([\w.\-_$]+)/i);
      if (userMatch && userMatch[1] && userMatch[2]) {
        username = userMatch[2];
      } else if (userMatch && userMatch[1]) {
        username = userMatch[1];
      }
    }

    // Regex extraction if sourceIp wasn't in structured fields
    if (!sourceIp) {
      const ipMatch = combined.match(/(?:from|client|src|ip|rhost)[=:\s]+(\b(?:\d{1,3}\.){3}\d{1,3}\b)/i) ||
                      combined.match(/(\b(?:\d{1,3}\.){3}\d{1,3}\b)/);
      if (ipMatch && ipMatch[1]) {
        sourceIp = ipMatch[1];
      }
    }

    // Determine Auth Status and Event Type
    const lowerCombined = combined.toLowerCase();
    let authStatus: AuthStatus = 'UNKNOWN';
    let eventType: SystemEventType = 'GENERAL_SYSTEM';

    const isFailure =
      lowerCombined.includes('failed password') ||
      lowerCombined.includes('authentication failure') ||
      lowerCombined.includes('login failed') ||
      lowerCombined.includes('logon failure') ||
      lowerCombined.includes('event id 4625') ||
      lowerCombined.includes('eventid: 4625') ||
      lowerCombined.includes('auth_failure') ||
      lowerCombined.includes('bad password') ||
      lowerCombined.includes('invalid credentials') ||
      lowerCombined.includes('pam_unix(sshd:auth): authentication failure');

    const isSuccess =
      lowerCombined.includes('accepted password') ||
      lowerCombined.includes('accepted publickey') ||
      lowerCombined.includes('session opened') ||
      lowerCombined.includes('login successful') ||
      lowerCombined.includes('logon success') ||
      lowerCombined.includes('event id 4624') ||
      lowerCombined.includes('eventid: 4624') ||
      lowerCombined.includes('auth_success') ||
      lowerCombined.includes('successful login');

    const isPrivilegeChange =
      lowerCombined.includes('sudo') ||
      lowerCombined.includes('event id 4672') ||
      lowerCombined.includes('eventid: 4672') ||
      lowerCombined.includes('special privileges assigned') ||
      lowerCombined.includes('privilege escalation') ||
      lowerCombined.includes('privilege_change') ||
      lowerCombined.includes('added to group') ||
      lowerCombined.includes('administrators /add') ||
      lowerCombined.includes('wheel') ||
      lowerCombined.includes('root session') ||
      lowerCombined.includes('su -') ||
      lowerCombined.includes('setuid') ||
      (integrityLevel && integrityLevel.toLowerCase().includes('high'));

    const isProcessExec =
      Boolean(processName || commandLine) ||
      lowerCombined.includes('process creation') ||
      lowerCombined.includes('event id 4688') ||
      lowerCombined.includes('eventid: 4688') ||
      lowerCombined.includes('executed command') ||
      lowerCombined.includes('execve');

    if (isFailure) {
      authStatus = 'FAILURE';
      eventType = 'AUTH_FAILURE';
    } else if (isSuccess) {
      authStatus = 'SUCCESS';
      eventType = 'AUTH_SUCCESS';
    } else if (isPrivilegeChange) {
      eventType = 'PRIVILEGE_CHANGE';
    } else if (isProcessExec) {
      eventType = 'PROCESS_EXEC';
    } else if (lowerCombined.includes('service installed') || lowerCombined.includes('system service')) {
      eventType = 'SYSTEM_SERVICE';
    } else if (lowerCombined.includes('user account created') || lowerCombined.includes('user account deleted')) {
      eventType = 'ACCOUNT_MANAGEMENT';
    } else if (lowerCombined.includes('session closed')) {
      eventType = 'SESSION_END';
    }

    return {
      id: event.id,
      timestamp: event.timestamp,
      host: host ? String(host).trim() : undefined,
      username: username ? String(username).trim() : undefined,
      sourceIp: sourceIp ? String(sourceIp).trim() : undefined,
      eventType,
      authStatus,
      processName: processName ? String(processName).trim() : undefined,
      processId,
      commandLine: commandLine ? String(commandLine).trim() : undefined,
      parentProcess: parentProcess ? String(parentProcess).trim() : undefined,
      integrityLevel: integrityLevel ? String(integrityLevel).trim() : undefined,
      action: typeof meta.action === 'string' ? meta.action : undefined,
      message: msg,
      rawEvent: event
    };
  }

  /**
   * Group and extract user-centric authentication behavior
   */
  public static extractUserAuthFeatures(events: LogEvent[]): Map<string, UserAuthFeatures> {
    const userMap = new Map<string, UserAuthFeatures>();

    // Sort events by chronological timestamp
    const sorted = [...events].sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return (isNaN(ta) ? 0 : ta) - (isNaN(tb) ? 0 : tb);
    });

    for (const event of sorted) {
      const fields = this.extractSingleEventFields(event);
      const user = fields.username || 'unknown_user';

      if (!userMap.has(user)) {
        const timeNum = new Date(event.timestamp).getTime() || Date.now();
        userMap.set(user, {
          username: user,
          hosts: new Set<string>(),
          sourceIps: new Set<string>(),
          totalAuthAttempts: 0,
          failedAttempts: 0,
          successfulAttempts: 0,
          failureTimestamps: [],
          successTimestamps: [],
          firstSeen: timeNum,
          lastSeen: timeNum,
          hasSuccessAfterFailures: false,
          eventIds: []
        });
      }

      const record = userMap.get(user)!;
      const t = new Date(event.timestamp).getTime() || Date.now();
      record.lastSeen = Math.max(record.lastSeen, t);
      record.firstSeen = Math.min(record.firstSeen, t);
      record.eventIds.push(event.id);

      if (fields.host) record.hosts.add(fields.host);
      if (fields.sourceIp) record.sourceIps.add(fields.sourceIp);

      if (fields.authStatus === 'FAILURE') {
        record.totalAuthAttempts += 1;
        record.failedAttempts += 1;
        record.failureTimestamps.push(t);
      } else if (fields.authStatus === 'SUCCESS') {
        record.totalAuthAttempts += 1;
        record.successfulAttempts += 1;
        record.successTimestamps.push(t);

        // Check if there were multiple failures before this success within reasonable window (15 mins = 900,000 ms)
        const recentFailures = record.failureTimestamps.filter(ft => t >= ft && (t - ft) <= 15 * 60 * 1000);
        if (recentFailures.length >= 2 && !record.hasSuccessAfterFailures) {
          record.hasSuccessAfterFailures = true;
          const firstFail = recentFailures[0];
          record.successAfterFailuresDetails = {
            failedCount: recentFailures.length,
            successTime: event.timestamp,
            firstFailureTime: new Date(firstFail).toISOString(),
            timeDeltaSeconds: Math.round((t - firstFail) / 1000),
            sourceIp: fields.sourceIp,
            host: fields.host
          };
        }
      }
    }

    return userMap;
  }

  /**
   * Group telemetry by host
   */
  public static extractHostTelemetryFeatures(events: LogEvent[]): Map<string, HostTelemetryFeatures> {
    const hostMap = new Map<string, HostTelemetryFeatures>();

    for (const event of events) {
      const fields = this.extractSingleEventFields(event);
      const host = fields.host || 'unknown_host';

      if (!hostMap.has(host)) {
        hostMap.set(host, {
          host,
          users: new Set<string>(),
          totalEvents: 0,
          authEvents: 0,
          processEvents: 0,
          failedLogins: 0,
          privilegeEvents: 0,
          processesObserved: new Set<string>(),
          sourceIps: new Set<string>(),
          eventIds: []
        });
      }

      const record = hostMap.get(host)!;
      record.totalEvents += 1;
      record.eventIds.push(event.id);

      if (fields.username) record.users.add(fields.username);
      if (fields.sourceIp) record.sourceIps.add(fields.sourceIp);
      if (fields.processName) record.processesObserved.add(fields.processName);

      if (fields.authStatus === 'FAILURE' || fields.authStatus === 'SUCCESS' || fields.eventType.startsWith('AUTH_')) {
        record.authEvents += 1;
        if (fields.authStatus === 'FAILURE') {
          record.failedLogins += 1;
        }
      }

      if (fields.eventType === 'PROCESS_EXEC') {
        record.processEvents += 1;
      }

      if (fields.eventType === 'PRIVILEGE_CHANGE') {
        record.privilegeEvents += 1;
      }
    }

    return hostMap;
  }
}
