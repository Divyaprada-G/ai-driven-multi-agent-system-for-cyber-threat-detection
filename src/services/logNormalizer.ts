import { LogEvent, LogFileFormat, LogType, NormalizedFields } from '../types';

export class LogNormalizer {
  /**
   * Normalizes a raw object/record into a standardized LogEvent structure.
   */
  static normalize(
    rawRecord: Record<string, unknown>,
    options: {
      logType?: LogType;
      format?: LogFileFormat;
      fallbackSource?: string;
      rawString?: string;
      index?: number;
    } = {}
  ): { event: LogEvent; unmappedKeys: string[] } {
    const rawKeys = Object.keys(rawRecord);
    const mappedKeys = new Set<string>();

    // Helper to find field value across aliases (even if value is empty string, zero, or null)
    const findRawEntry = (aliases: string[]): { key: string; value: unknown } | undefined => {
      // Direct case match
      for (const alias of aliases) {
        if (alias in rawRecord) {
          mappedKeys.add(alias);
          return { key: alias, value: rawRecord[alias] };
        }
      }
      // Case-insensitive / underscore-insensitive match
      const aliasClean = aliases.map(a => a.toLowerCase().replace(/[-_ \t]/g, ''));
      for (const key of rawKeys) {
        const cleanKey = key.toLowerCase().replace(/[-_ \t]/g, '');
        if (aliasClean.includes(cleanKey)) {
          mappedKeys.add(key);
          return { key, value: rawRecord[key] };
        }
      }
      return undefined;
    };

    const findValue = <T = unknown>(aliases: string[]): T | undefined => {
      const entry = findRawEntry(aliases);
      if (entry && entry.value !== undefined && entry.value !== null && entry.value !== '') {
        return entry.value as T;
      }
      return undefined;
    };

    // 1. Timestamp Normalization & Quality Check
    const rawTimeEntry = findRawEntry([
      'timestamp', '@timestamp', 'time', 'datetime', 'event_time', 'date', 'log_time', 'time_stamp', 'Timestamp'
    ]);
    const rawTime = rawTimeEntry?.value as string | number | undefined;
    const tsCheck = this.parseAndCheckTimestamp(rawTime);
    const normalizedTimestamp = tsCheck.isoTimestamp;

    // 2. Determine Log Type
    const logType: LogType = options.logType || 'NETWORK';

    // 3. Extract Normalized Domain Fields
    const normalizedFields: NormalizedFields = {
      originalTimestamp: rawTime !== undefined && rawTime !== null ? String(rawTime) : undefined,
      hasInvalidTimestamp: !tsCheck.isValid
    };

    // --- Network Fields ---
    const rawSrcIpEntry = findRawEntry([
      'sourceIp', 'src_ip', 'srcip', 'source_ip', 'ip_src', 'src_addr', 'client_ip', 'src', 'sourceIPAddress', 'Source IP', 'Src IP'
    ]);
    if (rawSrcIpEntry) {
      normalizedFields.sourceIp = rawSrcIpEntry.value !== undefined && rawSrcIpEntry.value !== null
        ? String(rawSrcIpEntry.value).trim()
        : '';
    }

    const rawDstIpEntry = findRawEntry([
      'destinationIp', 'dest_ip', 'dst_ip', 'dstip', 'destination_ip', 'ip_dst', 'dst_addr', 'server_ip', 'dst', 'destinationIPAddress', 'Destination IP', 'Dst IP'
    ]);
    if (rawDstIpEntry) {
      normalizedFields.destinationIp = rawDstIpEntry.value !== undefined && rawDstIpEntry.value !== null
        ? String(rawDstIpEntry.value).trim()
        : '';
    }

    const rawSrcPort = findValue<number | string>([
      'sourcePort', 'src_port', 'srcport', 'source_port', 'sport', 'srcPort', 'client_port', 'Source Port'
    ]);
    if (rawSrcPort !== undefined) {
      const port = Number(rawSrcPort);
      if (!isNaN(port)) normalizedFields.sourcePort = port;
    }

    const rawDstPort = findValue<number | string>([
      'destinationPort', 'dest_port', 'dst_port', 'dstport', 'destination_port', 'dport', 'dstPort', 'server_port', 'Destination Port'
    ]);
    if (rawDstPort !== undefined) {
      const port = Number(rawDstPort);
      if (!isNaN(port)) normalizedFields.destinationPort = port;
    }

    const rawProtoEntry = findRawEntry([
      'protocol', 'proto', 'transport', 'network_protocol', 'Protocol', 'protocol_type'
    ]);
    if (rawProtoEntry) {
      normalizedFields.protocol = rawProtoEntry.value !== undefined && rawProtoEntry.value !== null
        ? String(rawProtoEntry.value).toUpperCase().trim()
        : '';
    }

    const rawPacketSize = findValue<number | string>([
      'packetSize', 'packet_size', 'length', 'bytes', 'size', 'tot_len', 'bytes_toserver', 'Total Length of Fwd Packets'
    ]);
    if (rawPacketSize !== undefined) {
      const size = Number(rawPacketSize);
      if (!isNaN(size)) normalizedFields.packetSize = size;
    }

    const rawFlags = findValue<string | string[]>([
      'flags', 'tcp_flags', 'flag'
    ]);
    if (rawFlags) {
      if (Array.isArray(rawFlags)) {
        normalizedFields.flags = rawFlags.map(String);
      } else {
        normalizedFields.flags = String(rawFlags).split(/[,|\s]+/).map(f => f.trim()).filter(Boolean);
      }
    }

    // Flow duration
    const rawFlowDuration = findValue<number | string>([
      'flowDuration', 'flow_duration', 'duration', 'Flow Duration'
    ]);
    if (rawFlowDuration !== undefined) {
      const dur = Number(rawFlowDuration);
      if (!isNaN(dur)) normalizedFields.flowDuration = dur;
    }

    // --- System / Host Fields ---
    const rawHost = findValue<string>([
      'hostName', 'hostname', 'host', 'computer_name', 'device_name', 'node', 'system_name'
    ]);
    if (rawHost) normalizedFields.hostName = String(rawHost).trim();

    const rawPid = findValue<number | string>([
      'processId', 'pid', 'process_id', 'proc_id', 'ProcessId'
    ]);
    if (rawPid !== undefined) {
      const pid = Number(rawPid);
      if (!isNaN(pid)) normalizedFields.processId = pid;
    }

    const rawProcessName = findValue<string>([
      'processName', 'process_name', 'process', 'image', 'Image', 'exe', 'proc_name', 'binary'
    ]);
    if (rawProcessName) normalizedFields.processName = String(rawProcessName).trim();

    const rawUser = findValue<string>([
      'userName', 'username', 'user', 'account', 'user_id', 'User', 'TargetUserName', 'logname'
    ]);
    if (rawUser) normalizedFields.userName = String(rawUser).trim();

    const rawCmd = findValue<string>([
      'commandLine', 'command_line', 'cmdline', 'cmd', 'CommandLine', 'command'
    ]);
    if (rawCmd) normalizedFields.commandLine = String(rawCmd).trim();

    const rawParentProcess = findValue<string>([
      'parentProcess', 'parent_process', 'ppid', 'ParentImage', 'parent_image'
    ]);
    if (rawParentProcess) normalizedFields.parentProcess = String(rawParentProcess).trim();

    const rawIntegrity = findValue<string>([
      'integrityLevel', 'integrity_level', 'IntegrityLevel', 'privilege_level'
    ]);
    if (rawIntegrity) normalizedFields.integrityLevel = String(rawIntegrity).trim();

    // --- Application / Web Fields ---
    const rawAppName = findValue<string>([
      'applicationName', 'app_name', 'app', 'service', 'component', 'service_name'
    ]);
    if (rawAppName) normalizedFields.applicationName = String(rawAppName).trim();

    const rawMethod = findValue<string>([
      'httpMethod', 'http_method', 'method', 'verb', 'request_method'
    ]);
    if (rawMethod) normalizedFields.httpMethod = String(rawMethod).toUpperCase().trim();

    const rawEndpoint = findValue<string>([
      'endpoint', 'uri', 'url', 'path', 'request_path', 'request_uri', 'request'
    ]);
    if (rawEndpoint) normalizedFields.endpoint = String(rawEndpoint).trim();

    const rawStatusCode = findValue<number | string>([
      'statusCode', 'status_code', 'status', 'http_status', 'code', 'response_code'
    ]);
    if (rawStatusCode !== undefined) {
      const code = Number(rawStatusCode);
      if (!isNaN(code)) normalizedFields.statusCode = code;
    }

    const rawUserAgent = findValue<string>([
      'userAgent', 'user_agent', 'http_user_agent', 'agent'
    ]);
    if (rawUserAgent) normalizedFields.userAgent = String(rawUserAgent).trim();

    const rawPayload = findValue<string>([
      'payloadSnippet', 'payload', 'body', 'request_body', 'data', 'params'
    ]);
    if (rawPayload) normalizedFields.payloadSnippet = String(rawPayload).trim();

    // --- Security Telemetry & Dataset Specific Fields ---
    const rawFailedLoginsEntry = findRawEntry([
      'num_failed_logins', 'num_failed_login', 'failed_logins', 'failed_login', 'failedLogins', 'failed_login_count', 'failedLoginCount'
    ]);
    if (rawFailedLoginsEntry && rawFailedLoginsEntry.value !== undefined && rawFailedLoginsEntry.value !== null) {
      const parsedNum = Number(rawFailedLoginsEntry.value);
      normalizedFields.numFailedLogins = isNaN(parsedNum) ? (rawFailedLoginsEntry.value as any) : parsedNum;
      normalizedFields.failedLogins = normalizedFields.numFailedLogins;
    }

    const rawLabelEntry = findRawEntry([
      'label', 'Label', 'attack_cat', 'class', 'target', 'threat_class', 'category'
    ]);
    if (rawLabelEntry) {
      normalizedFields.label = rawLabelEntry.value !== undefined && rawLabelEntry.value !== null
        ? String(rawLabelEntry.value).trim()
        : '';
    }

    // Check for malformed or parser errors recorded during ingestion
    if (rawRecord.parseError || rawRecord.isMalformed || rawRecord.hasMalformedRecord) {
      normalizedFields.hasMalformedRecord = true;
      normalizedFields.parseError = String(rawRecord.parseError || rawRecord.message || 'Malformed record syntax');
    }

    // 4. Source Determination
    let source = findValue<string>(['source', 'src_host', 'origin', 'facility']);
    if (!source) {
      if (logType === 'NETWORK') {
        source = normalizedFields.sourceIp || normalizedFields.destinationIp || options.fallbackSource || 'network-ingress';
      } else if (logType === 'SYSTEM') {
        source = normalizedFields.hostName || (normalizedFields.processName ? `proc:${normalizedFields.processName}` : undefined) || options.fallbackSource || 'host-system';
      } else {
        source = normalizedFields.applicationName || (normalizedFields.endpoint ? `web:${normalizedFields.endpoint}` : undefined) || options.fallbackSource || 'web-gateway';
      }
    }

    // 5. Message Normalization
    let message = findValue<string>([
      'message', 'msg', 'info', 'description', 'summary', 'log', 'alert', 'alert.signature'
    ]);
    if (!message) {
      // Check nested alert object (Suricata style)
      if (rawRecord.alert && typeof rawRecord.alert === 'object') {
        const alertObj = rawRecord.alert as Record<string, unknown>;
        if (alertObj.signature) {
          message = String(alertObj.signature);
        }
      }
    }
    if (!message) {
      // Synthesize descriptive message from normalized fields
      if (logType === 'NETWORK' && normalizedFields.sourceIp) {
        message = `${normalizedFields.protocol || 'IP'} flow: ${normalizedFields.sourceIp}${normalizedFields.sourcePort ? `:${normalizedFields.sourcePort}` : ''} -> ${normalizedFields.destinationIp || 'remote'}${normalizedFields.destinationPort ? `:${normalizedFields.destinationPort}` : ''}`;
      } else if (logType === 'SYSTEM' && (normalizedFields.processName || normalizedFields.commandLine)) {
        message = `Process execution: ${normalizedFields.processName || 'cmd'} ${normalizedFields.commandLine ? `("${normalizedFields.commandLine}")` : ''} by ${normalizedFields.userName || 'unknown'}`;
      } else if (logType === 'APPLICATION' && normalizedFields.endpoint) {
        message = `HTTP ${normalizedFields.httpMethod || 'GET'} ${normalizedFields.endpoint} [Status ${normalizedFields.statusCode || 200}]`;
      } else if (options.rawString) {
        message = options.rawString.slice(0, 180);
      } else {
        message = `Standard ${logType} event ingested from ${source}`;
      }
    }

    // 6. ID Generation
    const rawId = findValue<string>(['id', 'uuid', 'eventId', 'event_id', '_id']);
    const id = rawId ? String(rawId) : `EVT-${Date.now().toString().slice(-6)}-${(options.index || 0).toString().padStart(4, '0')}`;

    // Collect unmapped keys for transparency
    const unmappedKeys = rawKeys.filter(k => !mappedKeys.has(k));

    const event: LogEvent = {
      id,
      timestamp: normalizedTimestamp,
      originalTimestamp: normalizedFields.originalTimestamp,
      ingestionTimestamp: new Date().toISOString(),
      source: String(source).trim(),
      logType,
      message: String(message).trim(),
      rawData: options.rawString || JSON.stringify(rawRecord),
      originalData: rawRecord,
      format: options.format || 'JSON',
      normalizedFields,
      metadata: unmappedKeys.length > 0 ? { unmapped: Object.fromEntries(unmappedKeys.map(k => [k, rawRecord[k]])) } : undefined
    };

    return { event, unmappedKeys };
  }

  /**
   * Deeply validates and standardizes date formats without silently swallowing invalid values.
   */
  static parseAndCheckTimestamp(input: string | number | undefined): {
    isValid: boolean;
    isoTimestamp: string;
    originalValue: string | number | undefined;
    error?: string;
  } {
    if (input === undefined || input === null || String(input).trim() === '') {
      return {
        isValid: false,
        isoTimestamp: new Date().toISOString(),
        originalValue: input,
        error: 'Missing or blank timestamp value'
      };
    }

    // Epoch timestamp (seconds or milliseconds)
    if (typeof input === 'number' || /^\d{10,13}$/.test(String(input).trim())) {
      const num = Number(input);
      const millis = num < 10000000000 ? num * 1000 : num;
      const d = new Date(millis);
      if (!isNaN(d.getTime())) {
        return { isValid: true, isoTimestamp: d.toISOString(), originalValue: input };
      }
    }

    const str = String(input).trim();

    // Explicit invalid checks (e.g., placeholder tokens, NaN, non-dates)
    if (/^(invalid|nan|null|undefined|none|unknown|-)$/i.test(str)) {
      return {
        isValid: false,
        isoTimestamp: new Date().toISOString(),
        originalValue: input,
        error: `Invalid timestamp literal: "${str}"`
      };
    }

    // Standard ISO 8601 or Date parse
    const isoDate = new Date(str);
    if (!isNaN(isoDate.getTime())) {
      // Guard against nonsensical single numbers that Date parses as years or epoch
      if (!/^\d{1,4}$/.test(str)) {
        return { isValid: true, isoTimestamp: isoDate.toISOString(), originalValue: input };
      }
    }

    // Apache / Nginx format: 11/Sep/2026:22:19:58 +0000 or 11/09/2026 22:19:58
    const apacheMatch = str.match(/^(\d{1,2})\/([a-zA-Z]{3}|\d{1,2})\/(\d{4}):?(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/);
    if (apacheMatch) {
      const [, day, month, year, h, m, s] = apacheMatch;
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      let monthIndex = monthNames.findIndex(mn => mn.toLowerCase() === month.toLowerCase());
      if (monthIndex === -1 && !isNaN(Number(month))) {
        monthIndex = Number(month) - 1;
      }
      if (monthIndex >= 0 && monthIndex <= 11) {
        const d = new Date(Date.UTC(Number(year), monthIndex, Number(day), Number(h), Number(m), Number(s)));
        if (!isNaN(d.getTime())) {
          return { isValid: true, isoTimestamp: d.toISOString(), originalValue: input };
        }
      }
    }

    // Syslog format: Sep 11 22:04:12 (without year)
    const syslogMatch = str.match(/^([a-zA-Z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (syslogMatch) {
      const [, month, day, h, m, s] = syslogMatch;
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const monthIndex = monthNames.findIndex(mn => mn.toLowerCase() === month.toLowerCase());
      if (monthIndex !== -1) {
        const year = new Date().getFullYear();
        const d = new Date(Date.UTC(year, monthIndex, Number(day), Number(h), Number(m), Number(s)));
        if (!isNaN(d.getTime())) {
          return { isValid: true, isoTimestamp: d.toISOString(), originalValue: input };
        }
      }
    }

    return {
      isValid: false,
      isoTimestamp: new Date().toISOString(),
      originalValue: input,
      error: `Unparseable timestamp format: "${str}"`
    };
  }

  /**
   * Backwards compatible standardization helper.
   */
  static standardizeTimestamp(input: string | number | undefined): string {
    return this.parseAndCheckTimestamp(input).isoTimestamp;
  }
}
