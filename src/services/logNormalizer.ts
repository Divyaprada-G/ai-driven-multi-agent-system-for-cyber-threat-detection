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

    // Helper to find field value across aliases
    const findValue = <T = unknown>(aliases: string[]): T | undefined => {
      // Direct case match
      for (const alias of aliases) {
        if (rawRecord[alias] !== undefined && rawRecord[alias] !== null && rawRecord[alias] !== '') {
          mappedKeys.add(alias);
          return rawRecord[alias] as T;
        }
      }
      // Case-insensitive / underscore-insensitive match
      const aliasClean = aliases.map(a => a.toLowerCase().replace(/[-_]/g, ''));
      for (const key of rawKeys) {
        const cleanKey = key.toLowerCase().replace(/[-_]/g, '');
        if (aliasClean.includes(cleanKey)) {
          if (rawRecord[key] !== undefined && rawRecord[key] !== null && rawRecord[key] !== '') {
            mappedKeys.add(key);
            return rawRecord[key] as T;
          }
        }
      }
      return undefined;
    };

    // 1. Timestamp Normalization
    const rawTime = findValue<string | number>([
      'timestamp', '@timestamp', 'time', 'datetime', 'event_time', 'date', 'log_time', 'time_stamp'
    ]);
    const normalizedTimestamp = this.standardizeTimestamp(rawTime);

    // 2. Determine Log Type
    const logType: LogType = options.logType || 'NETWORK';

    // 3. Extract Normalized Domain Fields
    const normalizedFields: NormalizedFields = {};

    // --- Network Fields ---
    const rawSrcIp = findValue<string>([
      'sourceIp', 'src_ip', 'srcip', 'source_ip', 'ip_src', 'src_addr', 'client_ip', 'src', 'sourceIPAddress'
    ]);
    if (rawSrcIp) normalizedFields.sourceIp = String(rawSrcIp).trim();

    const rawDstIp = findValue<string>([
      'destinationIp', 'dest_ip', 'dst_ip', 'dstip', 'destination_ip', 'ip_dst', 'dst_addr', 'server_ip', 'dst', 'destinationIPAddress'
    ]);
    if (rawDstIp) normalizedFields.destinationIp = String(rawDstIp).trim();

    const rawSrcPort = findValue<number | string>([
      'sourcePort', 'src_port', 'srcport', 'source_port', 'sport', 'srcPort', 'client_port'
    ]);
    if (rawSrcPort !== undefined) {
      const port = Number(rawSrcPort);
      if (!isNaN(port)) normalizedFields.sourcePort = port;
    }

    const rawDstPort = findValue<number | string>([
      'destinationPort', 'dest_port', 'dst_port', 'dstport', 'destination_port', 'dport', 'dstPort', 'server_port'
    ]);
    if (rawDstPort !== undefined) {
      const port = Number(rawDstPort);
      if (!isNaN(port)) normalizedFields.destinationPort = port;
    }

    const rawProto = findValue<string>([
      'protocol', 'proto', 'transport', 'network_protocol'
    ]);
    if (rawProto) normalizedFields.protocol = String(rawProto).toUpperCase().trim();

    const rawPacketSize = findValue<number | string>([
      'packetSize', 'packet_size', 'length', 'bytes', 'size', 'tot_len', 'bytes_toserver'
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
      ingestionTimestamp: new Date().toISOString(),
      source: String(source).trim(),
      logType,
      message: String(message).trim(),
      rawData: options.rawString || JSON.stringify(rawRecord),
      format: options.format || 'JSON',
      normalizedFields,
      metadata: unmappedKeys.length > 0 ? { unmapped: Object.fromEntries(unmappedKeys.map(k => [k, rawRecord[k]])) } : undefined
    };

    return { event, unmappedKeys };
  }

  /**
   * Safely standardizes various date formats into an ISO 8601 string.
   */
  static standardizeTimestamp(input: string | number | undefined): string {
    if (!input) {
      return new Date().toISOString();
    }

    // Epoch timestamp (seconds or milliseconds)
    if (typeof input === 'number' || /^\d{10,13}$/.test(String(input))) {
      const num = Number(input);
      const millis = num < 10000000000 ? num * 1000 : num;
      const d = new Date(millis);
      if (!isNaN(d.getTime())) return d.toISOString();
    }

    const str = String(input).trim();

    // Standard ISO 8601 string
    const isoDate = new Date(str);
    if (!isNaN(isoDate.getTime())) {
      return isoDate.toISOString();
    }

    // Apache / Nginx format: 11/Sep/2026:22:19:58 +0000
    const apacheMatch = str.match(/^(\d{1,2})\/([a-zA-Z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/);
    if (apacheMatch) {
      const [, day, month, year, h, m, s, tz] = apacheMatch;
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const monthIndex = monthNames.findIndex(mn => mn.toLowerCase() === month.toLowerCase());
      if (monthIndex !== -1) {
        const d = new Date(Date.UTC(Number(year), monthIndex, Number(day), Number(h), Number(m), Number(s)));
        if (!isNaN(d.getTime())) return d.toISOString();
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
        if (!isNaN(d.getTime())) return d.toISOString();
      }
    }

    // Fallback
    return new Date().toISOString();
  }
}
