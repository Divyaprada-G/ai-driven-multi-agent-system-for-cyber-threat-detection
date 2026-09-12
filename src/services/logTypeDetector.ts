import { LogType } from '../types';

interface DetectionResult {
  detectedType: LogType;
  confidence: number; // 0.0 to 1.0
  reasons: string[];
}

const NETWORK_INDICATORS = [
  'src_ip', 'dst_ip', 'sourceip', 'destinationip', 'source_ip', 'dest_ip', 'destination_ip',
  'src_port', 'dst_port', 'sourceport', 'destinationport', 'sport', 'dport',
  'proto', 'protocol', 'flow_id', 'packet', 'bytes_toclient', 'bytes_toserver',
  'in_iface', 'out_iface', 'tcp', 'udp', 'icmp', 'dns', 'pcap', 'suricata', 'snort',
  'zeek', 'bro', 'netflow', 'sflow', 'ip_src', 'ip_dst', 'client_ip', 'server_ip'
];

const SYSTEM_INDICATORS = [
  'processid', 'process_id', 'pid', 'processname', 'process_name', 'process', 'image', 'exe',
  'cmdline', 'commandline', 'command_line', 'parentprocess', 'parent_process', 'ppid',
  'parent_image', 'hostname', 'host', 'computer_name', 'username', 'user', 'user_id',
  'account', 'eventid', 'event_id', 'sysmon', 'wazuh', 'auditd', 'sudo', 'systemd',
  'winlog', 'integritylevel', 'security_id', 'logon_type', 'osquery', 'kernel'
];

const APPLICATION_INDICATORS = [
  'httpmethod', 'http_method', 'method', 'verb', 'endpoint', 'uri', 'url', 'path',
  'request_uri', 'request_path', 'statuscode', 'status_code', 'http_status', 'status',
  'useragent', 'user_agent', 'http_user_agent', 'payload', 'body', 'request_body',
  'referrer', 'referer', 'nginx', 'apache', 'waf', 'graphql', 'rest', 'api',
  'request_time', 'upstream_response_time', 'cookie', 'session_id'
];

export class LogTypeDetector {
  /**
   * Detects domain log type from a parsed object's keys and values.
   */
  static detectFromObject(obj: Record<string, unknown>): DetectionResult {
    let networkScore = 0;
    let systemScore = 0;
    let appScore = 0;
    const reasons: string[] = [];

    const keys = Object.keys(obj).map(k => k.toLowerCase().replace(/[-_]/g, ''));
    const rawKeys = Object.keys(obj).map(k => k.toLowerCase());

    // Check Network indicators
    for (const ind of NETWORK_INDICATORS) {
      const cleanInd = ind.replace(/[-_]/g, '');
      if (keys.includes(cleanInd) || rawKeys.includes(ind)) {
        networkScore += 2;
        reasons.push(`Matched network field: ${ind}`);
      }
    }

    // Check System indicators
    for (const ind of SYSTEM_INDICATORS) {
      const cleanInd = ind.replace(/[-_]/g, '');
      if (keys.includes(cleanInd) || rawKeys.includes(ind)) {
        systemScore += 2;
        reasons.push(`Matched system field: ${ind}`);
      }
    }

    // Check Application indicators
    for (const ind of APPLICATION_INDICATORS) {
      const cleanInd = ind.replace(/[-_]/g, '');
      if (keys.includes(cleanInd) || rawKeys.includes(ind)) {
        appScore += 2;
        reasons.push(`Matched application field: ${ind}`);
      }
    }

    // Content heuristics in object values
    const stringified = JSON.stringify(obj).toLowerCase();
    if (stringified.includes('suricata') || stringified.includes('"event_type":"alert"') || stringified.includes('"proto":"tcp"')) {
      networkScore += 4;
      reasons.push('Suricata / EVE network telemetry signature identified');
    }
    if (stringified.includes('sysmon') || stringified.includes('eventid=1') || stringified.includes('powershell') || stringified.includes('cmd.exe')) {
      systemScore += 4;
      reasons.push('Sysmon / Windows host event signature identified');
    }
    if (stringified.includes('http/1.') || stringified.includes('http/2') || stringified.includes('get /') || stringified.includes('post /') || stringified.includes('union select')) {
      appScore += 4;
      reasons.push('Web HTTP / Application payload signature identified');
    }

    return this.calculateWinner(networkScore, systemScore, appScore, reasons);
  }

  /**
   * Detects domain log type from a raw text line (e.g. Syslog, Apache, etc.).
   */
  static detectFromString(line: string): DetectionResult {
    let networkScore = 0;
    let systemScore = 0;
    let appScore = 0;
    const reasons: string[] = [];
    const lower = line.toLowerCase();

    // Application patterns: HTTP methods with status codes
    const httpRegex = /"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^"]+\s+HTTP\/[0-9.]+"/i;
    if (httpRegex.test(line)) {
      appScore += 8;
      reasons.push('Contains HTTP request line pattern (method, URI, HTTP version)');
    }
    if (/status=\d{3}/i.test(line) || /\s\d{3}\s\d+\s/i.test(line)) {
      appScore += 3;
      reasons.push('Contains HTTP numeric status code pattern');
    }

    // System patterns: Syslog daemons, sudo, pam, auditd, pids
    const systemDaemonRegex = /(sshd|sudo|pam_unix|auditd|systemd|cron|kernel|login|su)\[?\d*\]?:/i;
    if (systemDaemonRegex.test(line)) {
      systemScore += 8;
      reasons.push('Contains Linux/Unix system service or daemon tag');
    }
    if (/eventid\s*=\s*\d+/i.test(line) || /process\s*=\s*\S+/i.test(line) || /pid\s*=\s*\d+/i.test(line)) {
      systemScore += 6;
      reasons.push('Contains host process/event ID attributes');
    }

    // Network patterns: IP:Port -> IP:Port, TCP flags, ICMP, DNS
    const ipPortRegex = /\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\s*(?:->|>)\s*\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b/;
    if (ipPortRegex.test(line)) {
      networkScore += 8;
      reasons.push('Contains directional IP:port socket flow');
    }
    if (/\b(SYN|ACK|FIN|RST|PSH|URG)\b/.test(line) && /\b(TCP|UDP|ICMP)\b/i.test(line)) {
      networkScore += 5;
      reasons.push('Contains TCP/UDP protocol headers and transport flags');
    }

    return this.calculateWinner(networkScore, systemScore, appScore, reasons);
  }

  /**
   * Detects hint from filename.
   */
  static detectFromFilename(filename: string): LogType | null {
    const lower = filename.toLowerCase();
    if (lower.includes('net') || lower.includes('suricata') || lower.includes('snort') || lower.includes('pcap') || lower.includes('flow') || lower.includes('zeek') || lower.includes('dns')) {
      return 'NETWORK';
    }
    if (lower.includes('sys') || lower.includes('host') || lower.includes('wazuh') || lower.includes('auth') || lower.includes('event') || lower.includes('audit') || lower.includes('proc')) {
      return 'SYSTEM';
    }
    if (lower.includes('app') || lower.includes('nginx') || lower.includes('apache') || lower.includes('web') || lower.includes('http') || lower.includes('access') || lower.includes('api')) {
      return 'APPLICATION';
    }
    return null;
  }

  /**
   * Main detection entry point.
   */
  static detect(input: Record<string, unknown> | string, filename?: string): DetectionResult {
    let result: DetectionResult;

    if (typeof input === 'object' && input !== null) {
      result = this.detectFromObject(input);
    } else {
      result = this.detectFromString(String(input));
    }

    // Incorporate filename hint if confidence is low
    if (filename && result.confidence < 0.65) {
      const fileHint = this.detectFromFilename(filename);
      if (fileHint) {
        result.detectedType = fileHint;
        result.confidence = Math.max(result.confidence, 0.75);
        result.reasons.push(`Inferred from filename pattern: ${filename}`);
      }
    }

    return result;
  }

  private static calculateWinner(net: number, sys: number, app: number, reasons: string[]): DetectionResult {
    const total = net + sys + app;
    if (total === 0) {
      return {
        detectedType: 'SYSTEM',
        confidence: 0.35,
        reasons: ['No clear domain indicators detected; defaulted to SYSTEM']
      };
    }

    if (net >= sys && net >= app) {
      return {
        detectedType: 'NETWORK',
        confidence: Math.min(0.98, Number((net / (total || 1)).toFixed(2)) + 0.2),
        reasons
      };
    } else if (sys >= net && sys >= app) {
      return {
        detectedType: 'SYSTEM',
        confidence: Math.min(0.98, Number((sys / (total || 1)).toFixed(2)) + 0.2),
        reasons
      };
    } else {
      return {
        detectedType: 'APPLICATION',
        confidence: Math.min(0.98, Number((app / (total || 1)).toFixed(2)) + 0.2),
        reasons
      };
    }
  }
}
