import {
  LogEvent,
  LogValidationResult,
  RowValidationStatus,
  StructuredValidationResult,
  ValidationErrorItem,
  ValidationErrorSeverity
} from '../types';

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;

const KNOWN_PROTOCOLS = new Set([
  'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'SSH', 'FTP', 'SMTP',
  'ARP', 'IGMP', 'IPV4', 'IPV6', 'GRE', 'ESP', 'AH', 'EGP', 'OSPF', 'SCTP',
  '6', '17', '1', 'HOPOPT', 'GGP', 'ST', 'CBT', 'BBN-RCC-MON', 'NVP-II',
  'PUP', 'ARGUS', 'EMCON', 'XNET', 'CHAOS', 'MUX', 'DCN-MEAS', 'HMP', 'PRM',
  'XNS-IDP', 'TRUNK-1', 'TRUNK-2', 'LEAF-1', 'LEAF-2', 'RDP', 'IRTP',
  'ISO-TP4', 'NETBLT', 'MFE-NSP', 'MERIT-INP', 'DCCP', '3PC', 'IDPR', 'XTP',
  'DDP', 'IDPR-CMTP', 'TP++', 'IL'
]);

export interface ValidationOptions {
  row_id?: string | number;
  originalRecord?: Record<string, unknown> | string;
  isDuplicate?: boolean;
  isProcessingError?: boolean;
  processingErrorMessage?: string;
  datasetHeaders?: string[];
  hasLabelColumn?: boolean;
  requireIp?: boolean;
  requireProtocol?: boolean;
}

export class LogValidator {
  /**
   * Helper to retrieve field value across case-insensitive aliases from original record.
   */
  private static getRawValue(
    record: Record<string, unknown> | undefined,
    aliases: string[]
  ): { key: string; value: unknown; found: boolean } {
    if (!record || typeof record !== 'object') {
      return { key: '', value: undefined, found: false };
    }
    const cleanAliases = aliases.map(a => a.toLowerCase().replace(/[-_ \t]/g, ''));
    for (const key of Object.keys(record)) {
      const cleanKey = key.toLowerCase().replace(/[-_ \t]/g, '');
      if (cleanAliases.includes(cleanKey)) {
        return { key, value: record[key], found: true };
      }
    }
    return { key: '', value: undefined, found: false };
  }

  /**
   * Validates a normalized LogEvent or raw dataset row and produces a full StructuredValidationResult.
   */
  static validate(event: LogEvent, options: ValidationOptions = {}): StructuredValidationResult {
    const errors: ValidationErrorItem[] = [];
    const warnings: ValidationErrorItem[] = [];

    const nf = event.normalizedFields || {};
    const rawRec = (options.originalRecord && typeof options.originalRecord === 'object'
      ? (options.originalRecord as Record<string, unknown>)
      : typeof event.originalData === 'object' && event.originalData !== null
      ? (event.originalData as Record<string, unknown>)
      : undefined);

    const headers = options.datasetHeaders || (rawRec ? Object.keys(rawRec) : []);

    // -------------------------------------------------------------
    // 1. PROCESSING ERROR CHECK
    // -------------------------------------------------------------
    if (options.isProcessingError || nf.hasMalformedRecord || nf.parseError) {
      errors.push({
        field: 'record',
        error_code: 'PROCESSING_ERROR',
        message: options.processingErrorMessage || nf.parseError || 'Malformed record or parser syntax error',
        severity: 'ERROR',
        original_value: event.rawData || options.originalRecord || ''
      });
    }

    // -------------------------------------------------------------
    // 2. DUPLICATE CHECK (DUPLICATE_EVENT)
    // -------------------------------------------------------------
    const isDup = Boolean(options.isDuplicate || event.isDuplicate);
    if (isDup) {
      errors.push({
        field: 'record',
        error_code: 'DUPLICATE_EVENT',
        message: `Duplicate event detected in stream (fingerprint: ${event.fingerprint || event.id})`,
        severity: 'ERROR',
        original_value: event.fingerprint || event.id
      });
    }

    // -------------------------------------------------------------
    // 3. MANDATORY CORE ATTRIBUTES
    // -------------------------------------------------------------
    if (!event.id || typeof event.id !== 'string' || event.id.trim() === '') {
      errors.push({
        field: 'id',
        error_code: 'MISSING_ID',
        message: 'Missing or invalid unique event identifier [id]',
        severity: 'ERROR',
        original_value: event.id
      });
    }

    if (!event.source || typeof event.source !== 'string' || event.source.trim() === '') {
      errors.push({
        field: 'source',
        error_code: 'MISSING_SOURCE',
        message: 'Missing or empty origin source identifier [source]',
        severity: 'ERROR',
        original_value: event.source
      });
    }

    if (!event.message || typeof event.message !== 'string' || event.message.trim() === '') {
      errors.push({
        field: 'message',
        error_code: 'MISSING_MESSAGE',
        message: 'Missing or blank log message [message]',
        severity: 'ERROR',
        original_value: event.message
      });
    }

    // -------------------------------------------------------------
    // 4. TIMESTAMP VALIDATION (INVALID_TIMESTAMP)
    // -------------------------------------------------------------
    const rawTsEntry = this.getRawValue(rawRec, [
      'timestamp', '@timestamp', 'time', 'datetime', 'event_time', 'date', 'log_time', 'time_stamp', 'Timestamp'
    ]);
    const originalTs = nf.originalTimestamp !== undefined ? nf.originalTimestamp : rawTsEntry.value;

    if (nf.hasInvalidTimestamp) {
      errors.push({
        field: 'timestamp',
        error_code: 'INVALID_TIMESTAMP',
        message: `Invalid, unparseable, or missing timestamp: "${originalTs ?? ''}"`,
        severity: 'ERROR',
        original_value: originalTs ?? ''
      });
    } else if (!event.timestamp || event.timestamp.trim() === '') {
      errors.push({
        field: 'timestamp',
        error_code: 'INVALID_TIMESTAMP',
        message: 'Missing timestamp attribute',
        severity: 'ERROR',
        original_value: ''
      });
    } else {
      const parsedTime = new Date(event.timestamp);
      if (isNaN(parsedTime.getTime())) {
        errors.push({
          field: 'timestamp',
          error_code: 'INVALID_TIMESTAMP',
          message: `Unparseable timestamp format: "${event.timestamp}"`,
          severity: 'ERROR',
          original_value: originalTs ?? event.timestamp
        });
      } else {
        const now = Date.now();
        const eventEpoch = parsedTime.getTime();
        // Check if unreasonably far into future (>24 hours)
        if (eventEpoch > now + 24 * 60 * 60 * 1000) {
          warnings.push({
            field: 'timestamp',
            error_code: 'FUTURE_TIMESTAMP',
            message: `Timestamp is >24 hours in the future: ${event.timestamp}`,
            severity: 'WARNING',
            original_value: originalTs ?? event.timestamp
          });
        }
        // Check if pre-epoch or before 1995
        if (eventEpoch < new Date('1995-01-01').getTime()) {
          warnings.push({
            field: 'timestamp',
            error_code: 'HISTORICAL_TIMESTAMP',
            message: `Timestamp is historical (< 1995): ${event.timestamp}`,
            severity: 'WARNING',
            original_value: originalTs ?? event.timestamp
          });
        }
      }
    }

    // -------------------------------------------------------------
    // 5. IP ADDRESS VALIDATION (MISSING_IP, INVALID_IP)
    // -------------------------------------------------------------
    const srcIpEntry = this.getRawValue(rawRec, [
      'sourceIp', 'src_ip', 'srcip', 'source_ip', 'ip_src', 'src_addr', 'client_ip', 'src', 'sourceIPAddress', 'Source IP', 'Src IP'
    ]);
    const hasIpHeader = headers.some(h => /^(sourceip|src_ip|srcip|source_ip|ip_src|src_addr|client_ip|src|sourceipaddress|source ip|src ip)$/i.test(h));
    const isNetworkDomain = event.logType === 'NETWORK' || options.requireIp || hasIpHeader || srcIpEntry.found;

    if (isNetworkDomain) {
      const srcIpValue = nf.sourceIp !== undefined ? nf.sourceIp : (srcIpEntry.value as string);
      if (srcIpValue === undefined || srcIpValue === null || String(srcIpValue).trim() === '' || /^(nan|null|none|-)$/i.test(String(srcIpValue).trim())) {
        errors.push({
          field: 'sourceIp',
          error_code: 'MISSING_IP',
          message: 'Missing or empty source IP address in network flow telemetry',
          severity: 'ERROR',
          original_value: srcIpEntry.value ?? ''
        });
      } else if (!this.isValidIp(String(srcIpValue))) {
        errors.push({
          field: 'sourceIp',
          error_code: 'INVALID_IP',
          message: `Malformed source IPv4/IPv6 address syntax: "${srcIpValue}"`,
          severity: 'ERROR',
          original_value: srcIpValue
        });
      }

      // Check destination IP if present or if in headers
      const dstIpEntry = this.getRawValue(rawRec, [
        'destinationIp', 'dest_ip', 'dst_ip', 'dstip', 'destination_ip', 'ip_dst', 'dst_addr', 'server_ip', 'dst', 'destinationIPAddress', 'Destination IP', 'Dst IP'
      ]);
      const dstIpValue = nf.destinationIp !== undefined ? nf.destinationIp : (dstIpEntry.value as string);
      if (dstIpValue !== undefined && dstIpValue !== null && String(dstIpValue).trim() !== '' && !/^(nan|null|none|-)$/i.test(String(dstIpValue).trim())) {
        if (!this.isValidIp(String(dstIpValue))) {
          errors.push({
            field: 'destinationIp',
            error_code: 'INVALID_IP',
            message: `Malformed destination IPv4/IPv6 address syntax: "${dstIpValue}"`,
            severity: 'ERROR',
            original_value: dstIpValue
          });
        }
      }
    }

    // -------------------------------------------------------------
    // 6. PROTOCOL VALIDATION (INVALID_PROTOCOL)
    // -------------------------------------------------------------
    const protoEntry = this.getRawValue(rawRec, [
      'protocol', 'proto', 'transport', 'network_protocol', 'Protocol', 'protocol_type'
    ]);
    const hasProtoHeader = headers.some(h => /^(protocol|proto|transport|network_protocol|protocol_type)$/i.test(h));
    const shouldCheckProto = isNetworkDomain || options.requireProtocol || hasProtoHeader || protoEntry.found;

    if (shouldCheckProto) {
      const protoVal = nf.protocol !== undefined ? nf.protocol : (protoEntry.value as string);
      if (protoVal === undefined || protoVal === null || String(protoVal).trim() === '' || /^(nan|null|none|-)$/i.test(String(protoVal).trim())) {
        errors.push({
          field: 'protocol',
          error_code: 'INVALID_PROTOCOL',
          message: 'Missing or empty transport protocol specification',
          severity: 'ERROR',
          original_value: protoEntry.value ?? ''
        });
      } else {
        const cleanProto = String(protoVal).toUpperCase().trim();
        if (!KNOWN_PROTOCOLS.has(cleanProto)) {
          // Check if numeric protocol in range 0-255
          const numProto = Number(cleanProto);
          const isNumericValid = !isNaN(numProto) && Number.isInteger(numProto) && numProto >= 0 && numProto <= 255;
          if (!isNumericValid) {
            errors.push({
              field: 'protocol',
              error_code: 'INVALID_PROTOCOL',
              message: `Invalid or unrecognized transport protocol: "${protoVal}"`,
              severity: 'ERROR',
              original_value: protoEntry.value ?? protoVal
            });
          }
        }
      }
    }

    // -------------------------------------------------------------
    // 7. FAILED LOGINS VALIDATION (NEGATIVE_FAILED_LOGINS)
    // -------------------------------------------------------------
    const failedLoginsEntry = this.getRawValue(rawRec, [
      'num_failed_logins', 'num_failed_login', 'failed_logins', 'failed_login', 'failedLogins', 'failed_login_count', 'failedLoginCount'
    ]);
    const failedLoginsVal = nf.numFailedLogins !== undefined
      ? nf.numFailedLogins
      : (failedLoginsEntry.found ? Number(failedLoginsEntry.value) : undefined);

    if (failedLoginsVal !== undefined && !isNaN(failedLoginsVal)) {
      if (failedLoginsVal < 0) {
        errors.push({
          field: 'num_failed_logins',
          error_code: 'NEGATIVE_FAILED_LOGINS',
          message: `Negative failed login count detected: ${failedLoginsVal}. Failed logins must be a non-negative integer.`,
          severity: 'ERROR',
          original_value: failedLoginsEntry.value ?? failedLoginsVal
        });
      }
    }

    // -------------------------------------------------------------
    // 8. DATASET LABEL VALIDATION (MISSING_LABEL)
    // -------------------------------------------------------------
    const labelEntry = this.getRawValue(rawRec, [
      'label', 'Label', 'attack_cat', 'class', 'target', 'threat_class', 'category'
    ]);
    const hasLabelHeader = Boolean(options.hasLabelColumn || headers.some(h => /^(label|class|attack_cat|target|threat_class)$/i.test(h)));

    if (hasLabelHeader || labelEntry.found) {
      const labelVal = nf.label !== undefined ? nf.label : (labelEntry.value as string);
      if (labelVal === undefined || labelVal === null || String(labelVal).trim() === '' || /^(nan|null|none|undefined|-)$/i.test(String(labelVal).trim())) {
        errors.push({
          field: 'label',
          error_code: 'MISSING_LABEL',
          message: 'Missing ground truth classification or threat category label',
          severity: 'ERROR',
          original_value: labelEntry.value ?? ''
        });
      }
    }

    // -------------------------------------------------------------
    // 9. PORT & DOMAIN SPECIFIC RANGE CHECKS
    // -------------------------------------------------------------
    if (nf.sourcePort !== undefined) {
      if (!Number.isInteger(nf.sourcePort) || nf.sourcePort < 0 || nf.sourcePort > 65535) {
        errors.push({
          field: 'sourcePort',
          error_code: 'INVALID_PORT',
          message: `Source port out of valid range (0-65535): ${nf.sourcePort}`,
          severity: 'ERROR',
          original_value: nf.sourcePort
        });
      }
    }

    if (nf.destinationPort !== undefined) {
      if (!Number.isInteger(nf.destinationPort) || nf.destinationPort < 0 || nf.destinationPort > 65535) {
        errors.push({
          field: 'destinationPort',
          error_code: 'INVALID_PORT',
          message: `Destination port out of valid range (0-65535): ${nf.destinationPort}`,
          severity: 'ERROR',
          original_value: nf.destinationPort
        });
      }
    }

    if (event.logType === 'SYSTEM') {
      if (nf.processId !== undefined) {
        if (!Number.isInteger(nf.processId) || nf.processId < 0) {
          errors.push({
            field: 'processId',
            error_code: 'INVALID_PID',
            message: `Invalid host process ID (must be non-negative integer): ${nf.processId}`,
            severity: 'ERROR',
            original_value: nf.processId
          });
        }
      }
      if (nf.processName !== undefined && nf.processName.trim() === '') {
        warnings.push({
          field: 'processName',
          error_code: 'EMPTY_PROCESS_NAME',
          message: 'Host process name field is present but empty',
          severity: 'WARNING',
          original_value: ''
        });
      }
    } else if (event.logType === 'APPLICATION') {
      if (nf.statusCode !== undefined) {
        if (!Number.isInteger(nf.statusCode) || nf.statusCode < 100 || nf.statusCode > 599) {
          errors.push({
            field: 'statusCode',
            error_code: 'INVALID_STATUS_CODE',
            message: `HTTP status code out of RFC specification range (100-599): ${nf.statusCode}`,
            severity: 'ERROR',
            original_value: nf.statusCode
          });
        }
      }
      if (nf.httpMethod) {
        const knownMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
        if (!knownMethods.includes(nf.httpMethod.toUpperCase())) {
          warnings.push({
            field: 'httpMethod',
            error_code: 'NON_STANDARD_HTTP_METHOD',
            message: `Non-standard HTTP request method verb: "${nf.httpMethod}"`,
            severity: 'WARNING',
            original_value: nf.httpMethod
          });
        }
      }
    }

    // -------------------------------------------------------------
    // 10. STATUS & IS_VALID DETERMINATION
    // -------------------------------------------------------------
    let validation_status: RowValidationStatus = 'VALID';
    let is_valid = true;

    if (options.isProcessingError || errors.some(e => e.error_code === 'PROCESSING_ERROR')) {
      validation_status = 'PROCESSING_ERROR';
      is_valid = false;
    } else if (isDup || errors.some(e => e.error_code === 'DUPLICATE_EVENT')) {
      validation_status = 'DUPLICATE';
      is_valid = false;
    } else if (errors.length > 0) {
      validation_status = 'INVALID';
      is_valid = false;
    } else if (warnings.length > 0) {
      validation_status = 'WARNING';
      is_valid = true;
    } else {
      validation_status = 'VALID';
      is_valid = true;
    }

    const rowId = options.row_id !== undefined ? String(options.row_id) : `row-${event.id}`;

    const structuredResult: StructuredValidationResult = {
      row_id: rowId,
      event_id: event.id,
      is_valid,
      validation_status,
      status: is_valid ? 'VALID' : 'INVALID',
      errors,
      warnings,
      original_data: rawRec || (event.originalData as Record<string, unknown>) || event.rawData || {},
      normalized_data: (nf as Record<string, unknown>) || null,
      detected_at: new Date().toISOString()
    };

    // Attach to event for downstream components
    event.structuredValidation = structuredResult;
    event.validation = {
      status: is_valid ? 'VALID' : 'INVALID',
      errors: errors.map(e => e.message),
      warnings: warnings.map(w => w.message),
      structured: structuredResult
    };

    return structuredResult;
  }

  /**
   * Validates IP address syntax (IPv4 or IPv6 or localhost).
   */
  private static isValidIp(ip: string): boolean {
    const trimmed = ip.trim();
    return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed) || trimmed === 'localhost' || trimmed === '127.0.0.1' || trimmed === '::1';
  }
}
