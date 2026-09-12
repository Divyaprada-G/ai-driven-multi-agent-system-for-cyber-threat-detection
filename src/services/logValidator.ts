import { LogEvent, LogValidationResult } from '../types';

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;

export class LogValidator {
  /**
   * Validates a normalized LogEvent against security schema standards.
   */
  static validate(event: LogEvent): LogValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // 1. Mandatory Core Attributes
    if (!event.id || typeof event.id !== 'string' || event.id.trim() === '') {
      errors.push('Missing or invalid unique event identifier [id]');
    }

    if (!event.source || typeof event.source !== 'string' || event.source.trim() === '') {
      errors.push('Missing or empty origin source identifier [source]');
    }

    if (!event.message || typeof event.message !== 'string' || event.message.trim() === '') {
      errors.push('Missing or blank human-readable log message [message]');
    }

    if (!['NETWORK', 'SYSTEM', 'APPLICATION'].includes(event.logType)) {
      errors.push(`Unrecognized logType domain classification: "${event.logType}"`);
    }

    // 2. Timestamp Validation
    if (!event.timestamp) {
      errors.push('Missing timestamp');
    } else {
      const parsedTime = new Date(event.timestamp);
      if (isNaN(parsedTime.getTime())) {
        errors.push(`Unparseable timestamp format: "${event.timestamp}"`);
      } else {
        const now = Date.now();
        const eventEpoch = parsedTime.getTime();
        // Check if unreasonably far into future (>24 hours)
        if (eventEpoch > now + 24 * 60 * 60 * 1000) {
          warnings.push(`Timestamp is >24 hours in the future: ${event.timestamp}`);
        }
        // Check if pre-epoch or before 1995
        if (eventEpoch < new Date('1995-01-01').getTime()) {
          warnings.push(`Timestamp is historical (< 1995): ${event.timestamp}`);
        }
      }
    }

    // 3. Domain Specific Validations (Normalized Fields)
    const nf = event.normalizedFields || {};

    if (event.logType === 'NETWORK') {
      if (nf.sourceIp && !this.isValidIp(nf.sourceIp)) {
        errors.push(`Malformed source IPv4/IPv6 address syntax: "${nf.sourceIp}"`);
      }
      if (nf.destinationIp && !this.isValidIp(nf.destinationIp)) {
        errors.push(`Malformed destination IPv4/IPv6 address syntax: "${nf.destinationIp}"`);
      }
      if (nf.sourcePort !== undefined) {
        if (!Number.isInteger(nf.sourcePort) || nf.sourcePort < 0 || nf.sourcePort > 65535) {
          errors.push(`Source port out of valid range (0-65535): ${nf.sourcePort}`);
        }
      }
      if (nf.destinationPort !== undefined) {
        if (!Number.isInteger(nf.destinationPort) || nf.destinationPort < 0 || nf.destinationPort > 65535) {
          errors.push(`Destination port out of valid range (0-65535): ${nf.destinationPort}`);
        }
      }
      if (nf.protocol) {
        const knownProtos = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'SSH', 'FTP', 'SMTP', 'ARP', 'IGMP', 'IPV4', 'IPV6'];
        if (!knownProtos.includes(nf.protocol.toUpperCase())) {
          warnings.push(`Non-standard transport protocol specification: "${nf.protocol}"`);
        }
      }
    } else if (event.logType === 'SYSTEM') {
      if (nf.processId !== undefined) {
        if (!Number.isInteger(nf.processId) || nf.processId < 0) {
          errors.push(`Invalid host process ID (must be non-negative integer): ${nf.processId}`);
        }
      }
      if (nf.processName !== undefined && nf.processName.trim() === '') {
        warnings.push('Host process name field is present but empty');
      }
    } else if (event.logType === 'APPLICATION') {
      if (nf.statusCode !== undefined) {
        if (!Number.isInteger(nf.statusCode) || nf.statusCode < 100 || nf.statusCode > 599) {
          errors.push(`HTTP status code out of RFC specification range (100-599): ${nf.statusCode}`);
        }
      }
      if (nf.httpMethod) {
        const knownMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
        if (!knownMethods.includes(nf.httpMethod.toUpperCase())) {
          warnings.push(`Non-standard HTTP request method verb: "${nf.httpMethod}"`);
        }
      }
    }

    const isValid = errors.length === 0;

    return {
      status: isValid ? 'VALID' : 'INVALID',
      errors,
      warnings
    };
  }

  private static isValidIp(ip: string): boolean {
    const trimmed = ip.trim();
    return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed) || trimmed === 'localhost' || trimmed === '127.0.0.1' || trimmed === '::1';
  }
}
