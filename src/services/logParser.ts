import { LogEvent, LogFileFormat, LogType } from '../types';
import { LogTypeDetector } from './logTypeDetector';
import { LogNormalizer } from './logNormalizer';
import { LogValidator } from './logValidator';
import { DuplicateDetector } from './duplicateDetector';

export interface ParseResult {
  format: LogFileFormat;
  detectedLogType: LogType;
  events: LogEvent[];
  validCount: number;
  invalidCount: number;
  warningCount: number;
  duplicateCount: number;
  processingErrorCount: number;
  validationPercentage: number;
  parseErrors: string[];
}

export class LogParser {
  private duplicateDetector: DuplicateDetector;
  private lastParsedHeaders: string[] = [];

  constructor(duplicateDetector?: DuplicateDetector) {
    this.duplicateDetector = duplicateDetector || new DuplicateDetector();
  }

  /**
   * Auto-detects the structural format of the file or text payload.
   */
  static detectFormat(content: string, filename?: string): LogFileFormat {
    const trimmed = content.trim();

    // Check extension hint first
    if (filename) {
      const lower = filename.toLowerCase();
      if (lower.endsWith('.csv')) return 'CSV';
      if (lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) return 'JSONL';
      if (lower.endsWith('.json')) {
        if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
          // Verify if it's a single JSON or lines
          try {
            JSON.parse(trimmed);
            return 'JSON';
          } catch {
            return 'JSONL';
          }
        }
      }
    }

    // Check if entire content is valid JSON array or object
    if ((trimmed.startsWith('[') && trimmed.endsWith(']')) ||
        (trimmed.startsWith('{') && trimmed.endsWith('}') && !trimmed.includes('\n{"'))) {
      try {
        JSON.parse(trimmed);
        return 'JSON';
      } catch {
        // Fall through to JSONL or text
      }
    }

    const lines = trimmed.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (lines.length > 0) {
      const firstLine = lines[0].trim();

      // Check if first line is valid JSON
      if (firstLine.startsWith('{') && firstLine.endsWith('}')) {
        try {
          JSON.parse(firstLine);
          return 'JSONL';
        } catch {
          // not jsonl
        }
      }

      // Check CSV: header row with multiple commas/semicolons and common column names
      const commaCount = (firstLine.match(/,/g) || []).length;
      if (commaCount >= 2) {
        const lowerFirst = firstLine.toLowerCase();
        if (lowerFirst.includes('timestamp') || lowerFirst.includes('ip') || lowerFirst.includes('process') ||
            lowerFirst.includes('host') || lowerFirst.includes('user') || lowerFirst.includes('port') ||
            lowerFirst.includes('method') || lowerFirst.includes('event')) {
          return 'CSV';
        }
      }

      // Check Apache/Nginx Combined Log Format
      if (/^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+\s+\S+\s+HTTP\/[0-9.]+"/i.test(firstLine)) {
        return 'SYSLOG';
      }

      // Check RFC 3164 / RFC 5424 Syslog
      if (/^<[0-9]+>/i.test(firstLine) ||
          /^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+/i.test(firstLine)) {
        return 'SYSLOG';
      }

      // Check Key-Value pair format
      if (/^[a-zA-Z0-9_.-]+=[^\s=]+(?:\s+[a-zA-Z0-9_.-]+=[^\s=]+){2,}/.test(firstLine)) {
        return 'KEY_VALUE';
      }
    }

    return 'PLAINTEXT';
  }

  /**
   * Main parsing method that handles any supported format gracefully.
   */
  async parseContent(
    content: string,
    options: {
      filename?: string;
      overrideLogType?: LogType;
      overrideFormat?: LogFileFormat;
    } = {}
  ): Promise<ParseResult> {
    const format = options.overrideFormat || LogParser.detectFormat(content, options.filename);
    const parseErrors: string[] = [];
    const rawEvents: Array<{ rawRecord: Record<string, unknown>; rawString: string }> = [];

    // Parse according to detected format
    switch (format) {
      case 'JSON':
        this.parseJson(content, rawEvents, parseErrors);
        break;
      case 'JSONL':
        this.parseJsonLines(content, rawEvents, parseErrors);
        break;
      case 'CSV':
        this.parseCsv(content, rawEvents, parseErrors);
        break;
      case 'SYSLOG':
        this.parseSyslog(content, rawEvents, parseErrors);
        break;
      case 'KEY_VALUE':
        this.parseKeyValue(content, rawEvents, parseErrors);
        break;
      case 'PLAINTEXT':
      default:
        this.parsePlainText(content, rawEvents, parseErrors);
        break;
    }

    // Determine target LogType
    let detectedLogType: LogType = options.overrideLogType || 'NETWORK';
    if (!options.overrideLogType && rawEvents.length > 0) {
      // Sample first 5 records to detect overall logType
      const sample = rawEvents.slice(0, 5).map(e => e.rawRecord);
      const compositeObj: Record<string, unknown> = {};
      for (const item of sample) {
        Object.assign(compositeObj, item);
      }
      const det = LogTypeDetector.detect(compositeObj, options.filename);
      detectedLogType = det.detectedType;
    }

    // Normalize, Validate, and Deduplicate each event
    const events: LogEvent[] = [];
    let validCount = 0;
    let invalidCount = 0;
    let warningCount = 0;
    let duplicateCount = 0;
    let processingErrorCount = 0;

    const datasetHeaders = this.lastParsedHeaders || [];

    for (let i = 0; i < rawEvents.length; i++) {
      const { rawRecord, rawString } = rawEvents[i];

      // Determine item-specific log type if not overridden
      let itemLogType = detectedLogType;
      if (!options.overrideLogType) {
        const itemDet = LogTypeDetector.detect(rawRecord);
        if (itemDet.confidence > 0.8) {
          itemLogType = itemDet.detectedType;
        }
      }

      // 1. Normalization
      const { event } = LogNormalizer.normalize(rawRecord, {
        logType: itemLogType,
        format,
        rawString,
        index: i + 1,
        fallbackSource: options.filename || 'log-source'
      });

      // 2. Deduplication check FIRST
      const dupResult = this.duplicateDetector.checkAndRecord(event);
      event.isDuplicate = dupResult.isDuplicate;
      event.duplicateCount = dupResult.duplicateCount;
      event.fingerprint = dupResult.fingerprint;

      // 3. Validation with Structured Result
      const isProcessingErr = Boolean(rawRecord.isMalformed || rawRecord.hasMalformedRecord || rawRecord.parseError);
      const structuredResult = LogValidator.validate(event, {
        row_id: i + 1,
        originalRecord: rawRecord,
        isDuplicate: dupResult.isDuplicate,
        isProcessingError: isProcessingErr,
        processingErrorMessage: rawRecord.parseError as string | undefined,
        datasetHeaders: datasetHeaders.length > 0 ? datasetHeaders : Object.keys(rawRecord),
        hasLabelColumn: Boolean(
          datasetHeaders.some(h => /^(label|class|attack_cat|target|threat_class)$/i.test(h)) ||
          'label' in rawRecord || 'Label' in rawRecord
        )
      });

      event.structuredValidation = structuredResult;
      event.validation = {
        status: structuredResult.is_valid ? 'VALID' : 'INVALID',
        errors: structuredResult.errors.map(e => e.message),
        warnings: structuredResult.warnings.map(w => w.message),
        structured: structuredResult
      };

      if (structuredResult.validation_status === 'VALID') {
        validCount++;
      } else if (structuredResult.validation_status === 'WARNING') {
        warningCount++;
      } else if (structuredResult.validation_status === 'DUPLICATE') {
        duplicateCount++;
      } else if (structuredResult.validation_status === 'PROCESSING_ERROR') {
        processingErrorCount++;
      } else {
        invalidCount++;
      }

      events.push(event);
    }

    const totalProcessed = events.length;
    const validationPercentage = totalProcessed > 0
      ? Number(((validCount / totalProcessed) * 100).toFixed(1))
      : 100;

    return {
      format,
      detectedLogType,
      events,
      validCount,
      invalidCount,
      warningCount,
      duplicateCount,
      processingErrorCount,
      validationPercentage,
      parseErrors
    };
  }

  // --- Specialized Parsers ---

  private parseJson(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    try {
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          if (typeof item === 'object' && item !== null) {
            out.push({ rawRecord: item as Record<string, unknown>, rawString: JSON.stringify(item) });
          } else {
            out.push({ rawRecord: { message: String(item) }, rawString: String(item) });
          }
        }
      } else if (typeof parsed === 'object' && parsed !== null) {
        out.push({ rawRecord: parsed as Record<string, unknown>, rawString: content });
      } else {
        errors.push('JSON parsed but did not yield an object or array');
        out.push({ rawRecord: { message: String(parsed) }, rawString: content });
      }
    } catch (err) {
      errors.push(`JSON parse error: ${(err as Error).message}. Attempting JSONL fallback.`);
      this.parseJsonLines(content, out, errors);
    }
  }

  private parseJsonLines(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    const lines = content.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx].trim();
      if (!line) continue;

      try {
        const item = JSON.parse(line);
        if (typeof item === 'object' && item !== null) {
          out.push({ rawRecord: item as Record<string, unknown>, rawString: line });
        } else {
          out.push({ rawRecord: { message: String(item) }, rawString: line });
        }
      } catch (err) {
        errors.push(`Line ${idx + 1}: Invalid JSON syntax - ${(err as Error).message}`);
        // Keep as raw malformed record so user can inspect invalid logs
        out.push({
          rawRecord: {
            message: `[MALFORMED JSON] ${line.slice(0, 120)}`,
            rawLine: line,
            parseError: (err as Error).message
          },
          rawString: line
        });
      }
    }
  }

  private parseCsv(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (lines.length === 0) {
      errors.push('Empty CSV file provided');
      return;
    }

    const headers = this.parseCsvLine(lines[0]).map(h => h.trim());
    this.lastParsedHeaders = headers;
    if (headers.length === 0) {
      errors.push('Failed to parse CSV header row');
      return;
    }

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;

      try {
        const values = this.parseCsvLine(line);
        const record: Record<string, unknown> = {};

        for (let j = 0; j < headers.length; j++) {
          const key = headers[j] || `col_${j}`;
          const val = values[j] !== undefined ? values[j].trim() : '';
          record[key] = val;
        }

        out.push({ rawRecord: record, rawString: line });
      } catch (err) {
        errors.push(`Line ${i + 1}: Failed to parse CSV row - ${(err as Error).message}`);
        out.push({
          rawRecord: {
            message: `[MALFORMED CSV] ${line.slice(0, 120)}`,
            rawLine: line
          },
          rawString: line
        });
      }
    }
  }

  private parseCsvLine(text: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (char === '"') {
        if (inQuotes && text[i + 1] === '"') {
          current += '"';
          i++; // skip escaped quote
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === ',' && !inQuotes) {
        result.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    result.push(current);
    return result;
  }

  private parseSyslog(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);

    // Apache / Nginx combined log regex
    const webLogRegex = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]+)\s+HTTP\/[0-9.]+"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/i;

    // RFC 3164 Syslog regex: Month Day HH:MM:SS Host Daemon[PID]: Message
    const syslogRegex = /^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$/;

    // RFC 5424 Syslog: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    const rfc5424Regex = /^<(\d+)>[0-9]?\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[(.*?)\])?\s*(.*)$/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Try Apache/Nginx web log
      const webMatch = line.match(webLogRegex);
      if (webMatch) {
        const [, clientIp, user, timestamp, method, endpoint, statusCode, bytes, referer, userAgent] = webMatch;
        out.push({
          rawRecord: {
            timestamp,
            sourceIp: clientIp,
            userName: user !== '-' ? user : undefined,
            httpMethod: method,
            endpoint,
            statusCode: Number(statusCode),
            packetSize: bytes !== '-' ? Number(bytes) : undefined,
            userAgent: userAgent || undefined,
            message: `${method} ${endpoint} HTTP response ${statusCode}`,
            source: clientIp
          },
          rawString: line
        });
        continue;
      }

      // Try RFC 3164
      const sysMatch = line.match(syslogRegex);
      if (sysMatch) {
        const [, timestamp, hostName, processName, pid, message] = sysMatch;
        out.push({
          rawRecord: {
            timestamp,
            hostName,
            processName,
            processId: pid ? Number(pid) : undefined,
            message,
            source: hostName
          },
          rawString: line
        });
        continue;
      }

      // Try RFC 5424
      const rfcMatch = line.match(rfc5424Regex);
      if (rfcMatch) {
        const [, pri, timestamp, hostName, appName, procId, msgId, sd, message] = rfcMatch;
        out.push({
          rawRecord: {
            priority: pri,
            timestamp,
            hostName,
            processName: appName !== '-' ? appName : undefined,
            processId: procId !== '-' && !isNaN(Number(procId)) ? Number(procId) : undefined,
            message: message || `Syslog msgId=${msgId}`,
            source: hostName !== '-' ? hostName : 'syslog-host'
          },
          rawString: line
        });
        continue;
      }

      // Fallback: generic line parser
      out.push({
        rawRecord: {
          timestamp: new Date().toISOString(),
          message: line,
          source: 'syslog-stream'
        },
        rawString: line
      });
    }
  }

  private parseKeyValue(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
    const kvRegex = /([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|(\S+))/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const record: Record<string, unknown> = {};
      let match: RegExpExecArray | null;

      while ((match = kvRegex.exec(line)) !== null) {
        const key = match[1];
        const val = match[2] !== undefined ? match[2] : match[3];
        record[key] = val;
      }

      if (Object.keys(record).length > 0) {
        out.push({ rawRecord: record, rawString: line });
      } else {
        out.push({ rawRecord: { message: line }, rawString: line });
      }
    }
  }

  private parsePlainText(content: string, out: Array<{ rawRecord: Record<string, unknown>; rawString: string }>, errors: string[]): void {
    const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Try extract leading timestamp if present: e.g. 2026-09-11 22:58:14 ...
      const leadingDate = line.match(/^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$/);
      if (leadingDate) {
        out.push({
          rawRecord: {
            timestamp: leadingDate[1],
            message: leadingDate[2],
            source: 'plaintext-log'
          },
          rawString: line
        });
      } else {
        out.push({
          rawRecord: {
            timestamp: new Date().toISOString(),
            message: line,
            source: 'plaintext-log'
          },
          rawString: line
        });
      }
    }
  }
}
