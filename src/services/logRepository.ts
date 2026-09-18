import {
  IngestionBatchResult,
  LogEvent,
  LogFileRecord,
  LogFilterCriteria,
  LogType,
  RepositoryStats
} from '../types';
import { LogParser } from './logParser';
import { DuplicateDetector } from './duplicateDetector';
import { SAMPLE_DATASETS } from './sampleDatasets';

class LogRepositoryImpl {
  private events: LogEvent[] = [];
  private files: LogFileRecord[] = [];
  private batchResults: IngestionBatchResult[] = [];
  private duplicateDetector: DuplicateDetector = new DuplicateDetector();
  private parser: LogParser = new LogParser(this.duplicateDetector);
  private listeners: Set<() => void> = new Set();

  /**
   * Ingests a real File object from drag-and-drop or file input.
   */
  async ingestFile(file: File, overrideLogType?: LogType): Promise<IngestionBatchResult> {
    const startTime = performance.now();
    const content = await file.text();
    return this.processContent(content, file.name, file.size, startTime, overrideLogType);
  }

  /**
   * Ingests raw text directly (e.g. pasted log stream or sample dataset).
   */
  async ingestRawContent(
    content: string,
    filename: string,
    overrideLogType?: LogType
  ): Promise<IngestionBatchResult> {
    const startTime = performance.now();
    const size = new Blob([content]).size;
    return this.processContent(content, filename, size, startTime, overrideLogType);
  }

  /**
   * Loads a built-in realistic sample dataset into the real ingestion pipeline.
   */
  async loadSample(sampleKey: string): Promise<IngestionBatchResult> {
    const sample = SAMPLE_DATASETS[sampleKey];
    if (!sample) {
      throw new Error(`Sample dataset "${sampleKey}" not found`);
    }
    const targetType = sample.targetAgent === 'ALL' ? undefined : sample.targetAgent;
    return this.ingestRawContent(sample.content, sample.filename, targetType);
  }

  private async processContent(
    content: string,
    filename: string,
    fileSize: number,
    startTime: number,
    overrideLogType?: LogType
  ): Promise<IngestionBatchResult> {
    const fileId = `INGEST-${Date.now().toString().slice(-6)}`;
    const sizeInMB = (fileSize / (1024 * 1024)).toFixed(2);
    const formattedSize = Number(sizeInMB) >= 0.1 ? `${sizeInMB} MB` : `${(fileSize / 1024).toFixed(1)} KB`;

    // Parse and normalize content
    const parseResult = await this.parser.parseContent(content, {
      filename,
      overrideLogType
    });

    const durationMs = Math.round(performance.now() - startTime);

    const batchResult: IngestionBatchResult = {
      fileId,
      filename,
      fileSize: formattedSize,
      detectedFormat: parseResult.format,
      detectedLogType: parseResult.detectedLogType,
      totalParsed: parseResult.events.length,
      validCount: parseResult.validCount,
      invalidCount: parseResult.invalidCount,
      warningCount: parseResult.warningCount,
      duplicateCount: parseResult.duplicateCount,
      processingErrorCount: parseResult.processingErrorCount,
      validationPercentage: parseResult.validationPercentage,
      durationMs,
      events: parseResult.events,
      errors: parseResult.parseErrors
    };

    // Create file record for Log Explorer table
    const previewLines = parseResult.events.slice(0, 3).map(e => {
      const ts = e.timestamp;
      const nf = e.normalizedFields || {};
      if (e.logType === 'NETWORK') {
        return `[NET] ${ts} ${nf.sourceIp || e.source}:${nf.sourcePort || '*'} -> ${nf.destinationIp || 'dst'}:${nf.destinationPort || '*'} [${nf.protocol || 'TCP'}] ${e.message}`;
      } else if (e.logType === 'SYSTEM') {
        return `[SYS] ${ts} ${nf.hostName || e.source} proc=${nf.processName || 'proc'} pid=${nf.processId || '-'} user=${nf.userName || 'user'} - ${e.message}`;
      } else {
        return `[APP] ${ts} ${nf.httpMethod || 'REQ'} ${nf.endpoint || '/'} (${nf.statusCode || 200}) src=${nf.sourceIp || e.source} - ${e.message}`;
      }
    });

    const fileRecord: LogFileRecord = {
      id: fileId,
      filename,
      logType: parseResult.detectedLogType,
      fileSize: formattedSize,
      uploadTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
      processingStatus: parseResult.events.length > 0 ? 'COMPLETED' : 'FAILED',
      numberOfEvents: parseResult.events.length,
      validCount: parseResult.validCount,
      invalidCount: parseResult.invalidCount,
      warningCount: parseResult.warningCount,
      duplicateCount: parseResult.duplicateCount,
      processingErrorCount: parseResult.processingErrorCount,
      validationPercentage: parseResult.validationPercentage,
      detectedFormat: parseResult.format,
      parsedPreview: previewLines,
      parsingDurationMs: durationMs,
      errors: parseResult.parseErrors
    };

    // Update repository store (new events at the beginning)
    this.events = [...parseResult.events, ...this.events];
    this.files.unshift(fileRecord);
    this.batchResults.unshift(batchResult);

    this.notifyListeners();
    return batchResult;
  }

  /**
   * Retrieves events matching query filters.
   */
  getEvents(filter?: LogFilterCriteria): { events: LogEvent[]; total: number; filtered: number } {
    const total = this.events.length;
    if (!filter) {
      return { events: [...this.events], total, filtered: total };
    }

    let result = this.events;

    // Filter by Log Type
    if (filter.logType && filter.logType !== 'ALL') {
      result = result.filter(e => e.logType === filter.logType);
    }

    // Filter by Validation / Duplicate Status
    if (filter.validationStatus && filter.validationStatus !== 'ALL') {
      const targetStatus = filter.validationStatus;
      result = result.filter(e => {
        const rowStatus = e.structuredValidation?.validation_status;
        if (targetStatus === 'DUPLICATE') {
          return e.isDuplicate || rowStatus === 'DUPLICATE';
        }
        if (rowStatus) {
          return rowStatus === targetStatus;
        }
        return e.validation?.status === targetStatus;
      });
    }

    // Filter by Specific Error Code (e.g. MISSING_IP, INVALID_PROTOCOL, NEGATIVE_FAILED_LOGINS, etc.)
    if (filter.errorCode && filter.errorCode !== 'ALL') {
      const code = filter.errorCode.toUpperCase();
      result = result.filter(e => {
        return e.structuredValidation?.errors.some(err => err.error_code.toUpperCase() === code);
      });
    }

    // Deduplication filter toggle
    if (filter.deduplicate) {
      result = result.filter(e => !e.isDuplicate && e.structuredValidation?.validation_status !== 'DUPLICATE');
    }

    // Filter by Source
    if (filter.source && filter.source !== 'ALL') {
      result = result.filter(e => e.source === filter.source || e.normalizedFields?.sourceIp === filter.source);
    }

    // Search query filter (matches message, source, rawData, and normalized fields)
    if (filter.searchTerm && filter.searchTerm.trim() !== '') {
      const q = filter.searchTerm.toLowerCase().trim();
      result = result.filter(e => {
        if (e.message.toLowerCase().includes(q)) return true;
        if (e.source.toLowerCase().includes(q)) return true;
        if (e.rawData && e.rawData.toLowerCase().includes(q)) return true;
        if (e.id.toLowerCase().includes(q)) return true;

        const nf = e.normalizedFields;
        if (nf) {
          if (nf.sourceIp && nf.sourceIp.toLowerCase().includes(q)) return true;
          if (nf.destinationIp && nf.destinationIp.toLowerCase().includes(q)) return true;
          if (nf.hostName && nf.hostName.toLowerCase().includes(q)) return true;
          if (nf.processName && nf.processName.toLowerCase().includes(q)) return true;
          if (nf.userName && nf.userName.toLowerCase().includes(q)) return true;
          if (nf.endpoint && nf.endpoint.toLowerCase().includes(q)) return true;
        }

        // Also match error codes or messages in search
        if (e.structuredValidation?.errors.some(err => err.message.toLowerCase().includes(q) || err.error_code.toLowerCase().includes(q))) {
          return true;
        }

        return false;
      });
    }

    return {
      events: result,
      total,
      filtered: result.length
    };
  }

  getEventById(id: string): LogEvent | undefined {
    return this.events.find(e => e.id === id);
  }

  getUploadedFiles(): LogFileRecord[] {
    return [...this.files];
  }

  getBatchResults(): IngestionBatchResult[] {
    return [...this.batchResults];
  }

  /**
   * Calculates comprehensive telemetry stats from ingested data.
   */
  getStats(): RepositoryStats {
    const totalEvents = this.events.length;
    let validEvents = 0;
    let invalidEvents = 0;
    let warningEvents = 0;
    let duplicateEvents = 0;
    let processingErrorEvents = 0;
    let networkEvents = 0;
    let systemEvents = 0;
    let applicationEvents = 0;
    const sourcesSet = new Set<string>();

    let firstTime: number | null = null;
    let lastTime: number | null = null;

    for (const e of this.events) {
      const status = e.structuredValidation?.validation_status || (e.validation?.status === 'VALID' ? 'VALID' : 'INVALID');
      if (status === 'VALID') validEvents++;
      else if (status === 'WARNING') warningEvents++;
      else if (status === 'DUPLICATE') duplicateEvents++;
      else if (status === 'PROCESSING_ERROR') processingErrorEvents++;
      else invalidEvents++;

      if (e.isDuplicate && status !== 'DUPLICATE') duplicateEvents++;

      if (e.logType === 'NETWORK') networkEvents++;
      else if (e.logType === 'SYSTEM') systemEvents++;
      else if (e.logType === 'APPLICATION') applicationEvents++;

      if (e.source) sourcesSet.add(e.source);
      if (e.normalizedFields?.sourceIp) sourcesSet.add(e.normalizedFields.sourceIp);

      const t = new Date(e.timestamp).getTime();
      if (!isNaN(t)) {
        if (firstTime === null || t < firstTime) firstTime = t;
        if (lastTime === null || t > lastTime) lastTime = t;
      }
    }

    const validationPercentage = totalEvents > 0
      ? Number(((validEvents / totalEvents) * 100).toFixed(1))
      : 100;

    return {
      totalEvents,
      validEvents,
      invalidEvents,
      warningEvents,
      duplicateEvents,
      processingErrorEvents,
      validationPercentage,
      networkEvents,
      systemEvents,
      applicationEvents,
      uniqueSources: sourcesSet.size,
      firstEventTime: firstTime ? new Date(firstTime).toISOString() : null,
      lastEventTime: lastTime ? new Date(lastTime).toISOString() : null,
      ingestedFilesCount: this.files.length,
      isRealDataActive: totalEvents > 0
    };
  }

  getUniqueSources(): string[] {
    const s = new Set<string>();
    for (const e of this.events) {
      if (e.source) s.add(e.source);
      if (e.normalizedFields?.sourceIp) s.add(e.normalizedFields.sourceIp);
    }
    return Array.from(s);
  }

  hasRealData(): boolean {
    return this.events.length > 0;
  }

  deleteFile(fileId: string): boolean {
    const initialLen = this.files.length;
    this.files = this.files.filter(f => f.id !== fileId);
    this.batchResults = this.batchResults.filter(b => b.fileId !== fileId);
    if (this.files.length === 0) {
      this.clearAll();
    } else {
      this.notifyListeners();
    }
    return this.files.length < initialLen;
  }

  /**
   * Purges all ingested logs and resets to DEMO MODE.
   */
  clearAll(): void {
    this.events = [];
    this.files = [];
    this.batchResults = [];
    this.duplicateDetector.reset();
    this.notifyListeners();
  }

  /**
   * Exports the current repository state to JSON or CSV.
   */
  exportEvents(format: 'json' | 'csv' = 'json'): string {
    if (format === 'json') {
      return JSON.stringify(this.events, null, 2);
    }

    // CSV serialization
    const headers = [
      'id', 'timestamp', 'logType', 'source', 'message',
      'validationStatus', 'isDuplicate', 'sourceIp', 'destinationIp',
      'destinationPort', 'hostName', 'processName', 'userName', 'endpoint', 'statusCode'
    ];

    const escapeCsv = (str: string | number | undefined | null) => {
      if (str === undefined || str === null) return '';
      const s = String(str).replace(/"/g, '""');
      return `"${s}"`;
    };

    const rows = this.events.map(e => {
      const nf = e.normalizedFields || {};
      return [
        escapeCsv(e.id),
        escapeCsv(e.timestamp),
        escapeCsv(e.logType),
        escapeCsv(e.source),
        escapeCsv(e.message),
        escapeCsv(e.validation?.status || 'VALID'),
        escapeCsv(e.isDuplicate ? 'YES' : 'NO'),
        escapeCsv(nf.sourceIp),
        escapeCsv(nf.destinationIp),
        escapeCsv(nf.destinationPort),
        escapeCsv(nf.hostName),
        escapeCsv(nf.processName),
        escapeCsv(nf.userName),
        escapeCsv(nf.endpoint),
        escapeCsv(nf.statusCode)
      ].join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners(): void {
    this.listeners.forEach(fn => {
      try {
        fn();
      } catch (err) {
        console.error('Listener callback error', err);
      }
    });
  }
}

export const logRepository = new LogRepositoryImpl();
