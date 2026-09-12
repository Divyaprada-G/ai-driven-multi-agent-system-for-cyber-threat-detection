import { LogEvent, LogFileRecord, LogType } from '../types';
import { INITIAL_LOG_FILES } from './mockData';
import { logRepository } from './logRepository';

export interface ILogService {
  getUploadedFiles(): Promise<LogFileRecord[]>;
  uploadLogFile(file: File, logType?: LogType): Promise<LogFileRecord>;
  getLogEventsByType(type?: LogType): Promise<LogEvent[]>;
  deleteLogFile(id: string): Promise<boolean>;
  hasRealData(): boolean;
  clearAll(): void;
}

class LogServiceImpl implements ILogService {
  async getUploadedFiles(): Promise<LogFileRecord[]> {
    if (logRepository.hasRealData()) {
      return logRepository.getUploadedFiles();
    }
    // Return baseline mock files when in DEMO MODE
    return [...INITIAL_LOG_FILES];
  }

  async uploadLogFile(file: File, logType?: LogType): Promise<LogFileRecord> {
    const batch = await logRepository.ingestFile(file, logType);
    const files = logRepository.getUploadedFiles();
    return files.find(f => f.id === batch.fileId) || {
      id: batch.fileId,
      filename: batch.filename,
      logType: batch.detectedLogType,
      fileSize: batch.fileSize,
      uploadTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
      processingStatus: 'COMPLETED',
      numberOfEvents: batch.totalParsed,
      validCount: batch.validCount,
      invalidCount: batch.invalidCount,
      duplicateCount: batch.duplicateCount,
      detectedFormat: batch.detectedFormat,
      errors: batch.errors
    };
  }

  async getLogEventsByType(type?: LogType): Promise<LogEvent[]> {
    if (logRepository.hasRealData()) {
      const { events } = logRepository.getEvents({ logType: type || 'ALL' });
      return events;
    }

    const sampleEvents: LogEvent[] = [
      {
        id: 'LOG-NET-01',
        timestamp: '2026-09-11 22:58:14',
        source: '192.168.1.105',
        logType: 'NETWORK',
        message: 'TCP SYN flood detected on port 443 with anomalous TCP flag combo SYN/FIN',
        rawData: '{"proto":"TCP","flags":"0x03","src":"192.168.1.105:54122","dst":"10.0.0.5:443"}'
      },
      {
        id: 'LOG-SYS-02',
        timestamp: '2026-09-11 22:47:19',
        source: 'workstation-fin-04',
        logType: 'SYSTEM',
        message: 'Process spoolsv.exe attempted privilege elevation to NT AUTHORITY\\SYSTEM',
        rawData: 'EventID=4688; ProcessName=spoolsv.exe; ElevatedToken=1; User=admin_dev'
      },
      {
        id: 'LOG-APP-03',
        timestamp: '2026-09-11 22:51:30',
        source: 'api.corp.internal',
        logType: 'APPLICATION',
        message: 'POST /api/v2/checkout 500 status with signature: UNION SELECT NULL,PASS',
        rawData: 'HTTP/1.1 POST /api/v2/checkout Payload: {"orderId": "1\' UNION SELECT credit_card FROM payments--"}'
      }
    ];

    if (type) {
      return sampleEvents.filter(e => e.logType === type);
    }
    return sampleEvents;
  }

  async deleteLogFile(id: string): Promise<boolean> {
    if (logRepository.hasRealData()) {
      return logRepository.deleteFile(id);
    }
    return true;
  }

  hasRealData(): boolean {
    return logRepository.hasRealData();
  }

  clearAll(): void {
    logRepository.clearAll();
  }
}

export const logService: ILogService = new LogServiceImpl();

