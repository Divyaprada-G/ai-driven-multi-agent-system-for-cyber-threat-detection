import { LogEvent } from '../types';

export class DuplicateDetector {
  private seenFingerprints: Map<string, number> = new Map();

  /**
   * Generates a deterministic, collision-resistant string fingerprint from essential event fields.
   */
  static generateFingerprint(event: Partial<LogEvent>): string {
    const nf = event.normalizedFields || {};

    const signatureParts = [
      event.timestamp || '',
      event.source || '',
      event.logType || '',
      (event.message || '').trim().toLowerCase(),
      nf.sourceIp || '',
      nf.destinationIp || '',
      String(nf.destinationPort || ''),
      nf.hostName || '',
      nf.processName || '',
      String(nf.processId || ''),
      nf.endpoint || '',
      String(nf.statusCode || '')
    ];

    const compositeString = signatureParts.join('|#|');
    return this.fnv1a64(compositeString);
  }

  /**
   * Evaluates an event against the current ingestion session cache.
   * If a duplicate is detected, flags the event and increments duplicate count.
   */
  checkAndRecord(event: LogEvent): { isDuplicate: boolean; duplicateCount: number; fingerprint: string } {
    const fingerprint = DuplicateDetector.generateFingerprint(event);
    const existingCount = this.seenFingerprints.get(fingerprint) || 0;

    if (existingCount > 0) {
      this.seenFingerprints.set(fingerprint, existingCount + 1);
      return {
        isDuplicate: true,
        duplicateCount: existingCount + 1,
        fingerprint
      };
    } else {
      this.seenFingerprints.set(fingerprint, 1);
      return {
        isDuplicate: false,
        duplicateCount: 1,
        fingerprint
      };
    }
  }

  /**
   * Returns total unique fingerprints tracked.
   */
  getUniqueCount(): number {
    return this.seenFingerprints.size;
  }

  /**
   * Clears seen fingerprint cache.
   */
  reset(): void {
    this.seenFingerprints.clear();
  }

  /**
   * 64-bit FNV-1a Hash converted to 16-character hex string.
   */
  private static fnv1a64(str: string): string {
    let h1 = 0x811c9dc5;
    let h2 = 0xcbf29ce4;

    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      h1 ^= code;
      h1 = Math.imul(h1, 0x01000193);

      h2 ^= code;
      h2 = Math.imul(h2, 0x01000193);
    }

    const hex1 = (h1 >>> 0).toString(16).padStart(8, '0');
    const hex2 = (h2 >>> 0).toString(16).padStart(8, '0');
    return `fp-${hex1}${hex2}`;
  }
}
