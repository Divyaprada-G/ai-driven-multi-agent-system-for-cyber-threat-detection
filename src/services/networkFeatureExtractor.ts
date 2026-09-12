import { LogEvent, NetworkFeatures } from '../types';

export interface FlowGroupKey {
  sourceIp: string;
  destinationIp?: string;
}

export class NetworkFeatureExtractor {
  /**
   * Safely extracts network-specific single-event properties without inventing missing fields.
   */
  public static extractSingleEventFields(event: LogEvent): {
    sourceIp?: string;
    destinationIp?: string;
    sourcePort?: number;
    destinationPort?: number;
    protocol?: string;
    packetSize?: number;
    flowDuration?: number;
    isFailed?: boolean;
  } {
    const nf = event.normalizedFields || {};

    const sourceIp = nf.sourceIp || undefined;
    const destinationIp = nf.destinationIp || undefined;
    const sourcePort = typeof nf.sourcePort === 'number' ? nf.sourcePort : undefined;
    const destinationPort = typeof nf.destinationPort === 'number' ? nf.destinationPort : undefined;
    const protocol = nf.protocol ? String(nf.protocol).toUpperCase() : undefined;
    const packetSize = typeof nf.packetSize === 'number' ? nf.packetSize : undefined;
    const flowDuration = typeof nf.flowDuration === 'number' ? nf.flowDuration : undefined;

    // Detect failed attempt from RST flags, status codes, or error text
    const msg = (event.message || '').toLowerCase();
    const raw = (event.rawData || '').toLowerCase();
    const flags = Array.isArray(nf.flags) ? nf.flags.map(f => String(f).toUpperCase()) : [];

    const isFailed =
      flags.includes('RST') ||
      flags.includes('RST,ACK') ||
      msg.includes('connection refused') ||
      msg.includes('connection reset') ||
      msg.includes('failed') ||
      msg.includes('reject') ||
      msg.includes('drop') ||
      msg.includes('denied') ||
      msg.includes('timeout') ||
      raw.includes('rst') ||
      raw.includes('drop');

    return {
      sourceIp,
      destinationIp,
      sourcePort,
      destinationPort,
      protocol,
      packetSize,
      flowDuration,
      isFailed
    };
  }

  /**
   * Aggregates features grouped by Source IP to analyze scanning and burst behavior.
   * Never invents missing values; only calculates metrics from observed records.
   */
  public static extractSourceFeatures(events: LogEvent[]): Map<string, NetworkFeatures> {
    const groups = new Map<string, LogEvent[]>();

    for (const event of events) {
      const { sourceIp } = this.extractSingleEventFields(event);
      if (!sourceIp) continue; // Safely skip events without source IP

      const existing = groups.get(sourceIp) || [];
      existing.push(event);
      groups.set(sourceIp, existing);
    }

    const featureMap = new Map<string, NetworkFeatures>();

    for (const [sourceIp, groupEvents] of groups.entries()) {
      const destPortsSet = new Set<number>();
      const destIpsSet = new Set<string>();
      let totalBytes = 0;
      let hasBytes = false;
      let failedCount = 0;
      const rawEventIds: string[] = [];
      const timestamps: number[] = [];

      let primaryDestinationIp: string | undefined;
      let primaryProtocol: string | undefined;

      for (const evt of groupEvents) {
        rawEventIds.push(evt.id);
        const fields = this.extractSingleEventFields(evt);

        if (fields.destinationPort !== undefined) {
          destPortsSet.add(fields.destinationPort);
        }
        if (fields.destinationIp) {
          destIpsSet.add(fields.destinationIp);
          if (!primaryDestinationIp) primaryDestinationIp = fields.destinationIp;
        }
        if (fields.protocol && !primaryProtocol) {
          primaryProtocol = fields.protocol;
        }
        if (fields.packetSize !== undefined) {
          totalBytes += fields.packetSize;
          hasBytes = true;
        }
        if (fields.isFailed) {
          failedCount++;
        }

        const t = new Date(evt.timestamp).getTime();
        if (!isNaN(t)) {
          timestamps.push(t);
        }
      }

      // Calculate time span & connection frequency
      let timeSpanSeconds = 1;
      if (timestamps.length >= 2) {
        const minTime = Math.min(...timestamps);
        const maxTime = Math.max(...timestamps);
        timeSpanSeconds = Math.max(1, Math.round((maxTime - minTime) / 1000));
      }

      const connectionFrequency =
        timeSpanSeconds > 0
          ? Number((groupEvents.length / timeSpanSeconds).toFixed(2))
          : groupEvents.length;

      featureMap.set(sourceIp, {
        sourceIp,
        destinationIp: primaryDestinationIp,
        protocol: primaryProtocol,
        connectionCount: groupEvents.length,
        uniqueDestinationPorts: destPortsSet.size,
        destinationPortsList: Array.from(destPortsSet).sort((a, b) => a - b),
        uniqueDestinationIps: destIpsSet.size,
        destinationIpsList: Array.from(destIpsSet),
        connectionFrequency,
        bytesTransferred: hasBytes ? totalBytes : undefined,
        timestamp: groupEvents[groupEvents.length - 1].timestamp,
        failedConnectionCount: failedCount,
        timeSpanSeconds,
        rawEventIds
      });
    }

    return featureMap;
  }

  /**
   * Aggregates features grouped by (Source IP, Destination IP, Destination Port)
   * to detect targeted repeated connection attempts / brute force attacks.
   */
  public static extractServiceFlowFeatures(
    events: LogEvent[]
  ): Map<string, NetworkFeatures> {
    const groups = new Map<string, LogEvent[]>();

    for (const event of events) {
      const { sourceIp, destinationIp, destinationPort } = this.extractSingleEventFields(event);
      if (!sourceIp || !destinationIp || destinationPort === undefined) continue;

      const key = `${sourceIp}->${destinationIp}:${destinationPort}`;
      const existing = groups.get(key) || [];
      existing.push(event);
      groups.set(key, existing);
    }

    const flowFeatureMap = new Map<string, NetworkFeatures>();

    for (const [key, groupEvents] of groups.entries()) {
      const parts = key.split('->');
      const sourceIp = parts[0];
      const destParts = parts[1].split(':');
      const destinationIp = destParts[0];
      const destinationPort = Number(destParts[1]);

      let failedCount = 0;
      let primaryProtocol: string | undefined;
      const rawEventIds: string[] = [];
      const timestamps: number[] = [];

      for (const evt of groupEvents) {
        rawEventIds.push(evt.id);
        const fields = this.extractSingleEventFields(evt);
        if (fields.protocol && !primaryProtocol) primaryProtocol = fields.protocol;
        if (fields.isFailed) failedCount++;

        const t = new Date(evt.timestamp).getTime();
        if (!isNaN(t)) timestamps.push(t);
      }

      let timeSpanSeconds = 1;
      if (timestamps.length >= 2) {
        const minTime = Math.min(...timestamps);
        const maxTime = Math.max(...timestamps);
        timeSpanSeconds = Math.max(1, Math.round((maxTime - minTime) / 1000));
      }

      const connectionFrequency =
        timeSpanSeconds > 0
          ? Number((groupEvents.length / timeSpanSeconds).toFixed(2))
          : groupEvents.length;

      flowFeatureMap.set(key, {
        sourceIp,
        destinationIp,
        destinationPort,
        protocol: primaryProtocol,
        connectionCount: groupEvents.length,
        uniqueDestinationPorts: 1,
        destinationPortsList: [destinationPort],
        uniqueDestinationIps: 1,
        destinationIpsList: [destinationIp],
        connectionFrequency,
        timestamp: groupEvents[groupEvents.length - 1].timestamp,
        failedConnectionCount: failedCount,
        timeSpanSeconds,
        rawEventIds
      });
    }

    return flowFeatureMap;
  }
}
