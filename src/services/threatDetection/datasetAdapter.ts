import {
  TrainingDatasetMeta
} from '../../types/threatDetection';

export interface DatasetFeatureMapping {
  standard: 'CICIDS2017' | 'UNSW_NB15' | 'KDDCUP99' | 'CUSTOM';
  sourceColumns: string[];
  targetClassColumn: string;
  mappedFeatures: Record<string, string>; // internalFeatureKey -> externalColumnName
  notes: string;
}

/**
 * Standard feature schemas for benchmark cybersecurity datasets
 */
export const STANDARD_DATASET_SCHEMAS: Record<string, DatasetFeatureMapping> = {
  CICIDS2017: {
    standard: 'CICIDS2017',
    sourceColumns: [
      'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
      'Total Length of Fwd Packets', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
      'Fwd IAT Mean', 'Bwd IAT Mean', 'Fwd PSH Flags', 'FIN Flag Count', 'SYN Flag Count',
      'RST Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Down/Up Ratio', 'Average Packet Size',
      'Subflow Fwd Packets', 'Init_Win_bytes_forward', 'Active Mean', 'Idle Mean', 'Label'
    ],
    targetClassColumn: 'Label',
    mappedFeatures: {
      eventDurationSeconds: 'Flow Duration',
      uniqueDestIpsCount: 'Destination Port',
      findingCount: 'Total Fwd Packets',
      networkInvolvement: 'SYN Flag Count'
    },
    notes: 'Canadian Institute for Cybersecurity benchmark (DDoS, PortScan, Botnet, Web Attack, Infiltration).'
  },
  UNSW_NB15: {
    standard: 'UNSW_NB15',
    sourceColumns: [
      'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
      'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
      'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
      'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
      'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
      'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm',
      'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ],
    targetClassColumn: 'attack_cat',
    mappedFeatures: {
      eventDurationSeconds: 'dur',
      uniqueSourceIpsCount: 'srcip',
      uniqueDestIpsCount: 'dstip',
      timeSpanSeconds: 'Ltime'
    },
    notes: 'University of New South Wales modern cyber telemetry dataset (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).'
  },
  KDDCUP99: {
    standard: 'KDDCUP99',
    sourceColumns: [
      'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
      'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
      'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
      'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
      'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
      'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
      'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
      'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
      'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
    ],
    targetClassColumn: 'label',
    mappedFeatures: {
      eventDurationSeconds: 'duration',
      affectedUsersCount: 'num_failed_logins',
      systemInvolvement: 'root_shell',
      criticalSeverityCount: 'num_compromised'
    },
    notes: 'Classic DARPA/KDD network intrusion dataset (DoS, Probe, R2L, U2R, Normal).'
  }
};

/**
 * Dataset Parser and Schema Validator
 */
export class DatasetAdapter {
  /**
   * Parse uploaded CSV text into dataset metadata and summary
   */
  public static parseCsv(content: string, fileName: string): TrainingDatasetMeta {
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) {
      throw new Error('Dataset must contain at least a header row and one data row.');
    }

    const headerLine = lines[0];
    const columns = headerLine.split(',').map(col => col.trim().replace(/^["']|["']$/g, ''));

    // Detect if this matches a known benchmark
    let standardType: TrainingDatasetMeta['standardType'] = 'CUSTOM';
    if (columns.includes('Flow Duration') && columns.includes('Label')) {
      standardType = 'CICIDS2017';
    } else if (columns.includes('attack_cat') || (columns.includes('dur') && columns.includes('sbytes'))) {
      standardType = 'UNSW_NB15';
    } else if (columns.includes('num_failed_logins') || columns.includes('protocol_type')) {
      standardType = 'KDDCUP99';
    }

    // Default target column detection
    let targetColumn = columns[columns.length - 1];
    const targetCandidates = ['label', 'Label', 'attack_cat', 'class', 'target', 'category'];
    for (const cand of targetCandidates) {
      const found = columns.find(c => c.toLowerCase() === cand.toLowerCase());
      if (found) {
        targetColumn = found;
        break;
      }
    }

    const featureColumns = columns.filter(c => c !== targetColumn);

    // Calculate row count and class distribution
    const classDistribution: Record<string, number> = {};
    let missingValuesCount = 0;
    const targetIndex = columns.indexOf(targetColumn);

    const dataRows = lines.slice(1);
    for (const row of dataRows) {
      const cells = row.split(',');
      if (cells.length !== columns.length) {
        missingValuesCount++;
      }
      if (targetIndex >= 0 && targetIndex < cells.length) {
        const cls = cells[targetIndex].trim().replace(/^["']|["']$/g, '') || 'UNLABELED';
        classDistribution[cls] = (classDistribution[cls] || 0) + 1;
      }
    }

    const classesFound = Object.keys(classDistribution);

    return {
      datasetName: fileName,
      format: 'CSV',
      standardType,
      rowCount: dataRows.length,
      columnCount: columns.length,
      columns,
      featureColumns,
      targetColumn,
      classesFound,
      classDistribution,
      missingValuesCount,
      uploadedAt: new Date().toISOString()
    };
  }

  /**
   * Parse uploaded JSON text into dataset metadata
   */
  public static parseJson(content: string, fileName: string): TrainingDatasetMeta {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error('Invalid JSON file format.');
    }

    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('JSON dataset must be a non-empty array of record objects.');
    }

    const firstItem = parsed[0];
    if (typeof firstItem !== 'object' || firstItem === null) {
      throw new Error('JSON dataset array items must be objects.');
    }

    const columns = Object.keys(firstItem);
    let targetColumn = columns[columns.length - 1];
    for (const cand of ['label', 'class', 'target', 'category', 'attack_cat']) {
      const found = columns.find(c => c.toLowerCase() === cand.toLowerCase());
      if (found) {
        targetColumn = found;
        break;
      }
    }

    const featureColumns = columns.filter(c => c !== targetColumn);
    const classDistribution: Record<string, number> = {};
    let missingValuesCount = 0;

    for (const row of parsed as Record<string, unknown>[]) {
      for (const col of columns) {
        if (row[col] === undefined || row[col] === null || row[col] === '') {
          missingValuesCount++;
        }
      }
      const cls = String(row[targetColumn] ?? 'UNLABELED');
      classDistribution[cls] = (classDistribution[cls] || 0) + 1;
    }

    return {
      datasetName: fileName,
      format: 'JSON',
      standardType: 'CUSTOM',
      rowCount: parsed.length,
      columnCount: columns.length,
      columns,
      featureColumns,
      targetColumn,
      classesFound: Object.keys(classDistribution),
      classDistribution,
      missingValuesCount,
      uploadedAt: new Date().toISOString()
    };
  }
}
