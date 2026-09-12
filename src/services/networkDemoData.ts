import { LogEvent } from '../types';

export const NETWORK_DEMO_EVENTS: LogEvent[] = [
  // -------------------------------------------------------------
  // 1. Normal Traffic: Standard Web, DNS, NTP, and Internal Flow
  // -------------------------------------------------------------
  {
    id: 'DEMO-NET-001',
    timestamp: '2026-09-11T22:40:10.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'Allowed outbound HTTPS connection to Cloudflare CDN',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.1.15',
      destinationIp: '104.16.132.229',
      sourcePort: 51234,
      destinationPort: 443,
      protocol: 'TCP',
      packetSize: 1420,
      flags: ['ACK', 'PSH'],
      flowDuration: 0.12
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-002',
    timestamp: '2026-09-11T22:40:14.000Z',
    source: 'Internal DNS Resolver',
    logType: 'NETWORK',
    message: 'Standard DNS resolution query for internal api gateway',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.1.18',
      destinationIp: '10.0.0.1',
      sourcePort: 54312,
      destinationPort: 53,
      protocol: 'UDP',
      packetSize: 68,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-003',
    timestamp: '2026-09-11T22:40:22.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'Encrypted TLS 1.3 session established to enterprise ERP server',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.1.22',
      destinationIp: '10.0.0.2',
      sourcePort: 58910,
      destinationPort: 443,
      protocol: 'TCP',
      packetSize: 2048,
      flags: ['ACK'],
      flowDuration: 1.45
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-004',
    timestamp: '2026-09-11T22:40:30.000Z',
    source: 'NTP Time Daemon',
    logType: 'NETWORK',
    message: 'Periodic network time synchronization exchange',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.1.5',
      destinationIp: '162.159.200.1',
      sourcePort: 123,
      destinationPort: 123,
      protocol: 'UDP',
      packetSize: 48,
      flowDuration: 0.02
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-005',
    timestamp: '2026-09-11T22:40:45.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'Authorized REST API webhook delivery to Stripe API endpoint',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.2.50',
      destinationIp: '52.84.12.33',
      sourcePort: 60102,
      destinationPort: 443,
      protocol: 'TCP',
      packetSize: 840,
      flags: ['ACK', 'PSH'],
      flowDuration: 0.28
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },

  // -------------------------------------------------------------
  // 2. Port Scan Pattern: Source 192.168.1.105 targeting 10.0.0.5
  // Probing ports: 21, 22, 23, 25, 80, 135, 139, 445, 3389
  // -------------------------------------------------------------
  {
    id: 'DEMO-NET-SCAN-01',
    timestamp: '2026-09-11T22:42:01.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP SYN connection attempt to FTP service',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40101,
      destinationPort: 21,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.05
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-02',
    timestamp: '2026-09-11T22:42:02.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP SYN probe to SSH daemon',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40102,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.04
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-03',
    timestamp: '2026-09-11T22:42:03.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP SYN probe to Telnet port',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40103,
      destinationPort: 23,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.03
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-04',
    timestamp: '2026-09-11T22:42:04.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to SMTP relay port',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40104,
      destinationPort: 25,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.04
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-05',
    timestamp: '2026-09-11T22:42:05.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to HTTP server port',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40105,
      destinationPort: 80,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.05
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-06',
    timestamp: '2026-09-11T22:42:06.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to Microsoft RPC endpoint mapper',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40106,
      destinationPort: 135,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.04
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-07',
    timestamp: '2026-09-11T22:42:07.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to NetBIOS session service',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40107,
      destinationPort: 139,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.03
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-08',
    timestamp: '2026-09-11T22:42:08.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to SMB Direct Hosting service',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40108,
      destinationPort: 445,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.04
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-SCAN-09',
    timestamp: '2026-09-11T22:42:09.000Z',
    source: 'Suricata NIDS (Sensor-DMZ)',
    logType: 'NETWORK',
    message: 'TCP probe to Remote Desktop Protocol (RDP)',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      sourcePort: 40109,
      destinationPort: 3389,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 60,
      flowDuration: 0.05
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },

  // -------------------------------------------------------------
  // 3. Repeated Connection Attempts / SSH Brute Force:
  // Source 198.51.100.44 hammering 10.0.0.8:22 with failed handshakes
  // -------------------------------------------------------------
  {
    id: 'DEMO-NET-BF-01',
    timestamp: '2026-09-11T22:44:10.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 1 - connection reset by peer',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49811,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-BF-02',
    timestamp: '2026-09-11T22:44:11.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 2 - failed authentication handshake',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49812,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-BF-03',
    timestamp: '2026-09-11T22:44:12.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 3 - failed authentication handshake',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49813,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-BF-04',
    timestamp: '2026-09-11T22:44:13.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 4 - failed authentication handshake',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49814,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-BF-05',
    timestamp: '2026-09-11T22:44:14.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 5 - connection dropped',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49815,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-BF-06',
    timestamp: '2026-09-11T22:44:15.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'SSH connection attempt 6 - connection reset',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.0.8',
      sourcePort: 49816,
      destinationPort: 22,
      protocol: 'TCP',
      flags: ['RST'],
      packetSize: 120,
      flowDuration: 0.1
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },

  // -------------------------------------------------------------
  // 4. Suspicious Port Activity:
  // Internal host 10.0.0.42 initiating reverse shell to external port 4444 (Metasploit)
  // -------------------------------------------------------------
  {
    id: 'DEMO-NET-SUSP-01',
    timestamp: '2026-09-11T22:46:30.000Z',
    source: 'Perimeter Firewall (FW-01)',
    logType: 'NETWORK',
    message: 'Outbound TCP connection established to external non-standard port 4444',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '10.0.0.42',
      destinationIp: '203.0.113.19',
      sourcePort: 53120,
      destinationPort: 4444,
      protocol: 'TCP',
      flags: ['SYN', 'ACK'],
      packetSize: 340,
      flowDuration: 4.8
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },

  // -------------------------------------------------------------
  // 5. Abnormal Traffic Spike:
  // Host 172.16.5.90 generating a burst of connection attempts
  // -------------------------------------------------------------
  {
    id: 'DEMO-NET-ANOM-01',
    timestamp: '2026-09-11T22:48:00.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62001,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-02',
    timestamp: '2026-09-11T22:48:01.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62002,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-03',
    timestamp: '2026-09-11T22:48:02.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62003,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-04',
    timestamp: '2026-09-11T22:48:03.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62004,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-05',
    timestamp: '2026-09-11T22:48:04.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62005,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-06',
    timestamp: '2026-09-11T22:48:05.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62006,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  },
  {
    id: 'DEMO-NET-ANOM-07',
    timestamp: '2026-09-11T22:48:06.000Z',
    source: 'Core Switch Gateway',
    logType: 'NETWORK',
    message: 'Rapid SYN burst to internal gateway VIP',
    format: 'JSON',
    normalizedFields: {
      sourceIp: '172.16.5.90',
      destinationIp: '10.0.0.1',
      sourcePort: 62007,
      destinationPort: 8080,
      protocol: 'TCP',
      flags: ['SYN'],
      packetSize: 64,
      flowDuration: 0.01
    },
    validation: { status: 'VALID', errors: [], warnings: [] }
  }
];
