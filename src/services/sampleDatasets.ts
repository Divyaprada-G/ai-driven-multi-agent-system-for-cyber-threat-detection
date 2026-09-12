export interface SampleDatasetInfo {
  id: string;
  name: string;
  filename: string;
  format: 'JSON' | 'JSONL' | 'CSV' | 'SYSLOG';
  targetAgent: 'NETWORK' | 'SYSTEM' | 'APPLICATION' | 'ALL';
  description: string;
  eventCount: number;
  content: string;
}

export const SAMPLE_DATASETS: Record<string, SampleDatasetInfo> = {
  suricata_network: {
    id: 'suricata_network',
    name: 'Suricata EVE Network IDS Telemetry',
    filename: 'suricata_eve_network_alerts.jsonl',
    format: 'JSONL',
    targetAgent: 'NETWORK',
    description: 'Realistic Suricata IDS EVE JSON stream with port scans, DNS lookups, and TCP SYN flood signatures.',
    eventCount: 12,
    content: `{"timestamp":"2026-09-11T22:58:14.102Z","flow_id":19283746501,"event_type":"alert","src_ip":"192.168.1.105","src_port":54122,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":19,"signature":"ET SCAN Potential Nmap SYN Scan Observed","category":"Attempted Information Leak","severity":2},"payload":"4500003c41a200004006c5b9c0a801690a000005"}
{"timestamp":"2026-09-11T22:58:14.215Z","flow_id":19283746502,"event_type":"alert","src_ip":"192.168.1.105","src_port":54124,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":19,"signature":"ET SCAN Potential Nmap SYN Scan Observed","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-11T22:58:14.331Z","flow_id":19283746503,"event_type":"alert","src_ip":"192.168.1.105","src_port":54126,"dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":19,"signature":"ET SCAN Potential Nmap SYN Scan Observed","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-11T22:58:14.450Z","flow_id":19283746504,"event_type":"alert","src_ip":"192.168.1.105","src_port":54128,"dest_ip":"10.0.0.5","dest_port":3389,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":19,"signature":"ET SCAN Potential RDP Scan Observed","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-11T22:58:15.004Z","flow_id":19283746505,"event_type":"dns","src_ip":"10.240.12.88","src_port":61022,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"type":"query","id":4190,"rrname":"c2-stage9.entropy-tunnel.xyz","rrtype":"TXT","tx_id":0}}
{"timestamp":"2026-09-11T22:58:15.520Z","flow_id":19283746506,"event_type":"flow","src_ip":"10.0.0.5","src_port":443,"dest_ip":"192.168.1.105","dest_port":54122,"proto":"TCP","app_proto":"tls","tcp":{"tcp_flags":"14","syn":false,"ack":true,"rst":true}}
{"timestamp":"2026-09-11T22:58:16.120Z","flow_id":19283746507,"event_type":"alert","src_ip":"198.51.100.44","src_port":49200,"dest_ip":"10.0.0.12","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001221,"rev":14,"signature":"ET SCAN Potential SSH Brute Force Inbound","category":"Attempted Administrator Privilege Gain","severity":1}}
{"timestamp":"2026-09-11T22:58:16.890Z","flow_id":19283746508,"event_type":"flow","src_ip":"10.0.0.12","src_port":22,"dest_ip":"198.51.100.44","dest_port":49200,"proto":"TCP","tcp":{"tcp_flags":"12","syn":false,"ack":true,"rst":false}}
{"timestamp":"2026-09-11T22:58:17.310Z","flow_id":19283746509,"event_type":"dns","src_ip":"10.240.12.88","src_port":61023,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":4191,"rrname":"payload-chunk01.entropy-tunnel.xyz","rrtype":"TXT","tx_id":0}}
{"timestamp":"2026-09-11T22:58:18.005Z","flow_id":19283746510,"event_type":"alert","src_ip":"203.0.113.15","src_port":58391,"dest_ip":"10.0.0.2","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2024101,"rev":5,"signature":"ET ATTACK_RESPONSE Metasploit Meterpreter Reverse HTTPS Beacon","category":"A Network Trojan was detected","severity":1}}
{"timestamp":"2026-09-11T22:58:18.420Z","flow_id":19283746511,"event_type":"flow","src_ip":"10.0.0.2","src_port":443,"dest_ip":"203.0.113.15","dest_port":58391,"proto":"TCP","app_proto":"tls","length":1420}
{"timestamp":"2026-09-11T22:58:19.110Z","flow_id":19283746512,"event_type":"flow","src_ip":"192.168.1.105","src_port":54130,"dest_ip":"10.0.0.5","dest_port":8080,"proto":"TCP","tcp":{"tcp_flags":"02","syn":true,"ack":false,"rst":false}}`
  },

  sysmon_system: {
    id: 'sysmon_system',
    name: 'Sysmon & Host Audit Events (CSV)',
    filename: 'sysmon_host_telemetry.csv',
    format: 'CSV',
    targetAgent: 'SYSTEM',
    description: 'Windows Sysmon EventID 1 (Process Creation), Parent/Child PID tracking, and token privilege escalation logs.',
    eventCount: 10,
    content: `timestamp,hostName,event_id,processName,processId,parentProcess,userName,commandLine,integrityLevel,message
2026-09-11T22:47:19.000Z,workstation-fin-04,1,spoolsv.exe,1420,services.exe,NT AUTHORITY\\SYSTEM,C:\\Windows\\System32\\spoolsv.exe,High,Print spooler service process initialization
2026-09-11T22:47:19.420Z,workstation-fin-04,1,cmd.exe,4120,spoolsv.exe,admin_dev,cmd.exe /c "powershell -ep bypass -file C:\\Temp\\stage2.ps1",High,Anomalous child process spawned from spoolsv.exe
2026-09-11T22:47:20.100Z,workstation-fin-04,1,powershell.exe,4196,cmd.exe,admin_dev,powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA,High,PowerShell launched with base64 encoded payload and execution policy bypass
2026-09-11T22:47:21.350Z,workstation-fin-04,10,lsass.exe,768,powershell.exe,SYSTEM,lsass.exe open process handle,System,Process access request targeting LSASS security memory handle
2026-09-11T22:47:22.010Z,workstation-fin-04,1,whoami.exe,4220,powershell.exe,admin_dev,whoami /priv /groups,High,Discovery command whoami executed to inspect security token privileges
2026-09-11T22:47:23.120Z,dc-srv-01,4624,lsass.exe,812,services.exe,krbtgt,Kerberos TGT authentication validation,System,Successful network logon for domain controller replication
2026-09-11T22:47:24.450Z,dc-srv-01,4625,lsass.exe,812,services.exe,svc_backup,Logon attempt with unknown username or bad password,System,Failed logon attempt from unknown subnet
2026-09-11T22:47:25.800Z,workstation-fin-04,1,net.exe,4260,powershell.exe,admin_dev,net user hacker Password123! /add,High,Attempt to create local backdoor user account via net.exe
2026-09-11T22:47:26.900Z,workstation-fin-04,1,net1.exe,4264,net.exe,admin_dev,net1 localgroup administrators hacker /add,High,Privilege escalation attempt adding unauthorized user to administrators
2026-09-11T22:47:27.500Z,workstation-fin-04,7,rundll32.exe,4300,powershell.exe,admin_dev,rundll32.exe C:\\Temp\\payload.dll,DllRegisterServer,High,Execution of unauthorized dynamic library DLL payload`
  },

  nginx_application: {
    id: 'nginx_application',
    name: 'Nginx Web & API Gateway Access Logs',
    filename: 'nginx_access_application.log',
    format: 'SYSLOG',
    targetAgent: 'APPLICATION',
    description: 'Nginx Combined web access logs containing SQL injection probes, directory traversal, XSS payloads, and legitimate traffic.',
    eventCount: 11,
    content: `192.168.1.105 - - [11/Sep/2026:22:51:28 +0000] "GET /api/v2/items?category=electronics HTTP/1.1" 200 4520 "https://corp.internal/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.105 - - [11/Sep/2026:22:51:30 +0000] "POST /api/v2/checkout HTTP/1.1" 500 1204 "https://corp.internal/checkout" "python-requests/2.31.0"
192.168.1.105 - - [11/Sep/2026:22:51:31 +0000] "GET /api/v2/checkout?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 403 521 "-" "sqlmap/1.7.1#stable"
192.168.1.105 - - [11/Sep/2026:22:51:32 +0000] "GET /api/v2/checkout?id=1%27%20AND%201=1-- HTTP/1.1" 200 892 "-" "sqlmap/1.7.1#stable"
10.240.12.88 - admin [11/Sep/2026:22:52:01 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
10.240.12.88 - admin [11/Sep/2026:22:52:03 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
10.240.12.88 - admin [11/Sep/2026:22:52:05 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
192.168.1.105 - - [11/Sep/2026:22:53:10 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 230 "-" "curl/7.88.1"
192.168.1.105 - - [11/Sep/2026:22:53:15 +0000] "GET /static/%2e%2e%2f%2e%2e%2fwin.ini HTTP/1.1" 404 230 "-" "curl/7.88.1"
172.16.50.12 - - [11/Sep/2026:22:54:00 +0000] "POST /api/v1/comments HTTP/1.1" 400 312 "https://corp.internal/blog" "Mozilla/5.0 (X11; Linux x86_64)"
172.16.50.12 - - [11/Sep/2026:22:54:12 +0000] "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 400 184 "-" "Mozilla/5.0 (X11; Linux x86_64)"`
  },

  mixed_telemetry: {
    id: 'mixed_telemetry',
    name: 'Multi-Source Enterprise Security Telemetry',
    filename: 'mixed_soc_telemetry_stream.json',
    format: 'JSON',
    targetAgent: 'ALL',
    description: 'Combined JSON feed with heterogeneous field aliases from Network perimeter, Host endpoints, and Application microservices.',
    eventCount: 8,
    content: `[
  {
    "time": "2026-09-11T22:55:00Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.5",
    "sport": 54140,
    "dport": 443,
    "protocol": "TCP",
    "flags": ["SYN"],
    "msg": "SYN packet targeted at protected API gateway",
    "source": "firewall-dmz-01"
  },
  {
    "timestamp": "2026-09-11T22:55:10Z",
    "hostname": "workstation-fin-04",
    "pid": 5012,
    "process": "powershell.exe",
    "user": "admin_dev",
    "cmdline": "powershell -Command Get-Process",
    "message": "PowerShell command execution by local administrative account"
  },
  {
    "timestamp": "2026-09-11T22:55:20Z",
    "app": "checkout-microservice",
    "method": "POST",
    "endpoint": "/api/v2/checkout",
    "status": 500,
    "payload": "{\\"cartId\\": 4210, \\"coupon\\": \\"' OR '1'='1\\"}",
    "message": "Unhandled database exception during coupon verification"
  },
  {
    "event_time": "2026-09-11T22:55:30Z",
    "client_ip": "10.240.12.88",
    "server_ip": "1.1.1.1",
    "dport": 53,
    "proto": "UDP",
    "length": 512,
    "info": "DNS Query for high-entropy dynamic DNS domain"
  },
  {
    "datetime": "2026-09-11T22:55:40Z",
    "host": "auth-gateway-srv-02",
    "pid": 2100,
    "exe": "sshd",
    "username": "root",
    "message": "Failed password for root from 198.51.100.44 port 49200 ssh2"
  },
  {
    "timestamp": "2026-09-11T22:55:50Z",
    "applicationName": "waf-edge-proxy",
    "httpMethod": "GET",
    "uri": "/admin/dashboard",
    "statusCode": 403,
    "userAgent": "Nikto/2.1.6",
    "message": "Known vulnerability scanner user agent blocked by WAF rule"
  },
  {
    "timestamp": "2026-09-11T22:56:00Z",
    "sourceIp": "192.168.1.105",
    "destinationIp": "10.0.0.5",
    "sourcePort": 54142,
    "destinationPort": 22,
    "protocol": "TCP",
    "message": "Connection attempt to closed management port SSH"
  },
  {
    "timestamp": "2026-09-11T22:56:10Z",
    "hostName": "workstation-fin-04",
    "processName": "rundll32.exe",
    "processId": 5044,
    "parentProcess": "powershell.exe",
    "userName": "admin_dev",
    "message": "Execution of unsigned DLL binary from user profile directory"
  }
]`
  }
};

/**
 * Triggers a browser download of a sample dataset file so the user can test the upload dropzone.
 */
export function triggerSampleDownload(sampleKey: string): void {
  const sample = SAMPLE_DATASETS[sampleKey];
  if (!sample) return;

  const mimeMap: Record<string, string> = {
    JSON: 'application/json',
    JSONL: 'application/x-ndjson',
    CSV: 'text/csv',
    SYSLOG: 'text/plain'
  };

  const blob = new Blob([sample.content], { type: mimeMap[sample.format] || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = sample.filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
