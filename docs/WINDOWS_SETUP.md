# Windows Security & Telemetry Collector Setup Guide

## Overview

The **Windows Security & Telemetry Collector** is a modular, high-reliability Python service engineered to collect authentic security and operational telemetry from local and remote Windows workstations and servers.

### Core Guarantees & Constraints
- **Zero Simulation / No Mock Data**: The collector gathers authentic host logs and network states. If an event log channel or directory is missing, it reports `SOURCE_UNAVAILABLE` rather than generating artificial events.
- **Graceful Privilege Handling**: If Administrator elevation is absent, the collector logs a clear permission notice and continues gathering available channels (`System`, `Application`, file tailing, socket metrics).
- **Passive Network Telemetry**: Collects active socket tables and interface bindings non-intrusively via standard OS network utilities. It does not perform packet-level sniffing or offensive scanning.
- **Unified Schema & Deduplication**: All events are normalized with the 7 mandatory telemetry metadata fields:
  1. `source_type`
  2. `hostname`
  3. `collector_name`
  4. `event_id`
  5. `timestamp`
  6. `raw_message`
  7. `collection_status`
  and deduplicated via an LRU SHA-256 fingerprint cache before delivery to the SOC backend.

---

## Architecture & Sources

```
+-------------------------------------------------------------------------------+
|                           WINDOWS HOST ENVIRONMENT                            |
|                                                                               |
|  +---------------------------+  +-------------------+  +-------------------+  |
|  |  WindowsEventLogCollector |  | AppFileTailCollector|  | NetworkTelemetry  |  |
|  |  - System                 |  | - Directory scan  |  | - netstat -ano    |  |
|  |  - Application            |  | - Tail offset     |  | - TCP sockets     |  |
|  |  - Security (Admin req.)  |  | - Rotation handle |  | - Port bindings   |  |
|  +-------------+-------------+  +---------+---------+  +---------+---------+  |
|                |                          |                      |            |
|                +--------------------+     |     +----------------+            |
|                                     v     v     v                             |
|                        +----------------------------+                         |
|                        |      EventNormalizer       |                         |
|                        | - LRU SHA-256 Deduplication|                         |
|                        | - 7-Field Metadata Schema  |                         |
|                        | - MITRE ATT&CK Mapping     |                         |
|                        +--------------+-------------+                         |
|                                       |                                       |
|                        +--------------v-------------+                         |
|                        |   WindowsCollectorService  |                         |
|                        | - Health API (port 8085)   |                         |
|                        | - Batching & Retry Engine  |                         |
|                        +--------------+-------------+                         |
+---------------------------------------|---------------------------------------+
                                        | POST /api/telemetry/ingest
                                        v
+-------------------------------------------------------------------------------+
|                       SOC BACKEND & MULTI-AGENT PIPELINE                      |
|                                                                               |
|  +--------------------+   +-------------------+   +------------------------+  |
|  |  TelemetryManager  |-->|  Multi-Agent Core |-->| Threat Detection / ML  |  |
|  +--------------------+   +-------------------+   +------------------------+  |
|           |                                                    |              |
|           v                                                    v              |
|    Durable Storage                                     Live SOC Dashboard     |
| (MongoDB / PostgreSQL)                                 (SSE Real-Time Stream) |
+-------------------------------------------------------------------------------+
```

---

## Prerequisites

| Requirement | Details |
| :--- | :--- |
| **Operating System** | Windows 10, Windows 11, or Windows Server 2016/2019/2022/2025 |
| **Python** | Python 3.8+ (Uses Python Standard Library; **no pip packages required** for basic operation) |
| **Elevation** | **Standard User**: Collects `System`, `Application` logs, app file tailing, socket tables.<br>**Administrator (Elevated)**: Required to read the `Security` channel (Logon audits, privilege changes). |
| **Network Access** | Outbound HTTP/HTTPS to the SOC server URL (default `http://localhost:3000`). |

---

## Configuration Reference

All settings can be configured via environment variables or CLI flags:

| Setting | Environment Variable | CLI Argument | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Enabled Collectors** | `ENABLED_COLLECTORS` | `--enabled-collectors` | `event_log,file_tail,network` | Comma-separated list of active collectors |
| **Event Log Channels** | `WIN_EVENT_CHANNELS` | `--channels` | `System,Application,Security` | Windows Event Log channels to monitor |
| **App Log Folders** | `APP_LOG_DIRECTORIES` | `--app-log-dirs` | Empty / Auto-detected | Comma-separated list of log directory paths |
| **App Log Extensions** | `APP_LOG_EXTENSIONS` | `--app-log-exts` | `.log,.txt,.json,.log.1` | File extensions monitored for tailing |
| **Collection Interval**| `COLLECTION_INTERVAL_SEC` | `--interval` | `5.0` | Seconds between telemetry collection cycles |
| **Max Batch Size** | `MAX_BATCH_SIZE` | `--batch-size` | `100` | Max events per collector cycle |
| **Backend API URL** | `BACKEND_API_URL` | `--backend-url` | `http://localhost:3000` | Target SOC backend URL |
| **Backend API Key** | `BACKEND_API_KEY` | `--backend-api-key`| Empty | Optional bearer token for SOC ingestion |
| **MongoDB URI** | `MONGODB_URI` | `--mongo-uri` | Empty | Optional direct MongoDB persistence |
| **MongoDB DB Name** | `MONGODB_DB_NAME` | `--mongo-db` | `cyber_threat_soc` | Target MongoDB database name |
| **Health Server Port** | `COLLECTOR_HEALTH_PORT` | `--health-port`| `8085` | Local HTTP control port |
| **Log Level** | `LOG_LEVEL` | `--log-level` | `INFO` | Console logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## Exact Windows Commands

### 1. Run Standard Collection (PowerShell or Command Prompt)
For monitoring System and Application logs, file tailing, and socket tables:

```powershell
# Navigate to the project root
cd C:\path\to\ai-driven-multi-agent-system

# Run collector against local SOC backend
python run_windows_collector.py --backend-url http://localhost:3000 --interval 4.0
```

### 2. Run with Administrator Elevation (For Security Audit Logs)
Right-click **PowerShell** or **Command Prompt** and select **"Run as Administrator"**:

```powershell
# Run with full Security audit channel inspection enabled
python run_windows_collector.py `
  --backend-url http://localhost:3000 `
  --channels System,Application,Security `
  --interval 3.0 `
  --log-level INFO
```

### 3. Run with Custom Application Log Directories
To monitor web application logs (IIS, Nginx, custom services):

```powershell
python run_windows_collector.py `
  --backend-url http://localhost:3000 `
  --app-log-dirs "C:\inetpub\logs\LogFiles,C:\ProgramData\AppLogs,D:\Services\Logs" `
  --interval 5.0
```

### 4. Run with Authentication Key
When the SOC backend requires ingestion authorization:

```powershell
# Set environment variable
$env:BACKEND_API_KEY="your-soc-api-key"
$env:BACKEND_API_URL="http://soc.internal:3000"

python run_windows_collector.py
```

---

## Local Collector Health & Control API

When the service runs, it exposes a local HTTP management endpoint on port `8085` (or configured `COLLECTOR_HEALTH_PORT`):

### Check Collector Health
```powershell
curl http://localhost:8085/health
```
Response:
```json
{
  "status": "HEALTHY",
  "service": "Windows Security Telemetry Collector",
  "version": "1.0.0",
  "hostname": "WIN-WORKSTATION-01",
  "uptime_seconds": 124.5,
  "is_running": true,
  "cycles_completed": 31,
  "total_events_transmitted": 84,
  "total_transmission_errors": 0
}
```

### Check Detailed Collector Status & Permissions
```powershell
curl http://localhost:8085/status
```
Response includes each collector's state:
- `event_log`: Individual channels, permission status, record ID bookmarks.
- `file_tail`: Monitored log files, byte offsets, file rotation status.
- `network`: Active TCP connections, listening sockets, interface count.

### Trigger Immediate Telemetry Cycle
```powershell
curl -X POST http://localhost:8085/collect-now
```

### Pause and Resume Telemetry
```powershell
# Pause collection
curl -X POST http://localhost:8085/stop

# Resume collection
curl -X POST http://localhost:8085/start
```

---

## Testing & Verification

### 1. Run Automated Unit Tests
The test suite validates XML parsing, deduplication, log rotation, permission denial handling, and non-Windows graceful degradation:

```bash
python -m unittest cyber_agents/tests/test_windows_collector.py -v
```

### 2. Verify Live Event Ingestion in SOC Dashboard
1. Open the SOC Dashboard in your browser (`http://localhost:3000`).
2. Navigate to **Live Security Pipeline** -> **Telemetry Ingestion Layer**.
3. Expand **External Host Agent**.
4. Confirm your Windows host appears under **Active External Windows Telemetry Agents** with status `COLLECTED`.
5. Events will automatically flow through:
   - Event Normalization
   - Preprocessing
   - Multi-Agent Threat Analysis
   - Risk Scoring Engine
   - Durable Storage & Real-Time Alerts
