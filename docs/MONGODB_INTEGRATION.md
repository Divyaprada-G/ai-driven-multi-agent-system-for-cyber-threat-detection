# Secure MongoDB Integration Documentation
## AI-Driven Multi-Agent Cyber Threat Detection System

This document provides complete instructions for installing, configuring, and maintaining the MongoDB database integration for the multi-agent cybersecurity platform.

---

## 1. MongoDB Setup Instructions for Windows

Follow these steps to set up a local MongoDB Community instance on a Windows workstation or server:

### Step 1.1: Download MongoDB Community Server
1. Navigate to the official MongoDB Download Center:
   ```
   https://www.mongodb.com/try/download/community
   ```
2. Select:
   - **Version**: `7.0.x` or latest LTS
   - **Platform**: `Windows (x64)`
   - **Package**: `MSI`
3. Click **Download**.

### Step 1.2: Run the Installer
1. Double-click the downloaded `.msi` file.
2. Accept the terms and select **Complete** installation setup.
3. In the **Service Configuration** screen:
   - Check **"Install MongoDB as a Service"**.
   - Select **"Run service as Network Service user"**.
   - Service Name: `MongoDB`
   - Data Directory: `C:\Program Files\MongoDB\Server\7.0\data\`
   - Log Directory: `C:\Program Files\MongoDB\Server\7.0\log\`
4. (Optional but recommended) Leave **"Install MongoDB Compass"** checked. Compass provides a GUI to visually inspect security events, incidents, and threat detections.
5. Click **Next** and complete the installation.

### Step 1.3: Verify MongoDB Windows Service
Open PowerShell as Administrator:
```powershell
# Check service status
Get-Service MongoDB

# If stopped, start the service:
Start-Service MongoDB

# Verify port 27017 is listening:
Test-NetConnection -ComputerName localhost -Port 27017
```

### Step 1.4: Install and Test MongoDB Shell (`mongosh`)
1. Download `mongosh` from: `https://www.mongodb.com/try/download/shell`
2. Add `mongosh.exe` to your Windows `PATH` environment variable.
3. Connect from PowerShell:
   ```powershell
   mongosh "mongodb://localhost:27017"
   ```
4. In `mongosh`, verify database creation:
   ```javascript
   use cyber_threat_detection
   db.createCollection("security_events")
   show collections
   ```

---

## 2. Required Environment Variables

All MongoDB connection strings and database options are read from server-side environment variables (`process.env`) and are **never exposed to client-side code**.

Add the following to your root `.env` file:

```env
# ==============================================================================
# MONGODB DATABASE CONFIGURATION
# ==============================================================================

# Local Windows MongoDB Instance:
MONGODB_URI="mongodb://localhost:27017"
MONGODB_DB_NAME="cyber_threat_detection"

# OR Remote / MongoDB Atlas Cluster with TLS/SSL:
# MONGODB_URI="mongodb+srv://soc_agent_svc:<ENCRYPTED_PASSWORD>@cluster0.mongodb.net/?retryWrites=true&w=majority&appName=CyberDetection"
# MONGODB_DB_NAME="cyber_threat_detection"

# Optional Connection Pool Limits:
# MONGODB_MAX_POOL_SIZE=50
# MONGODB_MIN_POOL_SIZE=5
```

### Security Best Practices
- **No Client Exposure**: The Vite client is restricted from bundling variables without the `VITE_` prefix. All MongoDB interactions route through the server backend (`/api/mongo/*`).
- **Connection Resiliency**: If `MONGODB_URI` is omitted or MongoDB is unreachable, the system automatically falls back to the resilient local JSON store (`/data/local_db.json`) with zero downtime.

---

## 3. Database Schema & Index Explanation

The system maintains 6 core collections in MongoDB with automated index provisioning.

### 3.1 `security_events`
Stores normalized security telemetry ingested from Zeek, Suricata, Syslog, Windows Event Logs, and Application APIs.

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB unique document identifier |
| `id` | String | Unique event ID (e.g. `EVT-UUID`) |
| `contentHash` | String | SHA-256 deterministic hash of payload for deduplication |
| `source` | String | Telemetry source (`Zeek`, `Suricata`, `Syslog`, `Auth`) |
| `eventType` | String | Classification (e.g. `PORT_SCAN`, `SSH_BRUTE_FORCE`) |
| `severity` | String | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `timestamp` | Date | Event occurrence timestamp |
| `sourceIp` | String | IPv4 / IPv6 source address |
| `destinationIp` | String | IPv4 / IPv6 target address |
| `sourcePort` | Number | Source network port |
| `destinationPort` | Number | Destination network port |
| `rawPayload` | String | Sanitized raw event data (credentials redacted) |
| `normalizedFields` | Object | Structured key-value telemetry |
| `createdAt` | Date | Ingestion timestamp |

**Indexes**:
- `{ contentHash: 1 }` (Unique): Eliminates redundant events and prevents alert spam.
- `{ timestamp: -1, severity: 1 }`: Fast time-window sorting and severity filtering.
- `{ sourceIp: 1, destinationIp: 1 }`: Accelerated cross-agent correlation queries.

---

### 3.2 `incidents`
Stores multi-agent correlated security incidents with risk scores, MITRE ATT&CK techniques, and SOC analyst audit trails.

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB identifier |
| `incidentId` | String | Unique Incident identifier (`INC-UUID`) |
| `title` | String | Incident title |
| `description` | String | Detailed investigation context |
| `severity` | String | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `priority` | String | `P1`, `P2`, `P3`, `P4` |
| `status` | String | `NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED` |
| `riskScore` | Number | Composite risk score (0–100) |
| `primaryIp` | String | Primary indicator IP |
| `mitreTechniques` | Array<String> | MITRE ATT&CK technique IDs (e.g. `['T1046', 'T1110']`) |
| `correlatedEvents`| Array<String> | References to `security_events` IDs |
| `investigationNotes` | Array<Object> | Timestamped SOC notes (`id`, `author`, `note`, `timestamp`) |
| `containmentStatus` | String | `UNCONTAINED`, `CONTAINED`, `REMEDIATED` |
| `history` | Array<Object> | Status transition audit logs |
| `createdAt` | Date | Incident detection timestamp |
| `updatedAt` | Date | Last modification timestamp |

**Indexes**:
- `{ incidentId: 1 }` (Unique): Fast single incident lookup.
- `{ status: 1, severity: 1 }`: Incident triage board queries.
- `{ riskScore: -1, createdAt: -1 }`: Prioritized incident queue sorting.

---

### 3.3 `threat_detections`
Stores ML-based classifier detections (Random Forest, Isolation Forest) and rule-based agent findings.

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB identifier |
| `detectionId` | String | Unique detection ID (`DET-UUID`) |
| `eventId` | String | Reference to security event |
| `threatType` | String | Threat category (e.g. `DDoS - SYN Flood`, `Lateral Movement`) |
| `severity` | String | Severity rating |
| `confidence` | Number | ML confidence score (0.00 – 1.00) |
| `detectionEngine` | String | Engine (`ML_ISOLATION_FOREST`, `ML_RANDOM_FOREST`, `RULE_HEURISTIC`) |
| `agentId` | String | Detecting agent (`network-agent`, `system-agent`, `application-agent`) |
| `features` | Object | Normalized ML feature vector |
| `timestamp` | Date | Detection timestamp |

**Indexes**:
- `{ detectionId: 1 }` (Unique)
- `{ timestamp: -1, severity: 1 }`
- `{ detectionEngine: 1, confidence: -1 }`

---

### 3.4 `alerts`
Stores high-priority notifications dispatched to SOC analysts and external automation webhooks (e.g. n8n).

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB identifier |
| `alertId` | String | Unique Alert ID (`ALT-UUID`) |
| `title` | String | Alert summary |
| `severity` | String | Alert severity |
| `status` | String | `NEW`, `ACKNOWLEDGED`, `ESCALATED`, `DISMISSED` |
| `incidentId` | String | Correlated incident reference |
| `evidence` | Array<Object> | Supporting forensic artifacts |
| `notificationSent`| Boolean | External webhook dispatch flag |
| `createdAt` | Date | Dispatch timestamp |

**Indexes**:
- `{ alertId: 1 }` (Unique)
- `{ status: 1, severity: 1 }`
- `{ incidentId: 1 }`

---

### 3.5 `agent_logs`
Stores execution traces and diagnostic logs from autonomous domain agents.

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB identifier |
| `logId` | String | Log entry identifier |
| `agentId` | String | Domain agent ID (`network-agent`, `system-agent`, etc.) |
| `action` | String | Action executed |
| `level` | String | `INFO`, `WARN`, `ERROR`, `CRITICAL` |
| `message` | String | Execution message |
| `payload` | Object | Sanitized parameters |
| `timestamp` | Date | Execution timestamp |

**Indexes**:
- `{ agentId: 1, timestamp: -1 }`
- `{ level: 1 }`

---

### 3.6 `model_metadata`
Stores ML model registry data, training versions, accuracy, F1-scores, and hyperparameters.

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB identifier |
| `modelId` | String | Model identifier (e.g. `RF-CICIDS2017-V2`) |
| `modelType` | String | `RandomForestClassifier`, `IsolationForest` |
| `version` | String | Semantic version string |
| `status` | String | `ACTIVE`, `STAGING`, `ARCHIVED` |
| `metrics` | Object | Accuracy, Precision, Recall, F1-Score |
| `hyperparameters` | Object | Model parameters (e.g. `n_estimators`, `max_depth`) |
| `features` | Array<String> | Feature column names |
| `updatedAt` | Date | Last registration timestamp |

**Indexes**:
- `{ modelId: 1 }` (Unique)
- `{ status: 1, version: -1 }`

---

## 4. API Endpoint Documentation

All endpoints are hosted under `/api/mongo/*` on the Express backend.

### 4.1 Health & Diagnostics
- **`GET /api/mongo/health`**
  - **Description**: Returns live connection state, database name, ping latency in ms, and document counts across all 6 collections.
  - **Sample Response**:
    ```json
    {
      "status": "ONLINE",
      "connected": true,
      "database": "cyber_threat_detection",
      "latencyMs": 2,
      "collections": {
        "securityEvents": 1420,
        "incidents": 38,
        "threatDetections": 115,
        "alerts": 29,
        "agentLogs": 482,
        "modelMetadata": 4
      }
    }
    ```

- **`POST /api/mongo/test-suite`**
  - **Description**: Executes the automated 13-test integration suite covering data sanitization, deduplication, CRUD operations, status workflows, and aggregations.
  - **Sample Response**:
    ```json
    {
      "timestamp": "2026-09-17T11:00:42.712Z",
      "totalTests": 13,
      "passedTests": 13,
      "failedTests": 0,
      "results": [...]
    }
    ```

---

### 4.2 Security Events
- **`POST /api/mongo/events`**
  - **Description**: Ingests and sanitizes a security event. Replaces plaintext credentials with `[REDACTED]` and checks `contentHash` for deduplication.
  - **Body**:
    ```json
    {
      "source": "Suricata",
      "eventType": "SSH_BRUTE_FORCE",
      "severity": "HIGH",
      "sourceIp": "198.51.100.24",
      "destinationIp": "10.0.0.15",
      "destinationPort": 22,
      "rawPayload": "Failed password for root from 198.51.100.24 port 54321 ssh2",
      "normalizedFields": { "attemptCount": 14 }
    }
    ```
  - **Response Status**: `201 Created` (or `200 OK` if duplicate).

- **`GET /api/mongo/events`**
  - **Query Parameters**:
    - `source` (optional): Filter by source name
    - `eventType` (optional): Filter by event type
    - `severity` (optional): Filter by `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
    - `sourceIp` / `destinationIp` (optional): IP search
    - `from` / `to` (optional): ISO 8601 timestamps
    - `page` (default: 1): Page number
    - `limit` (default: 50, max: 200): Records per page
    - `sortBy` (default: `timestamp`): Sort column
    - `sortOrder` (`asc` | `desc`): Sort direction

---

### 4.3 Incidents
- **`POST /api/mongo/incidents`**
  - **Description**: Creates a correlated security incident.
  - **Body**:
    ```json
    {
      "incidentId": "INC-2026-0917-001",
      "title": "Cross-Agent Correlated Lateral Movement",
      "description": "Port scan identified by Network Agent followed by privilege escalation on App Agent",
      "severity": "CRITICAL",
      "priority": "P1",
      "status": "NEW",
      "riskScore": 92,
      "primaryIp": "192.168.1.50",
      "mitreTechniques": ["T1046", "T1078"],
      "correlatedEvents": ["EVT-1001", "EVT-1002"]
    }
    ```

- **`GET /api/mongo/incidents`**
  - **Query Parameters**:
    - `status`: `NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, etc.
    - `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
    - `priority`: `P1`, `P2`, `P3`, `P4`
    - `minRisk`: Numeric minimum risk score (e.g. `50`)
    - `page`, `limit`, `sortBy`, `sortOrder`

- **`GET /api/mongo/incidents/:id`**
  - **Description**: Retrieves single incident by its `incidentId`.

- **`PATCH /api/mongo/incidents/:id/status`**
  - **Description**: Updates incident status with actor audit tracking.
  - **Body**:
    ```json
    {
      "status": "INVESTIGATING",
      "actor": "SOC Senior Analyst",
      "reason": "Host quarantined from internal subnet"
    }
    ```

- **`POST /api/mongo/incidents/:id/notes`**
  - **Description**: Appends an investigation note to the incident's note log.
  - **Body**:
    ```json
    {
      "note": "Forensic dump acquired from dmz-srv01. Analysis ongoing.",
      "author": "Forensic Investigator"
    }
    ```

---

### 4.4 Alerts & History
- **`GET /api/mongo/alerts`**
  - **Query Parameters**: `status`, `severity`, `incidentId`, `limit`, `page`
  - **Description**: Retrieves alert history with filtering and pagination.

- **`PATCH /api/mongo/alerts/:id/status`**
  - **Description**: Updates alert status (`ACKNOWLEDGED`, `DISMISSED`, `ESCALATED`).

---

### 4.5 Dashboard Statistics
- **`GET /api/mongo/stats`**
  - **Description**: Returns live aggregation of total events, active threats by severity, open incidents, alerts count, and active ML models.
  - **Sample Response**:
    ```json
    {
      "status": "ONLINE",
      "totalEvents": 1420,
      "threatsDetected": 115,
      "criticalThreats": 14,
      "highThreats": 42,
      "mediumThreats": 38,
      "lowThreats": 21,
      "activeIncidents": 8,
      "resolvedIncidents": 30,
      "totalAlerts": 45,
      "openAlerts": 6,
      "agentLogsCount": 482,
      "activeModelsCount": 2,
      "source": "MONGODB"
    }
    ```
