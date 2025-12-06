# CyberGard Log Ingestion: Complete Step-by-Step Flow Documentation

## Table of Contents
1. [Overview & Architecture](#overview--architecture)
2. [Pre-Deployment Setup](#pre-deployment-setup)
3. [Device Deployment Phase](#device-deployment-phase)
4. [Log Collection & Forwarding (Runtime)](#log-collection--forwarding-runtime)
5. [API Ingestion & Processing](#api-ingestion--processing)
6. [UEBA Analysis & Storage](#ueba-analysis--storage)
7. [Dashboard & Alerts](#dashboard--alerts)
8. [Troubleshooting & Monitoring](#troubleshooting--monitoring)

---

## Overview & Architecture

### High-Level System Flow

```
[Device 1]  [Device 2]  [Device 3]  ... [Device 10]
     |            |            |                |
     +------------|------------|-----...--------|
                  |            |                |
            (Network - HTTP/HTTPS)
                  |            |                |
              [Forwarder / Beats Agent]
                  |            |                |
     +------------|------------|-----...--------|
                  |            |                |
         [CyberGard Backend API]
              (Port 8000/443)
                  |
        POST /api/v1/logs/ingest
                  |
         [API Handler Layer]
                  |
         [Log Normalization]
                  |
         [Database Storage]
                  |
    [UEBA / ML Analysis Engine]
                  |
      [Alert Generation & Storage]
                  |
         [Frontend Dashboard]
```

### Key Components

| Component | Role | Location |
|-----------|------|----------|
| **Forwarder/Agent** | Collects logs from device and sends to CyberGard API | Each device |
| **Backend API** | Receives and processes log ingestion requests | `backend/app/main.py` |
| **Log Handler** | Routes logs to appropriate processors | `backend/app/api/` |
| **Normalization Layer** | Standardizes log format | `backend/app/schemas/` |
| **Database** | Stores raw logs | PostgreSQL/SQLite |
| **UEBA Engine** | Analyzes patterns for anomalies | `ml/` module |
| **Frontend** | Displays logs, alerts, and dashboards | `frontend/` |

---

## Pre-Deployment Setup

### Step 1: Prepare the CyberGard Server

**What happens:**
1. Backend API is running and listening on port 8000 (or 443 for HTTPS)
2. Database is initialized and ready to accept log records
3. API authentication (API keys) is configured

**Actions to take:**

```bash
# Start the backend server
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Verify API is running
curl http://localhost:8000/api/v1/logs/ingest -X POST \
  -H "Content-Type: application/json" \
  -d '[{"timestamp":"2025-12-06T12:00:00Z","details":{"test":"ok"}}]'
```

**What the system does:**
- Initializes the database schema (creates tables for logs, events, UEBA analysis results)
- Loads ML models (if pre-trained) for UEBA analysis
- Starts the FastAPI server and begins listening for incoming requests
- Loads configuration (batch sizes, processing intervals, etc.)

**Expected output:**
```json
{
  "status": "success",
  "message": "Ingested 1 logs",
  "processed": true
}
```

---

### Step 2: Prepare Devices & Credentials

**What happens:**
1. Identify all 10 devices and document their hostnames/IPs
2. Generate API keys for authentication
3. Prepare device manifest (CSV file with device info)

**Actions to take:**

```powershell
# Create API key (example)
# In production, generate via your API key management system
$apiKey = "sk_prod_$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"

# Example devices_manifest.csv
# DeviceName,IpAddress,ApiKey
# Device01,192.168.1.101,sk_prod_1234567890
# Device02,192.168.1.102,sk_prod_0987654321
# ... (repeat for all 10 devices)
```

**What the system does:**
- Validates device hostnames/IPs
- Stores API keys securely (should be hashed in real implementation)
- Prepares device metadata for log attribution

---

## Device Deployment Phase

### Step 3: Deploy Forwarder to Each Device

**Timeline:**

#### **Phase 3A: Windows Device Deployment (Device01 - Device05)**

**Command executed (PowerShell as Admin on Device01):**

```powershell
$parameters = @{
    DeviceName = "Device01"
    ApiUrl = "https://cybergard.company.com/api/v1/logs/ingest"
    ApiKey = "sk_prod_1234567890"
    SkipVerify = $false
    CaBundle = "C:\certs\ca.crt"
}

.\deploy_windows.ps1 @parameters
```

**What happens step-by-step:**

| Step | Action | System Response | Time |
|------|--------|-----------------|------|
| 1 | Check Admin privileges | Verifies PowerShell runs as Admin | 0.1s |
| 2 | Verify Python 3 installation | Checks `python --version` | 0.2s |
| 3 | Create `C:\CyberGard\` directory | Directory created with proper permissions | 0.1s |
| 4 | Copy `remote_log_forwarder.py` to `C:\CyberGard\` | Script deployed, ready to execute | 0.3s |
| 5 | Build Scheduled Task arguments | Constructs command with API key and URL | 0.1s |
| 6 | Register Scheduled Task "CyberGardLogForwarder-Device01" | Task registered in Windows Task Scheduler | 0.5s |
| 7 | Enable task auto-startup | Task set to run at system startup | 0.2s |
| 8 | Start forwarder immediately | Service starts in background (pythonw.exe) | 0.3s |

**Total deployment time: ~2 seconds per device**

**File structure after deployment:**

```
C:\CyberGard\
├── remote_log_forwarder.py
└── forwarder_state.json (created on first run)

Windows Task Scheduler:
  Task Name: CyberGardLogForwarder-Device01
  Trigger: At system startup
  Action: pythonw.exe C:\CyberGard\remote_log_forwarder.py --url https://... --api-key sk_prod_...
```

#### **Phase 3B: Linux Device Deployment (Device06 - Device10)**

**Command executed (root on Device06):**

```bash
sudo bash deploy_linux.sh \
  --device-name Device06 \
  --api-url https://cybergard.company.com/api/v1/logs/ingest \
  --api-key sk_prod_0987654321 \
  --ca-bundle /etc/ssl/certs/ca-certificates.crt
```

**What happens step-by-step:**

| Step | Action | System Response | Time |
|------|--------|-----------------|------|
| 1 | Verify root privileges | Checks `$EUID -ne 0` | 0.1s |
| 2 | Check Python 3 installation | Checks `command -v python3` | 0.2s |
| 3 | Create `/opt/cybergard/` directory | Directory created with mode 0755 | 0.1s |
| 4 | Copy `remote_log_forwarder.py` to `/opt/cybergard/` | Script deployed, made executable | 0.3s |
| 5 | Create systemd service file | `/etc/systemd/system/cybergard-forwarder.service` created | 0.2s |
| 6 | Reload systemd daemon | `systemctl daemon-reload` executed | 0.3s |
| 7 | Enable service for auto-boot | Service linked to `multi-user.target` | 0.2s |
| 8 | Start service immediately | `systemctl start cybergard-forwarder` executed | 0.5s |

**Total deployment time: ~2 seconds per device**

**File structure after deployment:**

```
/opt/cybergard/
├── remote_log_forwarder.py
└── forwarder_state.json (created on first run)

/etc/systemd/system/
└── cybergard-forwarder.service

Systemd status:
  Service Name: cybergard-forwarder
  Status: active (running)
  Enabled: yes (auto-start on boot)
```

**Service file contents:**

```ini
[Unit]
Description=CyberGard Log Forwarder - Device06
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/cybergard/remote_log_forwarder.py --url https://... --api-key sk_prod_...
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Log Collection & Forwarding (Runtime)

### Step 4: Forwarder Initialization & Log Collection

**Triggered by:** Device startup (automatic) or manual start

#### **Timeline for Single Device (Device01 - Windows)**

| Time (Seconds) | Event | Details |
|---|---|---|
| 0 | **Startup** | `pythonw.exe` spawns `remote_log_forwarder.py` |
| 0.5 | **Argument Parsing** | Script reads `--url`, `--api-key`, `--device-name` |
| 1 | **OS Detection** | Detects Windows via `platform.system()` |
| 1.5 | **Load State File** | Reads `forwarder_state.json` (tracking last event record numbers) |
| 2 | **Initialize Forwarder** | `WindowsForwarder` class instantiated |
| 2.5 | **Get Hostname** | `socket.gethostname()` returns "Device01" |
| 3 | **Logging Setup** | Logger initialized, writes to console (redirected to void by pythonw) |
| 3 | **START MAIN LOOP** | Enters infinite `while True` loop |

**What happens in the main loop (every 10 seconds by default):**

```
=== POLLING CYCLE (Every 10 seconds) ===

[Cycle Start: T=3s]
  |
  +-> Read Windows Event Logs (System, Application, Security)
  |    - Opens handle to each event log
  |    - Reads events backwards from newest
  |    - Filters out already-processed events using stored RecordNumber
  |
  +-> Format Events into JSON
  |    {
  |      "source": "Security",
  |      "message": "User logon succeeded",
  |      "event_id": 4624,
  |      "computer": "Device01",
  |      "timestamp": "2025-12-06T14:30:45.123456"
  |    }
  |
  +-> Batch Events (up to BATCH_SIZE=50)
  |
  +-> Save State (record numbers of processed events)
  |
  +-> POST to CyberGard API
  |    HTTP POST https://cybergard.company.com/api/v1/logs/ingest
  |    Headers: {
  |      "Content-Type": "application/json",
  |      "Authorization": "Bearer sk_prod_1234567890"
  |    }
  |    Body: [event1, event2, ..., eventN]
  |
  +-> Check Response
  |    - 200 OK: Success, save state
  |    - 4xx/5xx: Log error, retry later
  |
  +-> Sleep 10 seconds
  |
[Cycle End: T=13s]

=== NEXT CYCLE BEGINS ===
```

**Actual code flow (simplified):**

```python
# In WindowsForwarder.run()
while True:
    all_logs = []
    
    for source in ['System', 'Application', 'Security']:
        hand = win32evtlog.OpenEventLog(None, source)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ
        
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        while events:
            for event in events:
                # Skip already-processed events
                if event.RecordNumber <= self.state.get(source, 0):
                    continue
                
                # Update state
                self.state[source] = event.RecordNumber
                
                # Format event
                logs.append({
                    "source": source,
                    "message": msg,
                    "event_id": event.EventID,
                    "computer": self.computer_name,
                    "timestamp": datetime.fromtimestamp(event.TimeGenerated).isoformat()
                })
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        win32evtlog.CloseEventLog(hand)
    
    # Forward to API
    self.forward(all_logs)
    
    # Save state
    self.save_state()
    
    # Wait for next cycle
    time.sleep(POLL_INTERVAL)  # 10 seconds
```

#### **Timeline for Single Device (Device06 - Linux)**

| Time (Seconds) | Event | Details |
|---|---|---|
| 0 | **Startup** | `systemctl start cybergard-forwarder` spawns `/usr/bin/python3` |
| 0.5 | **Argument Parsing** | Script reads systemd environment variables and CLI args |
| 1 | **OS Detection** | Detects Linux via `platform.system()` |
| 1.5 | **Load State File** | Reads `forwarder_state.json` (file positions in log files) |
| 2 | **Initialize Forwarder** | `LinuxForwarder` class instantiated |
| 2.5 | **Get Hostname** | `socket.gethostname()` returns "Device06" |
| 3 | **Logging Setup** | Logger configured to output to `journalctl` |
| 3 | **START MAIN LOOP** | Enters infinite `while True` loop |

**What happens in Linux polling cycle (every 10 seconds):**

```
=== POLLING CYCLE (Every 10 seconds) ===

[Cycle Start: T=3s]
  |
  +-> Iterate over log files ['/var/log/syslog', '/var/log/auth.log']
  |
  +-> For each log file:
  |    - Get current file size
  |    - Retrieve last known file position from state
  |    - If file was rotated (pos > size): reset position to 0
  |    - Open file and seek to saved position
  |    - Read all new lines since last position
  |    - Update file position to current EOF
  |
  +-> Format Lines into JSON
  |    {
  |      "source": "/var/log/auth.log",
  |      "message": "Failed password for invalid user admin from 192.168.1.50",
  |      "computer": "Device06",
  |      "timestamp": "2025-12-06T14:30:45.123456"
  |    }
  |
  +-> Batch Events (up to BATCH_SIZE=50)
  |
  +-> Save State (file positions)
  |
  +-> POST to CyberGard API
  |    (Same as Windows, with Authorization header)
  |
  +-> Check Response (retry logic)
  |
  +-> Sleep 10 seconds
  |
[Cycle End: T=13s]
```

### Step 5: Network Communication & Authentication

**What happens during POST request:**

```
Device01 (Windows) / Device06 (Linux)
           |
           | HTTPS Connection Established
           | TLS Handshake (1-3 seconds)
           | Verifies server certificate against CA bundle
           |
CyberGard Server (port 443)
           |
           v
[Nginx Reverse Proxy] (if configured)
           |
           | Route to /api/v1/logs/ingest
           | Extract Authorization header: "Bearer sk_prod_1234567890"
           |
           v
[FastAPI Backend - app/main.py]
           |
           +-> Authentication Middleware
           |    - Decode bearer token
           |    - Verify API key against database
           |    - Check rate limits
           |    - Set user/device context
           |
           +-> Validation
           |    - Parse JSON payload
           |    - Validate against LogSchema
           |    - Check for required fields (timestamp, details)
           |
           +-> Request Handler
           |    POST /api/v1/logs/ingest (in app/api/)
           |
           v
```

**Detailed request/response:**

```http
POST /api/v1/logs/ingest HTTP/1.1
Host: cybergard.company.com
Content-Type: application/json
Authorization: Bearer sk_prod_1234567890
Content-Length: 1250

[
  {
    "timestamp": "2025-12-06T14:30:45.123Z",
    "details": {
      "source": "Security",
      "message": "User logon succeeded",
      "event_id": 4624,
      "computer": "Device01",
      "user": "admin",
      "source_ip": "192.168.1.50"
    }
  },
  {
    "timestamp": "2025-12-06T14:30:50.456Z",
    "details": { ... }
  }
]

---

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 95

{
  "status": "success",
  "message": "Ingested 2 logs",
  "processed": true
}
```

---

## API Ingestion & Processing

### Step 6: API Handler & Database Storage

**Location:** `backend/app/api/logs.py` or `backend/app/main.py`

**What happens immediately after API receives POST:**

| Step | Component | Action | Time |
|------|-----------|--------|------|
| 1 | Authentication Middleware | Validates Bearer token against API keys table | 10ms |
| 2 | Request Parser | Deserializes JSON to LogSchema objects | 5ms |
| 3 | Validation Layer | Checks required fields (timestamp, details) | 5ms |
| 4 | Device Mapper | Maps API key to device_id and device_name | 5ms |
| 5 | Timestamp Normalization | Converts to UTC, validates format | 5ms |
| 6 | Database Insertion | Executes SQL INSERT into logs table | 50-200ms |
| 7 | Transaction Commit | Commits to PostgreSQL/SQLite | 10-50ms |
| 8 | Response Builder | Builds HTTP 200 response | 5ms |
| 9 | Response Send | Sends back to forwarder | 5ms |

**Total processing time: 95-290ms per batch**

**Database schema (simplified):**

```sql
CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  device_id INT REFERENCES devices(id),
  timestamp TIMESTAMP NOT NULL,
  source VARCHAR(255),
  message TEXT,
  event_id INT,
  user VARCHAR(255),
  source_ip INET,
  details JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  indexed_at TIMESTAMP,
  processed_by_ueba BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_timestamp ON logs(timestamp);
CREATE INDEX idx_device_id ON logs(device_id);
CREATE INDEX idx_processed_by_ueba ON logs(processed_by_ueba);
```

**What gets stored in database:**

```json
{
  "id": 12345,
  "device_id": 1,
  "device_name": "Device01",
  "timestamp": "2025-12-06T14:30:45.123Z",
  "source": "Security",
  "message": "User logon succeeded",
  "event_id": 4624,
  "user": "admin",
  "source_ip": "192.168.1.50",
  "details": {
    "source": "Security",
    "message": "User logon succeeded",
    "event_id": 4624,
    "computer": "Device01",
    "user": "admin",
    "source_ip": "192.168.1.50"
  },
  "created_at": "2025-12-06T14:30:45.123Z",
  "indexed_at": null,
  "processed_by_ueba": false
}
```

**Forwarder receives response:**

```python
resp = requests.post(api_url, json=payload, headers=headers)
if resp.status_code == 200:
    logger.info(f"Forwarded {len(logs)} logs.")
    self.save_state()  # Save event record numbers
else:
    logger.error(f"Failed to forward: {resp.status_code}")
```

---

## UEBA Analysis & Storage

### Step 7: Background Processing & ML Analysis

**Triggered by:** Background task or scheduled job (Celery worker)

**Timeline:**

| Time (Post-Ingestion) | Event | Details |
|---|---|---|
| 0-5 seconds | **Batch Accumulation** | API continues to receive logs from all 10 devices |
| 5-30 seconds | **UEBA Task Triggered** | Celery beat scheduler triggers UEBA analysis every 30 seconds (configurable) |
| 30-35 seconds | **Query Unprocessed Logs** | DB query: `SELECT * FROM logs WHERE processed_by_ueba = FALSE LIMIT 1000` |
| 35-40 seconds | **Load ML Models** | UEBA engine loads trained models from `ml/artifacts/` |
| 40-120 seconds | **Feature Extraction** | Extract features per user/device: login patterns, data access, privilege changes |
| 120-130 seconds | **Anomaly Detection** | Apply ML models (Isolation Forest, Local Outlier Factor, etc.) |
| 130-140 seconds | **Risk Scoring** | Assign risk score (0-100) to each event/session |
| 140-150 seconds | **Alert Generation** | Generate alerts for anomalies (risk > threshold) |
| 150-160 seconds | **Database Update** | Insert alerts, update `processed_by_ueba = TRUE` for processed logs |

**Code flow (conceptual):**

```python
# In backend/app/services/ueba_service.py or ml/services/

def process_logs_for_ueba():
    """Background task to analyze logs"""
    
    # Step 1: Get unprocessed logs
    unprocessed_logs = db.query(Log).filter(
        Log.processed_by_ueba == False
    ).limit(1000).all()
    
    if not unprocessed_logs:
        return
    
    # Step 2: Group by device and user
    grouped = group_logs_by_device_and_user(unprocessed_logs)
    
    # Step 3: Load ML models
    model_isolation_forest = load_model('ml/artifacts/isolation_forest.pkl')
    model_lof = load_model('ml/artifacts/local_outlier_factor.pkl')
    
    # Step 4: Process each group
    alerts_generated = []
    
    for device_id, user_data in grouped.items():
        for username, user_logs in user_data.items():
            
            # Extract features
            features = extract_features(user_logs)
            # e.g., {
            #   'login_count': 5,
            #   'unique_ips': 3,
            #   'access_time_variance': 0.85,
            #   'privilege_escalations': 2,
            #   'file_modifications': 127
            # }
            
            # Normalize features
            features_normalized = scaler.transform([features])
            
            # Run anomaly detection
            anomaly_score_if = model_isolation_forest.predict(features_normalized)
            anomaly_score_lof = model_lof.predict(features_normalized)
            
            # Calculate risk score
            risk_score = calculate_risk(anomaly_score_if, anomaly_score_lof)
            
            # Generate alert if risk is high
            if risk_score > RISK_THRESHOLD:
                alert = Alert(
                    device_id=device_id,
                    username=username,
                    alert_type='ANOMALOUS_BEHAVIOR',
                    risk_score=risk_score,
                    description=f"Anomalous login pattern detected",
                    triggered_at=now()
                )
                alerts_generated.append(alert)
                db.add(alert)
    
    # Step 5: Mark logs as processed
    for log in unprocessed_logs:
        log.processed_by_ueba = True
        log.indexed_at = now()
    
    # Step 6: Commit
    db.commit()
    
    logger.info(f"Processed {len(unprocessed_logs)} logs, generated {len(alerts_generated)} alerts")
```

**What the UEBA engine looks for (examples):**

```
1. ANOMALOUS LOGIN PATTERNS
   - Login from unusual IP address
   - Login outside normal working hours
   - Multiple failed attempts followed by success
   - Login on multiple devices simultaneously
   
2. PRIVILEGE ESCALATION
   - Unexpected sudo/admin command execution
   - User gaining permissions they don't normally have
   
3. DATA EXFILTRATION
   - Large file transfers to external IPs
   - Access to files outside normal job function
   - Copy of sensitive files to removable media
   
4. LATERAL MOVEMENT
   - Rapid scanning of multiple IPs
   - Port scanning activity
   - Exploitation attempts
   
5. APPLICATION MISUSE
   - Repeated failed authentication attempts
   - Access to disabled accounts
   - Database queries for sensitive data
```

**Alert record stored in database:**

```sql
INSERT INTO alerts (device_id, username, alert_type, risk_score, description, status, created_at)
VALUES (1, 'admin', 'ANOMALOUS_BEHAVIOR', 87, 'Unusual login from 203.0.113.45 at 03:15 AM', 'ACTIVE', '2025-12-06 14:35:00');

-- Alert record structure:
{
  "id": 999,
  "device_id": 1,
  "device_name": "Device01",
  "username": "admin",
  "alert_type": "ANOMALOUS_BEHAVIOR",
  "risk_score": 87,
  "severity": "HIGH",
  "description": "Unusual login from 203.0.113.45 at 03:15 AM",
  "status": "ACTIVE",
  "created_at": "2025-12-06T14:35:00Z",
  "acknowledged_at": null,
  "assigned_to": null
}
```

---

## Dashboard & Alerts

### Step 8: Real-Time Dashboard Updates

**Architecture:**

```
[Frontend - React/Vue]
        |
        | WebSocket Connection
        | or HTTP Polling (every 5 seconds)
        |
[Backend API]
        |
        +-> GET /api/v1/logs (with device filter)
        +-> GET /api/v1/alerts (with status filter)
        +-> GET /api/v1/devices/Device01/activity
        |
[Database]
        |
        +-> SELECT * FROM logs WHERE device_id = 1 ORDER BY timestamp DESC LIMIT 100
        +-> SELECT * FROM alerts WHERE status = 'ACTIVE' ORDER BY created_at DESC
```

**Dashboard displays in real-time:**

1. **Log Timeline (Event Stream)**
   - Shows last 100 logs from all devices
   - Filters by device, time range, event type
   - Auto-refreshes every 5 seconds
   
2. **Active Alerts (Red/Yellow boxes)**
   - Shows high-risk alerts (risk_score > 75)
   - Grouped by device
   - Clickable to view details
   
3. **Device Status**
   - Shows which devices are actively sending logs
   - Last log received timestamp per device
   - Connection status (online/offline)
   
4. **UEBA Summary**
   - Total events processed
   - Anomalies detected (count)
   - Risk trend (graph)

**Example frontend request/response:**

```http
GET /api/v1/logs?device_id=1&limit=50&offset=0 HTTP/1.1
Authorization: Bearer user_token_xyz

---

HTTP/1.1 200 OK
Content-Type: application/json

{
  "logs": [
    {
      "id": 12345,
      "device_name": "Device01",
      "timestamp": "2025-12-06T14:30:45.123Z",
      "source": "Security",
      "message": "User logon succeeded",
      "event_id": 4624,
      "user": "admin",
      "source_ip": "192.168.1.50"
    },
    ...
  ],
  "total": 4523,
  "timestamp": "2025-12-06T14:35:00Z"
}
```

---

## Troubleshooting & Monitoring

### Step 9: Health Checks & Error Handling

**Monitoring Points:**

| Component | Check | Command | Expected Output |
|-----------|-------|---------|-----------------|
| **Forwarder (Windows)** | Task running | `Get-ScheduledTask -TaskName CyberGardLogForwarder-Device01 \| Select-Object State` | `State: Running` |
| **Forwarder (Linux)** | Service status | `systemctl status cybergard-forwarder` | `active (running)` |
| **Forwarder Logs (Windows)** | Event Viewer | Event Viewer > Applications > CyberGard | No errors |
| **Forwarder Logs (Linux)** | Systemd logs | `journalctl -u cybergard-forwarder -f` | `[INFO] Forwarded N logs` |
| **API Endpoint** | Health check | `curl https://cybergard.company.com/api/v1/health` | `{"status": "ok"}` |
| **Database** | Connection | `curl https://cybergard.company.com/api/v1/db-health` | `{"connected": true}` |
| **Ingestion Rate** | Metrics | `curl https://cybergard.company.com/api/v1/metrics` | `{"logs_per_minute": 150}` |

**Common Issues & Resolutions:**

#### **Issue 1: Forwarder Not Sending Logs**

**Diagnostic steps:**

```powershell
# Windows
# 1. Check if task is running
Get-ScheduledTask -TaskName CyberGardLogForwarder-Device01 | Select-Object State

# 2. Check task history
Get-ScheduledTaskInfo -TaskName CyberGardLogForwarder-Device01

# 3. Manually run to see errors
cd C:\CyberGard\
python remote_log_forwarder.py --url https://... --api-key sk_prod_...

# 4. Check Windows Event Logs manually
Get-WinEvent -LogName Security -MaxEvents 10
```

```bash
# Linux
# 1. Check service status
systemctl status cybergard-forwarder

# 2. Check recent logs
journalctl -u cybergard-forwarder -n 50

# 3. Manually run to see errors
python3 /opt/cybergard/remote_log_forwarder.py --url https://... --api-key sk_prod_...

# 4. Check log files manually
tail -f /var/log/syslog
tail -f /var/log/auth.log
```

**Possible root causes & fixes:**

| Cause | Symptom | Fix |
|-------|---------|-----|
| Network unreachable | Connection timeout | Check firewall rules, DNS resolution |
| Invalid API key | 401 Unauthorized | Verify API key matches backend config |
| TLS certificate error | SSL verification failed | Use `--skip-verify` (testing only) or provide correct CA bundle |
| Disk full | No logs collected | Check disk space: `df -h` |
| Python crash | Task stops after few seconds | Check `forwarder_state.json` syntax |

#### **Issue 2: High API Latency**

**Diagnostic:**

```bash
# Measure API response time
time curl -X POST "https://cybergard.company.com/api/v1/logs/ingest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_prod_..." \
  -d '[{"timestamp":"2025-12-06T14:30:00Z","details":{"test":"ok"}}]'

# Expected: < 200ms
```

**Causes & fixes:**

| Cause | Fix |
|-------|-----|
| Database slow | Add indexes, optimize queries |
| High volume (>1000 logs/sec) | Scale DB, add more API workers |
| Network latency | Check distance to server, use edge cache |
| CPU bottleneck | Increase server resources |

#### **Issue 3: Logs Not Appearing in Dashboard**

**Check database directly:**

```sql
-- Are logs in database?
SELECT COUNT(*) FROM logs WHERE created_at > NOW() - INTERVAL '5 minutes';

-- Are they from the right device?
SELECT device_id, COUNT(*) FROM logs GROUP BY device_id;

-- Are they processed by UEBA?
SELECT COUNT(*) FROM logs WHERE processed_by_ueba = FALSE;
```

**If logs exist but not in UI:**

- Clear browser cache
- Check frontend API token expiration
- Verify database connection in backend
- Check API logs: `tail -f backend/logs/api.log`

---

## Complete End-to-End Timeline Example

Here's what happens when a user logs in to Device01 between 14:30:00 and 14:35:00 UTC:

```
14:30:45.000 UTC
├─ User "admin" successfully logs in on Device01 from IP 192.168.1.50
│  └─ Windows Security Event ID 4624 generated
│
14:30:50.000 UTC (Polling cycle on Device01)
├─ Forwarder reads Windows Event Logs
├─ Detects Event 4624 (not yet processed, RecordNumber > state)
├─ Formats as JSON with timestamp, device name, user
├─ Batches with other recent events
├─ POSTs to https://cybergard.company.com/api/v1/logs/ingest
│  ├─ TLS handshake (1-3 seconds)
│  ├─ API validates Bearer token
│  ├─ Database stores log record
│  └─ Returns 200 OK
├─ Saves new RecordNumber to forwarder_state.json
└─ Sleeps 10 seconds

14:31:00.000 UTC
├─ Log is now in database, processed_by_ueba = FALSE
│
14:35:00.000 UTC (Celery beat triggers UEBA)
├─ UEBA engine queries: SELECT * FROM logs WHERE processed_by_ueba = FALSE
├─ Extracts features for admin user on Device01
├─ Runs ML anomaly detection
├─ Risk score: 45 (normal login, during business hours)
├─ Updates: processed_by_ueba = TRUE, indexed_at = NOW()
└─ No alert generated (risk < threshold)

14:35:05.000 UTC
├─ Frontend dashboard queries GET /api/v1/logs?device_id=1&limit=50
├─ Displays new log in Event Timeline
└─ Shows "Device01: Online, Last event: 14:30:45 UTC"
```

### Now Compare with Suspicious Activity

```
22:15:30.000 UTC (Outside working hours!)
├─ User "admin" logs in on Device01 from IP 203.0.113.45 (unknown IP)
│  └─ Windows Security Event ID 4624 generated
│
22:15:35.000 UTC (Polling cycle on Device01)
├─ Forwarder sends log to API
├─ Database stores: {user: admin, ip: 203.0.113.45, timestamp: 22:15:30, ...}
│
22:35:00.000 UTC (UEBA analysis - 20 minutes later)
├─ UEBA engine processes this log
├─ Feature extraction:
│  ├─ time_of_day: 22:15 (outside 09:00-18:00 business hours) ← ANOMALY
│  ├─ source_ip: 203.0.113.45 (never seen before) ← ANOMALY
│  ├─ login_count_today: 1 (normal)
│  └─ privilege_usage: none (normal)
├─ Anomaly score: HIGH
├─ Risk score: 82 (HIGH)
├─ Generates ALERT:
│  {
│    "alert_type": "SUSPICIOUS_LOGIN",
│    "risk_score": 82,
│    "severity": "HIGH",
│    "description": "Unusual login: admin from 203.0.113.45 at 22:15 UTC (outside business hours)"
│  }
├─ Inserts alert into alerts table
└─ Updates processed_by_ueba = TRUE

22:35:05.000 UTC
├─ Frontend GET /api/v1/alerts?status=ACTIVE
├─ Alert appears in RED box on dashboard
├─ Security admin sees notification: "HIGH RISK: Suspicious login on Device01"
└─ Can click to investigate event details
```

---

## Summary: Data Flow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Device01    │     │  Device02    │     │   Device10   │
│  (Windows)   │     │  (Windows)   │     │   (Linux)    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  Poll every 10s    │  Poll every 10s    │
       │  (Win Event Logs)  │  (Win Event Logs)  │  Poll every 10s
       │                    │                    │  (syslog files)
       │                    │                    │
       └────────────┬───────┴────────────┬───────┘
                    │                    │
                    ▼                    ▼
        ┌───────────────────────────────────────┐
        │   CyberGard Backend API (Port 8000)   │
        │  POST /api/v1/logs/ingest             │
        │  (Authentication: Bearer token)       │
        └───────────────┬───────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │ 1. API Handler (FastAPI)      │
        │ 2. Validate & Parse JSON      │
        │ 3. Database Insert (logs)     │
        │ 4. Return 200 OK              │
        └───────────────┬───────────────┘
                        │
        ┌───────────────┴───────────────┐
        │    PostgreSQL Database        │
        │  - logs table (raw events)    │
        │  - devices table              │
        │  - alerts table               │
        │  - users table                │
        └───────────────┬───────────────┘
                        │
        ┌───────────────┴───────────────┐
        │  Celery Background Task       │
        │  (Every 30 seconds)           │
        │  1. Query unprocessed logs    │
        │  2. Load ML models            │
        │  3. Extract features          │
        │  4. Anomaly detection         │
        │  5. Generate alerts           │
        │  6. Update logs (processed)   │
        └───────────────┬───────────────┘
                        │
        ┌───────────────┴───────────────┐
        │   Frontend Dashboard (React)  │
        │   GET /api/v1/logs            │
        │   GET /api/v1/alerts          │
        │   GET /api/v1/devices         │
        │                               │
        │  Displays:                    │
        │  - Event stream (sorted)      │
        │  - Active alerts (red boxes)  │
        │  - Device status              │
        │  - Risk trends (graphs)       │
        └───────────────────────────────┘
```

---

## Quick Reference: Commands & Logs

### Check Forwarder Status

**Windows:**
```powershell
# Check task
Get-ScheduledTask -TaskName CyberGardLogForwarder-Device01 | Select-Object State

# Check recent logs
Get-EventLog -LogName Application -Source CyberGard -Newest 10

# Manual test
python C:\CyberGard\remote_log_forwarder.py --url https://... --api-key ...
```

**Linux:**
```bash
# Check service
systemctl status cybergard-forwarder

# View logs
journalctl -u cybergard-forwarder -f

# Manual test
python3 /opt/cybergard/remote_log_forwarder.py --url https://... --api-key ...
```

### Check API Health

```bash
# API running?
curl https://cybergard.company.com/api/v1/health

# Database connected?
curl https://cybergard.company.com/api/v1/db-health

# Ingest an event manually
curl -X POST https://cybergard.company.com/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_prod_..." \
  -d '[{"timestamp":"2025-12-06T14:30:00Z","details":{"test":"ok"}}]'
```

### Check Database

```sql
-- Count logs per device (last 1 hour)
SELECT device_name, COUNT(*) as log_count 
FROM logs 
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY device_name;

-- Active alerts
SELECT device_name, username, alert_type, risk_score
FROM alerts
WHERE status = 'ACTIVE'
ORDER BY risk_score DESC;

-- UEBA processing status
SELECT COUNT(*) as unprocessed FROM logs WHERE processed_by_ueba = FALSE;
```

---

## End of Documentation

For more detailed information, see:
- `docs/user_guides/log_ingestion.md` — Basic setup guide
- `docs/user_guides/agents/` — Filebeat/Winlogbeat examples
- `backend/app/api/logs.py` — API endpoint code
- `ml/` — UEBA engine code
- `docs/troubleshooting.md` — More troubleshooting

