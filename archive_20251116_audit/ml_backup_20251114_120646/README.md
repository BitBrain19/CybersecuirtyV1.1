# SecurityAI ML Service

This service provides machine learning capabilities for the SecurityAI platform, including threat detection, vulnerability assessment, and advanced security analytics.

## Features

- **Threat Detection**: Identifies potential security threats using machine learning models
- **Vulnerability Assessment**: Evaluates system vulnerabilities and provides risk scores
- **Model Training**: API endpoints for training and retraining models with new data
- **Model Evaluation**: Tools to assess model performance with various metrics
- **Batch Prediction**: Support for processing multiple prediction requests efficiently
- **User and Entity Behavior Analytics (UEBA)**: Establishes behavioral baselines and detects anomalies
- **Security Orchestration, Automation and Response (SOAR)**: Automates incident response with customizable workflows
- **Endpoint Detection and Response (EDR)**: Monitors endpoints for suspicious activities and provides response capabilities
- **Extended Detection and Response (XDR)**: Integrates security data across multiple sources for unified threat detection

## API Endpoints

### Health Check

```
GET /health
```

Returns the health status of the service.

### Security Analytics

```
GET /analytics/summary
```

Returns a summary of security analytics across all components.

```
GET /analytics/ueba
```

Returns User and Entity Behavior Analytics data.

```
GET /analytics/edr
```

Returns Endpoint Detection and Response analytics.

```
GET /analytics/xdr
```

Returns Extended Detection and Response analytics.

### Prediction

```
POST /predict
```

Makes a prediction using the specified model.

**Request Body:**
```json
{
  "features": { "feature1": "value1", "feature2": "value2" },
  "model_name": "threat_detection",
  "model_version": "latest"
}
```

**Response:**
```json
{
  "prediction": "malicious",
  "probability": 0.85,
  "model_info": {
    "name": "threat_detection",
    "version": "1.1.0",
    "timestamp": "2023-06-15T10:30:00Z"
  }
}
```

### Batch Prediction

```
POST /batch-predict
```

Makes predictions for multiple inputs.

**Request Body:**
```json
{
  "items": [
    {
      "features": { "feature1": "value1" },
      "model_name": "threat_detection"
    },
    {
      "features": { "feature1": "value2" },
      "model_name": "vulnerability_assessment"
    }
  ]
}
```

**Response:**
```json
{
  "results": [
    {
      "prediction": "malicious",
      "probability": 0.85,
      "model_info": { ... }
    },
    {
      "prediction": "high",
      "score": 7.5,
      "severity": "high",
      "model_info": { ... }
    }
  ],
  "failed_indices": [],
  "errors": []
}
```

### Training

```
POST /train
```

Trains or retrains a model with new data.

**Request Body:**
```json
{
  "model_name": "threat_detection",
  "features": [
    { "feature1": "value1", "feature2": "value2" },
    { "feature1": "value3", "feature2": "value4" }
  ],
  "labels": ["malicious", "benign"],
  "hyperparameters": {
    "n_estimators": 100,
    "max_depth": 10
  },
  "run_name": "training_run_1"
}
```

**Response:**
```json
{
  "model_name": "threat_detection",
  "run_id": "abc123",
  "metrics": {},
  "status": "success",
  "message": "Model threat_detection trained successfully"
}
```

### Evaluation

```
POST /evaluate
```

Evaluates a model's performance on test data.

**Request Body:**
```json
{
  "model_name": "threat_detection",
  "features": [
    { "feature1": "value1", "feature2": "value2" },
    { "feature1": "value3", "feature2": "value4" }
  ],
  "labels": ["malicious", "benign"],
  "model_version": "latest"
}
```

**Response:**
```json
{
  "model_name": "threat_detection",
  "metrics": {
    "accuracy": 0.95,
    "precision": 0.92,
    "recall": 0.94,
    "f1_score": 0.93
  },
  "confusion_matrix": [[45, 5], [3, 47]],
  "status": "success"
}
```

### List Models

```
GET /models
```

Lists available models.

**Response:**
```json
{
  "models": [
    {
      "name": "threat_detection",
      "versions": ["1.0.0", "1.1.0"],
      "latest": "1.1.0",
      "description": "Detects malicious activities and potential threats"
    },
    {
      "name": "vulnerability_assessment",
      "versions": ["0.9.0"],
      "latest": "0.9.0",
      "description": "Assesses vulnerabilities in systems and applications"
    }
  ]
}
```

### SOAR Workflows

```
GET /soar/workflows
```

Lists available SOAR workflows.

**Response:**
```json
{
  "workflows": [
    {
      "id": "wf-123",
      "name": "Malware Response",
      "description": "Automated response to malware detections",
      "trigger_type": "alert",
      "status": "active"
    },
    {
      "id": "wf-456",
      "name": "Phishing Investigation",
      "description": "Workflow for investigating phishing attempts",
      "trigger_type": "email",
      "status": "active"
    }
  ]
}
```

```
POST /soar/workflows/{workflow_id}/execute
```

Executes a specific workflow.

**Request Body:**
```json
{
  "context": {
    "alert_id": "alert-123",
    "severity": "high",
    "source": "edr",
    "additional_data": {}
  }
}
```

**Response:**
```json
{
  "execution_id": "exec-789",
  "workflow_id": "wf-123",
  "status": "running",
  "start_time": "2023-08-15T14:30:00Z"
}
```

### EDR Endpoints

```
GET /edr/agents
```

Lists all registered EDR agents.

**Response:**
```json
{
  "agents": [
    {
      "id": "agent-123",
      "hostname": "workstation-1",
      "ip_address": "192.168.1.100",
      "status": "active",
      "last_seen": "2023-08-15T14:30:00Z"
    },
    {
      "id": "agent-456",
      "hostname": "server-db-1",
      "ip_address": "192.168.1.101",
      "status": "active",
      "last_seen": "2023-08-15T14:35:00Z"
    }
  ]
}
```

```
POST /edr/agents/{agent_id}/isolate
```

Isolates an endpoint from the network.

**Request Body:**
```json
{
  "isolation_level": "full",
  "reason": "Suspected malware infection"
}
```

**Response:**
```json
{
  "agent_id": "agent-123",
  "status": "isolated",
  "isolation_level": "full",
  "timestamp": "2023-08-15T14:40:00Z"
}
```

### UEBA Endpoints

```
GET /ueba/profiles/{entity_id}
```

Returns the behavior profile for a specific entity.

**Response:**
```json
{
  "entity_id": "user123",
  "entity_type": "user",
  "risk_score": 45,
  "baseline_established": true,
  "last_updated": "2023-08-15T10:30:00Z",
  "behavior_patterns": [
    {
      "category": "login",
      "normal_hours": ["08:00-18:00"],
      "normal_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      "normal_locations": ["US-East", "US-West"]
    },
    {
      "category": "file_access",
      "normal_patterns": ["HR Documents", "Team Shared"],
      "frequency": "medium"
    }
  ]
}
```

```
GET /ueba/anomalies
```

Lists recent behavioral anomalies.

**Response:**
```json
{
  "anomalies": [
    {
      "id": "anomaly-123",
      "entity_id": "user123",
      "entity_type": "user",
      "category": "login",
      "severity": "high",
      "description": "Login from unusual location",
      "timestamp": "2023-08-15T03:45:00Z",
      "details": {
        "location": "RU-Moscow",
        "device": "Unknown",
        "ip_address": "203.0.113.1"
      }
    },
    {
      "id": "anomaly-456",
      "entity_id": "server-db-1",
      "entity_type": "system",
      "category": "process",
      "severity": "medium",
      "description": "Unusual process execution",
      "timestamp": "2023-08-15T12:30:00Z",
      "details": {
        "process_name": "svchost.exe",
        "command_line": "svchost.exe -k netsvcs -p -s BITS",
        "parent_process": "explorer.exe"
      }
    }
  ]
}
```

## Development

### Running Locally

```bash
uvicorn app.main:app --reload --port 8001
```

### Docker

```bash
docker build -t securityai-ml -f Dockerfile.dev .
docker run -p 8001:8001 securityai-ml
```

### Environment Variables

- `MLFLOW_TRACKING_URI`: URI for MLflow tracking server (default: http://mlflow:5000)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `ENABLE_UEBA`: Enable User and Entity Behavior Analytics (default: true)
- `ENABLE_SOAR`: Enable Security Orchestration, Automation and Response (default: true)
- `ENABLE_EDR`: Enable Endpoint Detection and Response (default: true)
- `ENABLE_XDR`: Enable Extended Detection and Response (default: true)
- `SPLUNK_URL`: Splunk SIEM URL for XDR integration
- `CROWDSTRIKE_URL`: CrowdStrike Falcon URL for XDR integration

## XDR Integration

The Extended Detection and Response (XDR) platform integrates data from multiple security components to provide unified threat detection and response capabilities.

### XDR Endpoints

```
GET /xdr/events
```

Returns recent security events from all integrated sources.

**Response:**
```json
{
  "events": [
    {
      "id": "evt-123",
      "source_type": "edr",
      "source_name": "CrowdStrike Falcon",
      "event_type": "process_create",
      "severity": "medium",
      "hostname": "workstation-1",
      "timestamp": "2023-08-15T14:30:00Z",
      "data": {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass..."
      }
    },
    {
      "id": "evt-456",
      "source_type": "siem",
      "source_name": "Splunk",
      "event_type": "network_connection",
      "severity": "low",
      "hostname": "server-db-1",
      "timestamp": "2023-08-15T14:35:00Z",
      "data": {
        "destination_address": "203.0.113.1",
        "destination_port": 443,
        "protocol": "TCP"
      }
    }
  ]
}
```

```
GET /xdr/alerts
```

Returns security alerts from all integrated sources.

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert-123",
      "title": "Suspicious PowerShell Execution",
      "description": "PowerShell execution with encoded command detected",
      "severity": "high",
      "source_type": "edr",
      "source_name": "CrowdStrike Falcon",
      "hostname": "workstation-1",
      "timestamp": "2023-08-15T14:32:00Z",
      "status": "new",
      "mitre_techniques": ["T1059.001"],
      "data": {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass..."
      }
    }
  ]
}
```

```
POST /xdr/correlate
```

Correlates events and alerts to identify potential threats.

**Request Body:**
```json
{
  "event_ids": ["evt-123", "evt-456"],
  "alert_ids": ["alert-123"],
  "time_window": 3600
}
```

**Response:**
```json
{
  "correlation_id": "corr-789",
  "threat_score": 85,
  "related_entities": ["workstation-1", "user123"],
  "summary": "High confidence correlation between suspicious PowerShell execution and unusual network connection",
  "recommendation": "Isolate workstation-1 and investigate"
}
```