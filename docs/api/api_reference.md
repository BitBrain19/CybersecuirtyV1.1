# API Reference

## Overview

The SecurityAI Platform provides a comprehensive REST API that allows programmatic access to all platform capabilities. This document serves as a reference for developers integrating with the platform.

## Authentication

### Obtaining API Credentials

To access the API, you need to obtain API credentials from the SecurityAI Platform administration interface:

1. Log in to the SecurityAI Platform as an administrator
2. Navigate to Configuration > API Management
3. Click "Create API Key"
4. Provide a name and select appropriate permissions
5. Save the generated API key securely

### Authentication Methods

The API supports two authentication methods:

#### Bearer Token Authentication

```
Authorization: Bearer {api_key}
```

Example:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### API Key as Query Parameter

```
?api_key={api_key}
```

Example:
```
https://api.securityai.example.com/v1/alerts?api_key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

> **Note**: Bearer token authentication is recommended for production use. Query parameter authentication should only be used for testing or when bearer token authentication is not possible.

## API Versioning

The API uses URL versioning. The current version is `v1`.

All API endpoints are prefixed with `/v1/`.

Example:
```
https://api.securityai.example.com/v1/alerts
```

## Rate Limiting

The API implements rate limiting to prevent abuse and ensure fair usage:

- Standard API keys: 100 requests per minute
- Premium API keys: 1000 requests per minute

Rate limit information is included in the response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1620000000
```

When rate limits are exceeded, the API returns a `429 Too Many Requests` response.

## Common Parameters

Many API endpoints support the following common parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Maximum number of items to return (default: 100, max: 1000) |
| `offset` | integer | Number of items to skip (for pagination) |
| `sort` | string | Field to sort by (prefix with `-` for descending order) |
| `fields` | string | Comma-separated list of fields to include in the response |
| `filter` | string | Filter expression (see Filtering section) |

## Filtering

Many endpoints support filtering using a simple query language:

```
field:value               # Exact match
field:>value              # Greater than
field:<value              # Less than
field:>=value             # Greater than or equal
field:<=value             # Less than or equal
field:value1,value2       # In list
field:~value              # Contains
field:!value              # Not equal
```

Multiple filters can be combined with `AND` and `OR` operators:

```
severity:high AND status:open
severity:high OR severity:critical
```

Example:
```
/v1/alerts?filter=severity:high AND created_at:>2023-01-01
```

## Response Format

All API responses are in JSON format. Successful responses have the following structure:

```json
{
  "data": [...],
  "meta": {
    "total": 100,
    "limit": 10,
    "offset": 0
  }
}
```

Error responses have the following structure:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid filter expression",
    "details": {...}
  }
}
```

## Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `invalid_request` | The request was malformed or contained invalid parameters |
| 401 | `unauthorized` | Authentication failed or was not provided |
| 403 | `forbidden` | The authenticated user does not have permission to access the resource |
| 404 | `not_found` | The requested resource was not found |
| 409 | `conflict` | The request conflicts with the current state of the resource |
| 422 | `validation_error` | The request contained invalid data |
| 429 | `rate_limit_exceeded` | The rate limit has been exceeded |
| 500 | `internal_error` | An internal server error occurred |

## Core API Endpoints

### Alerts

#### List Alerts

```
GET /v1/alerts
```

Retrieve a list of security alerts.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `status` | string | Filter by status (open, acknowledged, resolved, dismissed) |
| `from_date` | string | Filter by creation date (ISO 8601 format) |
| `to_date` | string | Filter by creation date (ISO 8601 format) |
| `asset_id` | string | Filter by affected asset ID |

**Response:**

```json
{
  "data": [
    {
      "id": "alert-123",
      "title": "Suspicious Login Attempt",
      "description": "Multiple failed login attempts detected",
      "severity": "high",
      "status": "open",
      "created_at": "2023-05-01T12:00:00Z",
      "updated_at": "2023-05-01T12:00:00Z",
      "source": "authentication_logs",
      "asset_id": "asset-456",
      "tags": ["authentication", "brute_force"],
      "assignee": null,
      "risk_score": 85
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### Get Alert

```
GET /v1/alerts/{alert_id}
```

Retrieve a specific alert by ID.

**Response:**

```json
{
  "data": {
    "id": "alert-123",
    "title": "Suspicious Login Attempt",
    "description": "Multiple failed login attempts detected",
    "severity": "high",
    "status": "open",
    "created_at": "2023-05-01T12:00:00Z",
    "updated_at": "2023-05-01T12:00:00Z",
    "source": "authentication_logs",
    "asset_id": "asset-456",
    "tags": ["authentication", "brute_force"],
    "assignee": null,
    "risk_score": 85,
    "events": [
      {
        "id": "event-789",
        "timestamp": "2023-05-01T11:58:00Z",
        "type": "authentication_failure",
        "source_ip": "192.168.1.100",
        "username": "admin"
      },
      {
        "id": "event-790",
        "timestamp": "2023-05-01T11:59:00Z",
        "type": "authentication_failure",
        "source_ip": "192.168.1.100",
        "username": "admin"
      }
    ]
  }
}
```

#### Update Alert

```
PATCH /v1/alerts/{alert_id}
```

Update an alert's status or other properties.

**Request Body:**

```json
{
  "status": "acknowledged",
  "assignee": "user-123",
  "notes": "Investigating this alert"
}
```

**Response:**

```json
{
  "data": {
    "id": "alert-123",
    "status": "acknowledged",
    "assignee": "user-123",
    "notes": "Investigating this alert",
    "updated_at": "2023-05-01T12:30:00Z"
  }
}
```

#### Create Alert (Updated)

```
POST /v1/alerts
```

Create a new alert. The alert payload uses `tags` and `metadata` instead of legacy `event_type` and `details` fields.

**Request Body:**

```json
{
  "title": "Suspicious Login Attempt",
  "description": "Multiple failed login attempts detected",
  "severity": "high",
  "source": "authentication_logs",
  "asset_id": "asset-456",
  "tags": ["authentication", "brute_force"],
  "metadata": {
    "failed_attempts": 12,
    "username": "admin",
    "source_ip": "192.168.1.100"
  },
  "risk_score": 85
}
```

**Response:**

```json
{
  "data": {
    "id": "alert-124",
    "title": "Suspicious Login Attempt",
    "description": "Multiple failed login attempts detected",
    "severity": "high",
    "status": "open",
    "created_at": "2023-05-01T12:10:00Z",
    "updated_at": "2023-05-01T12:10:00Z",
    "source": "authentication_logs",
    "asset_id": "asset-456",
    "tags": ["authentication", "brute_force"],
    "metadata": {
      "failed_attempts": 12,
      "username": "admin",
      "source_ip": "192.168.1.100"
    },
    "risk_score": 85
  }
}
```

> Note: `event_type` and `details` apply to XDR Events. Alerts now use `tags` (categorization) and `metadata` (context object).

### Assets

#### List Assets

```
GET /v1/assets
```

Retrieve a list of assets.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by asset type |
| `criticality` | string | Filter by criticality (low, medium, high, critical) |
| `tag` | string | Filter by tag |

**Response:**

```json
{
  "data": [
    {
      "id": "asset-456",
      "name": "web-server-01",
      "type": "server",
      "criticality": "high",
      "ip_address": "192.168.1.10",
      "operating_system": "Ubuntu 20.04 LTS",
      "owner": "IT Department",
      "tags": ["production", "web"],
      "created_at": "2023-01-15T10:00:00Z",
      "updated_at": "2023-04-20T14:30:00Z",
      "last_seen": "2023-05-01T12:00:00Z",
      "risk_score": 65
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### Get Asset

```
GET /v1/assets/{asset_id}
```

Retrieve a specific asset by ID.

**Response:**

```json
{
  "data": {
    "id": "asset-456",
    "name": "web-server-01",
    "type": "server",
    "criticality": "high",
    "ip_address": "192.168.1.10",
    "operating_system": "Ubuntu 20.04 LTS",
    "owner": "IT Department",
    "tags": ["production", "web"],
    "created_at": "2023-01-15T10:00:00Z",
    "updated_at": "2023-04-20T14:30:00Z",
    "last_seen": "2023-05-01T12:00:00Z",
    "risk_score": 65,
    "vulnerabilities": [
      {
        "id": "vuln-123",
        "cve_id": "CVE-2023-1234",
        "severity": "high",
        "status": "open"
      }
    ],
    "recent_alerts": [
      {
        "id": "alert-123",
        "title": "Suspicious Login Attempt",
        "severity": "high",
        "created_at": "2023-05-01T12:00:00Z"
      }
    ]
  }
}
```

### Vulnerabilities

#### List Vulnerabilities

```
GET /v1/vulnerabilities
```

Retrieve a list of vulnerabilities.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `status` | string | Filter by status (open, in_progress, resolved, accepted_risk) |
| `asset_id` | string | Filter by affected asset ID |

**Response:**

```json
{
  "data": [
    {
      "id": "vuln-123",
      "cve_id": "CVE-2023-1234",
      "title": "OpenSSL Buffer Overflow",
      "description": "A buffer overflow vulnerability in OpenSSL...",
      "severity": "high",
      "cvss_score": 8.5,
      "status": "open",
      "discovered_at": "2023-04-15T09:30:00Z",
      "asset_id": "asset-456",
      "remediation": "Update OpenSSL to version 3.0.8 or later"
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

## ML API Endpoints

### Threat Detection

#### Predict Threat

```
POST /v1/ml/predict
```

Analyze data for potential threats using machine learning models.

**Request Body:**

```json
{
  "data": {
    "source_ip": "192.168.1.100",
    "destination_ip": "203.0.113.10",
    "destination_port": 445,
    "protocol": "tcp",
    "bytes_sent": 1024,
    "bytes_received": 8192,
    "duration": 5.2,
    "timestamp": "2023-05-01T12:00:00Z"
  },
  "model_id": "threat-detection-v2"
}
```

**Response:**

```json
{
  "data": {
    "prediction": {
      "is_threat": true,
      "confidence": 0.92,
      "threat_type": "lateral_movement",
      "explanation": {
        "feature_importance": {
          "destination_port": 0.45,
          "bytes_received": 0.30,
          "protocol": 0.15,
          "duration": 0.10
        }
      }
    },
    "model_id": "threat-detection-v2",
    "model_version": "2.3.0",
    "processing_time": 0.023
  }
}
```

#### Batch Prediction

```
POST /v1/ml/batch_predict
```

Analyze multiple data points for potential threats.

**Request Body:**

```json
{
  "data": [
    {
      "source_ip": "192.168.1.100",
      "destination_ip": "203.0.113.10",
      "destination_port": 445,
      "protocol": "tcp",
      "bytes_sent": 1024,
      "bytes_received": 8192,
      "duration": 5.2,
      "timestamp": "2023-05-01T12:00:00Z"
    },
    {
      "source_ip": "192.168.1.101",
      "destination_ip": "203.0.113.11",
      "destination_port": 80,
      "protocol": "tcp",
      "bytes_sent": 512,
      "bytes_received": 2048,
      "duration": 1.5,
      "timestamp": "2023-05-01T12:01:00Z"
    }
  ],
  "model_id": "threat-detection-v2"
}
```

**Response:**

```json
{
  "data": {
    "predictions": [
      {
        "is_threat": true,
        "confidence": 0.92,
        "threat_type": "lateral_movement"
      },
      {
        "is_threat": false,
        "confidence": 0.87,
        "threat_type": null
      }
    ],
    "model_id": "threat-detection-v2",
    "model_version": "2.3.0",
    "processing_time": 0.045
  }
}
```

### Model Management

#### List Models

```
GET /v1/ml/models
```

Retrieve a list of available machine learning models.

**Response:**

```json
{
  "data": [
    {
      "id": "threat-detection-v2",
      "name": "Threat Detection Model",
      "version": "2.3.0",
      "type": "classification",
      "created_at": "2023-03-15T10:00:00Z",
      "last_updated": "2023-04-10T14:30:00Z",
      "status": "active",
      "metrics": {
        "accuracy": 0.95,
        "precision": 0.92,
        "recall": 0.94,
        "f1_score": 0.93
      }
    },
    {
      "id": "vuln-assessment-v1",
      "name": "Vulnerability Assessment Model",
      "version": "1.5.2",
      "type": "regression",
      "created_at": "2023-02-20T09:00:00Z",
      "last_updated": "2023-04-05T11:15:00Z",
      "status": "active",
      "metrics": {
        "rmse": 0.12,
        "mae": 0.09,
        "r2": 0.87
      }
    }
  ],
  "meta": {
    "total": 2,
    "limit": 10,
    "offset": 0
  }
}
```

#### Train Model

```
POST /v1/ml/train
```

Train a new machine learning model or retrain an existing one.

**Request Body:**

```json
{
  "model_type": "threat_detection",
  "training_data_source": "historical_alerts",
  "parameters": {
    "algorithm": "random_forest",
    "features": ["source_ip", "destination_ip", "destination_port", "protocol", "bytes_sent", "bytes_received", "duration"],
    "target": "is_threat",
    "test_size": 0.2,
    "random_state": 42
  },
  "name": "Threat Detection Model v3",
  "description": "Improved threat detection model with additional features"
}
```

**Response:**

```json
{
  "data": {
    "job_id": "train-job-123",
    "status": "submitted",
    "estimated_completion": "2023-05-01T14:00:00Z"
  }
}
```

#### Get Training Job Status

```
GET /v1/ml/train/{job_id}
```

Check the status of a model training job.

**Response:**

```json
{
  "data": {
    "job_id": "train-job-123",
    "status": "completed",
    "started_at": "2023-05-01T12:30:00Z",
    "completed_at": "2023-05-01T13:45:00Z",
    "model": {
      "id": "threat-detection-v3",
      "name": "Threat Detection Model v3",
      "version": "1.0.0",
      "metrics": {
        "accuracy": 0.96,
        "precision": 0.94,
        "recall": 0.95,
        "f1_score": 0.94
      }
    }
  }
}
```

## UEBA API Endpoints

### Entity Profiles

#### Get Entity Profile

```
GET /v1/ueba/profiles/{entity_id}
```

Retrieve the behavioral profile for a specific entity.

**Response:**

```json
{
  "data": {
    "entity_id": "user-789",
    "entity_type": "user",
    "name": "john.doe",
    "risk_score": 42,
    "last_updated": "2023-05-01T12:00:00Z",
    "baseline_established": true,
    "baseline_confidence": "high",
    "behavioral_patterns": {
      "login_times": {
        "typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        "typical_days": [1, 2, 3, 4, 5],
        "unusual_login_count": 2
      },
      "access_patterns": {
        "commonly_accessed_resources": ["email", "crm", "file_server"],
        "unusual_resource_access_count": 1
      },
      "network_patterns": {
        "typical_source_ips": ["10.0.0.15", "192.168.1.100"],
        "unusual_source_ip_count": 1
      }
    },
    "recent_anomalies": [
      {
        "id": "anomaly-123",
        "type": "unusual_login_time",
        "severity": "medium",
        "detected_at": "2023-04-30T03:15:00Z",
        "description": "Login outside of typical hours"
      }
    ]
  }
}
```

#### List Anomalies

```
GET /v1/ueba/anomalies
```

Retrieve a list of detected behavioral anomalies.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | string | Filter by entity ID |
| `entity_type` | string | Filter by entity type (user, device, application) |
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `from_date` | string | Filter by detection date (ISO 8601 format) |
| `to_date` | string | Filter by detection date (ISO 8601 format) |

**Response:**

```json
{
  "data": [
    {
      "id": "anomaly-123",
      "entity_id": "user-789",
      "entity_type": "user",
      "entity_name": "john.doe",
      "type": "unusual_login_time",
      "severity": "medium",
      "confidence": 0.85,
      "detected_at": "2023-04-30T03:15:00Z",
      "description": "Login outside of typical hours",
      "details": {
        "login_time": "2023-04-30T03:15:00Z",
        "typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        "source_ip": "203.0.113.42",
        "location": "New York, USA"
      },
      "status": "open"
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

## SOAR API Endpoints

### Workflows

#### List Workflows

```
GET /v1/soar/workflows
```

Retrieve a list of available SOAR workflows.

**Response:**

```json
{
  "data": [
    {
      "id": "workflow-123",
      "name": "Phishing Response",
      "description": "Automated response to phishing attacks",
      "trigger_type": "alert",
      "trigger_conditions": {
        "alert_type": "phishing"
      },
      "enabled": true,
      "created_at": "2023-03-10T09:00:00Z",
      "updated_at": "2023-04-15T14:30:00Z",
      "execution_count": 42,
      "average_execution_time": 45.2
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### Execute Workflow

```
POST /v1/soar/workflows/{workflow_id}/execute
```

Manually execute a SOAR workflow.

**Request Body:**

```json
{
  "context": {
    "alert_id": "alert-456",
    "parameters": {
      "email_address": "suspicious@example.com",
      "attachment_hash": "a1b2c3d4e5f6..."
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "execution_id": "exec-789",
    "status": "in_progress",
    "started_at": "2023-05-01T12:30:00Z",
    "estimated_completion": "2023-05-01T12:32:00Z"
  }
}
```

#### Get Workflow Execution Status

```
GET /v1/soar/executions/{execution_id}
```

Check the status of a workflow execution.

**Response:**

```json
{
  "data": {
    "execution_id": "exec-789",
    "workflow_id": "workflow-123",
    "status": "completed",
    "started_at": "2023-05-01T12:30:00Z",
    "completed_at": "2023-05-01T12:31:45Z",
    "steps": [
      {
        "id": "step-1",
        "name": "Check Email Reputation",
        "status": "completed",
        "started_at": "2023-05-01T12:30:05Z",
        "completed_at": "2023-05-01T12:30:15Z",
        "output": {
          "reputation_score": 15,
          "is_malicious": true
        }
      },
      {
        "id": "step-2",
        "name": "Block Email Address",
        "status": "completed",
        "started_at": "2023-05-01T12:30:20Z",
        "completed_at": "2023-05-01T12:30:45Z",
        "output": {
          "success": true,
          "message": "Email address blocked in email gateway"
        }
      },
      {
        "id": "step-3",
        "name": "Create Incident Ticket",
        "status": "completed",
        "started_at": "2023-05-01T12:30:50Z",
        "completed_at": "2023-05-01T12:31:30Z",
        "output": {
          "ticket_id": "INC-12345",
          "ticket_url": "https://helpdesk.example.com/tickets/INC-12345"
        }
      }
    ],
    "result": {
      "success": true,
      "actions_taken": ["email_blocked", "ticket_created"],
      "ticket_id": "INC-12345"
    }
  }
}
```

## EDR API Endpoints

### Agents

#### List Agents

```
GET /v1/edr/agents
```

Retrieve a list of EDR agents.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status (online, offline, degraded) |
| `os_type` | string | Filter by operating system type (windows, linux, macos) |
| `hostname` | string | Filter by hostname (partial match) |

**Response:**

```json
{
  "data": [
    {
      "id": "agent-123",
      "hostname": "workstation-01",
      "ip_address": "192.168.1.50",
      "os_type": "windows",
      "os_version": "Windows 10 Pro 21H2",
      "agent_version": "2.3.4",
      "status": "online",
      "last_seen": "2023-05-01T12:25:00Z",
      "installed_at": "2023-01-15T10:00:00Z",
      "updated_at": "2023-04-10T09:15:00Z",
      "policy_id": "policy-456",
      "tags": ["finance", "windows"]
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### Isolate Endpoint

```
POST /v1/edr/agents/{agent_id}/isolate
```

Isolate an endpoint from the network.

**Request Body:**

```json
{
  "reason": "Suspected malware infection",
  "isolation_level": "full",
  "duration_hours": 4
}
```

**Response:**

```json
{
  "data": {
    "agent_id": "agent-123",
    "hostname": "workstation-01",
    "isolation_status": "isolating",
    "requested_at": "2023-05-01T12:30:00Z",
    "isolation_level": "full",
    "expiration": "2023-05-01T16:30:00Z",
    "reason": "Suspected malware infection"
  }
}
```

#### Release Isolation

```
POST /v1/edr/agents/{agent_id}/release
```

Release an endpoint from isolation.

**Request Body:**

```json
{
  "reason": "Threat remediated"
}
```

**Response:**

```json
{
  "data": {
    "agent_id": "agent-123",
    "hostname": "workstation-01",
    "isolation_status": "releasing",
    "requested_at": "2023-05-01T14:30:00Z",
    "reason": "Threat remediated"
  }
}
```

## XDR API Endpoints

### Events

#### List Security Events

```
GET /v1/xdr/events
```

Retrieve a list of security events across different sources.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `source` | string | Filter by source (endpoint, network, cloud, email) |
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `from_date` | string | Filter by timestamp (ISO 8601 format) |
| `to_date` | string | Filter by timestamp (ISO 8601 format) |
| `entity_id` | string | Filter by affected entity ID |

**Response:**

```json
{
  "data": [
    {
      "id": "event-123",
      "source": "endpoint",
      "source_name": "workstation-01",
      "event_type": "process_creation",
      "severity": "medium",
      "timestamp": "2023-05-01T12:15:30Z",
      "details": {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ...",
        "parent_process": "cmd.exe",
        "user": "DOMAIN\\user"
      },
      "related_entities": [
        {
          "id": "agent-123",
          "type": "endpoint"
        },
        {
          "id": "user-456",
          "type": "user"
        }
      ]
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### List Security Alerts

```
GET /v1/xdr/alerts
```

Retrieve a list of security alerts generated by XDR correlation.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `status` | string | Filter by status (open, acknowledged, resolved, dismissed) |
| `from_date` | string | Filter by creation date (ISO 8601 format) |
| `to_date` | string | Filter by creation date (ISO 8601 format) |

**Response:**

```json
{
  "data": [
    {
      "id": "xdr-alert-123",
      "title": "Potential Data Exfiltration",
      "description": "Suspicious data transfer detected from sensitive system",
      "severity": "high",
      "status": "open",
      "created_at": "2023-05-01T12:30:00Z",
      "updated_at": "2023-05-01T12:30:00Z",
      "detection_rule": "data_exfiltration_detection",
      "tactics": ["Exfiltration"],
      "techniques": ["T1048"],
      "confidence": 85,
      "related_events": [
        "event-123",
        "event-124",
        "event-125"
      ],
      "affected_entities": [
        {
          "id": "agent-123",
          "type": "endpoint",
          "name": "workstation-01"
        },
        {
          "id": "user-456",
          "type": "user",
          "name": "john.doe"
        }
      ]
    }
  ],
  "meta": {
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

#### Correlate Events

```
POST /v1/xdr/correlate
```

Correlate a set of events to identify potential security incidents.

**Request Body:**

```json
{
  "event_ids": ["event-123", "event-124", "event-125"],
  "time_window": "1h",
  "context": {
    "entity_id": "agent-123",
    "entity_type": "endpoint"
  }
}
```

**Response:**

```json
{
  "data": {
    "correlation_id": "corr-789",
    "detected_patterns": [
      {
        "name": "Data Exfiltration Pattern",
        "confidence": 85,
        "matched_events": ["event-123", "event-125"],
        "description": "Pattern of sensitive file access followed by unusual network connection"
      }
    ],
    "alert_generated": true,
    "alert_id": "xdr-alert-123"
  }
}
```

## Webhooks

### Webhook Configuration

The SecurityAI Platform can send webhook notifications for various events. To configure webhooks:

1. Navigate to Configuration > Integrations > Webhooks in the web interface
2. Click "Add Webhook"
3. Provide the webhook URL and select event types
4. Configure optional authentication for the webhook

### Webhook Payload Format

All webhook payloads follow this general structure:

```json
{
  "event_type": "alert.created",
  "timestamp": "2023-05-01T12:30:00Z",
  "data": {
    // Event-specific data
  },
  "webhook_id": "webhook-123"
}
```

### Webhook Event Types

| Event Type | Description | Payload Example |
|------------|-------------|----------------|
| `alert.created` | New alert created | Alert object |
| `alert.updated` | Alert status changed | Alert object with changes |
| `incident.created` | New incident created | Incident object |
| `incident.updated` | Incident status changed | Incident object with changes |
| `vulnerability.detected` | New vulnerability detected | Vulnerability object |
| `anomaly.detected` | New behavioral anomaly detected | Anomaly object |
| `workflow.executed` | SOAR workflow executed | Workflow execution details |

## API Changelog

### v1.2.0 (2023-04-15)

- Added XDR correlation endpoints
- Enhanced UEBA profile information
- Added support for custom ML model training
- Improved filtering capabilities across all endpoints

### v1.1.0 (2023-02-10)

- Added SOAR workflow execution endpoints
- Added EDR agent management endpoints
- Enhanced asset information with vulnerability data
- Added support for batch predictions

### v1.0.0 (2023-01-01)

- Initial API release
- Core functionality for alerts, assets, and vulnerabilities
- Basic ML prediction capabilities
- Authentication and user management