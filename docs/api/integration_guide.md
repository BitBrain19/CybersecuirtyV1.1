# Integration Guide

## Overview

This guide provides detailed information for integrating external systems with the SecurityAI Platform. It covers API usage, data exchange formats, authentication methods, and best practices for building robust integrations.

## Integration Architecture

The SecurityAI Platform offers multiple integration points:

1. **REST API**: Primary method for programmatic interaction with the platform
2. **Webhooks**: Event-driven notifications from the platform to external systems
3. **Data Ingestion**: Methods for importing security data into the platform
4. **Data Export**: Methods for extracting data from the platform
5. **Custom Plugins**: Framework for extending platform functionality

## Authentication

### API Key Authentication

The most common authentication method for integrations is API key authentication:

1. Generate an API key in the SecurityAI Platform:
   - Navigate to Administration > API Management
   - Click "Create API Key"
   - Provide a name and select appropriate permissions
   - Save the generated API key securely

2. Use the API key in requests:
   - As a bearer token in the Authorization header:
     ```
     Authorization: Bearer {api_key}
     ```
   - As a query parameter (not recommended for production):
     ```
     ?api_key={api_key}
     ```

### OAuth 2.0 Authentication

For more advanced scenarios, the platform supports OAuth 2.0:

1. Register an OAuth client:
   - Navigate to Administration > API Management > OAuth Clients
   - Click "Register Client"
   - Provide client name, redirect URIs, and select scopes
   - Save the client ID and secret

2. Implement the OAuth 2.0 flow:
   - Authorization Code Flow (for web applications)
   - Client Credentials Flow (for server-to-server integrations)
   - Device Code Flow (for devices without browsers)

3. Example OAuth 2.0 Client Credentials Flow:

```python
import requests

# Request an access token
token_url = "https://api.securityai.example.com/oauth/token"
data = {
    "grant_type": "client_credentials",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "scope": "alerts:read assets:read"
}

response = requests.post(token_url, data=data)
token = response.json()["access_token"]

# Use the token in API requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("https://api.securityai.example.com/v1/alerts", headers=headers)
```

## Common Integration Scenarios

### SIEM Integration

Integrating the SecurityAI Platform with a SIEM system typically involves:

1. **Alert forwarding**: Send SecurityAI alerts to the SIEM
   - Configure a webhook in SecurityAI to send alerts to the SIEM's API
   - Map SecurityAI alert fields to SIEM fields

2. **Data enrichment**: Enrich SIEM alerts with SecurityAI data
   - Create an integration in the SIEM to query SecurityAI's API
   - Use entity information from SIEM alerts to query SecurityAI

3. **Bidirectional sync**: Keep alert status in sync between systems
   - Configure webhooks in both systems
   - Implement status mapping logic

#### Example: Splunk Integration

1. Create a Splunk HTTP Event Collector (HEC) token
2. Configure a webhook in SecurityAI:
   - Endpoint: `https://splunk-instance:8088/services/collector`
   - Authentication: HEC token in header `Authorization: Splunk {token}`
   - Event mapping:

```json
{
  "event": {
    "source": "securityai",
    "sourcetype": "securityai:alert",
    "index": "security",
    "data": {
      "alert_id": "{{alert.id}}",
      "title": "{{alert.title}}",
      "description": "{{alert.description}}",
      "severity": "{{alert.severity}}",
      "status": "{{alert.status}}",
      "created_at": "{{alert.created_at}}",
      "source": "{{alert.source}}",
      "asset_id": "{{alert.asset_id}}",
      "tags": "{{alert.tags}}",
      "risk_score": "{{alert.risk_score}}"
    }
  }
}
```

### Ticketing System Integration

Integrating with ticketing systems like Jira, ServiceNow, or Zendesk:

1. **Alert to ticket**: Create tickets from SecurityAI alerts
   - Configure a webhook in SecurityAI to create tickets
   - Map alert fields to ticket fields

2. **Ticket to alert updates**: Update SecurityAI alerts based on ticket changes
   - Configure a webhook in the ticketing system
   - Update alert status via SecurityAI API

#### Example: Jira Integration

1. Create a Jira API token
2. Configure a webhook in SecurityAI:
   - Endpoint: `https://your-jira-instance.atlassian.net/rest/api/2/issue`
   - Authentication: Basic auth with email and API token
   - Event mapping:

```json
{
  "fields": {
    "project": {
      "key": "SEC"
    },
    "summary": "{{alert.title}}",
    "description": "{{alert.description}}\n\nAlert ID: {{alert.id}}\nSeverity: {{alert.severity}}\nDetected at: {{alert.created_at}}\nAffected Asset: {{alert.asset_id}}",
    "issuetype": {
      "name": "Security Incident"
    },
    "priority": {
      "name": "{% if alert.severity == 'critical' %}Highest{% elif alert.severity == 'high' %}High{% elif alert.severity == 'medium' %}Medium{% else %}Low{% endif %}"
    },
    "labels": ["securityai", "{{alert.source}}"],
    "customfield_10001": "{{alert.id}}"
  }
}
```

3. Configure a webhook in Jira to update SecurityAI alerts:
   - Trigger on issue status changes
   - Send updates to SecurityAI API endpoint

### SOAR Integration

Integrating with SOAR platforms for automated response:

1. **Alert ingestion**: Send SecurityAI alerts to SOAR
   - Configure a webhook in SecurityAI
   - Map alert fields to SOAR incident fields

2. **Automated actions**: Trigger SecurityAI actions from SOAR
   - Use SecurityAI API to execute actions
   - Implement custom playbooks in SOAR

3. **Enrichment**: Use SecurityAI data to enrich SOAR incidents
   - Query SecurityAI API for additional context
   - Incorporate ML insights into SOAR decision-making

#### Example: Palo Alto XSOAR Integration

1. Create an incoming webhook in XSOAR
2. Configure a webhook in SecurityAI:
   - Endpoint: XSOAR webhook URL
   - Event mapping to XSOAR incident format

3. Create XSOAR playbooks that use SecurityAI API:

```python
import requests

def get_asset_details(asset_id, api_key):
    url = f"https://api.securityai.example.com/v1/assets/{asset_id}"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(url, headers=headers)
    return response.json()["data"]

def isolate_endpoint(agent_id, api_key, reason):
    url = f"https://api.securityai.example.com/v1/edr/agents/{agent_id}/isolate"
    headers = {"Authorization": f"Bearer {api_key}"}
    data = {"reason": reason, "isolation_level": "full"}
    response = requests.post(url, headers=headers, json=data)
    return response.json()["data"]
```

## Data Exchange Formats

### Alert Format

The standard format for security alerts:

```json
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
  "risk_score": 85,
  "events": [
    {
      "id": "event-789",
      "timestamp": "2023-05-01T11:58:00Z",
      "type": "authentication_failure",
      "source_ip": "192.168.1.100",
      "username": "admin"
    }
  ]
}
```

### Asset Format

The standard format for assets:

```json
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
```

### Create Alert via API (Updated)

Create alerts programmatically using `tags` and `metadata`:

```python
import requests

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

payload = {
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

resp = requests.post(f"{BASE_URL}/alerts", headers=headers, json=payload)
resp.raise_for_status()
print("Created alert:", resp.json()["data"]["id"]) 
```

> Note: `event_type` and `details` are used for XDR Events. Alerts use `tags` for categorization and `metadata` for structured context.

### Vulnerability Format

The standard format for vulnerabilities:

```json
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
```

### Event Format

The standard format for security events:

```json
{
  "id": "event-789",
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
```

## Webhook Integration

### Configuring Webhooks

1. Navigate to Administration > Integrations > Webhooks
2. Click "Add Webhook"
3. Configure the following settings:
   - Name: A descriptive name for the webhook
   - URL: The endpoint that will receive webhook events
   - Secret: A shared secret for signature verification
   - Event types: Select which events trigger the webhook
   - Format: JSON or XML
   - Custom headers (optional)
   - Retry policy (optional)
4. Click "Test Webhook" to verify the configuration
5. Click "Save Webhook"

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

### Webhook Signature Verification

To verify webhook authenticity, each request includes a signature header:

```
X-SecurityAI-Signature: sha256=5257a869e7bdf3ecf7f1b4f6d7e5c8d4e3b2a1c0...
```

To verify the signature:

```python
import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        key=secret.encode(),
        msg=payload.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Extract the signature value after "sha256="
    received_signature = signature.split("sha256=")[1]
    
    return hmac.compare_digest(expected_signature, received_signature)
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

## Data Ingestion

### Log Ingestion

The platform supports multiple methods for log ingestion:

1. **Syslog**: Send logs via syslog protocol
   - Configure your devices to send syslog to the platform
   - Supported formats: RFC3164, RFC5424
   - Supported transports: UDP, TCP, TLS

2. **Log Files**: Upload log files directly
   - Use the API to upload log files
   - Supported formats: CSV, JSON, XML, plain text

3. **Log Collectors**: Deploy collectors in your environment
   - Download and install collectors from the platform
   - Configure collectors to gather logs from sources
   - Collectors forward logs to the platform

#### Example: Syslog Configuration

```python
import socket
import time

def send_syslog(message, host="securityai.example.com", port=514):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timestamp = time.strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    syslog_message = f"<134>{timestamp} {hostname} {message}"
    sock.sendto(syslog_message.encode(), (host, port))
    sock.close()

send_syslog("CEF:0|SecurityAI|Logger|1.0|100|Login Failure|High|src=192.168.1.100 duser=admin")
```

### Threat Intelligence Ingestion

Import threat intelligence data into the platform:

1. **STIX/TAXII**: Connect to TAXII servers
   - Configure TAXII connection in the platform
   - Select collections to import
   - Configure polling frequency

2. **CSV/JSON Import**: Upload indicator files
   - Use the API to upload indicator files
   - Map file fields to platform fields

3. **Custom Feeds**: Connect to custom threat feeds
   - Implement a custom connector
   - Configure data mapping

#### Example: Uploading Indicators via API

```python
import requests

def upload_indicators(indicators, api_key):
    url = "https://api.securityai.example.com/v1/threat-intelligence/indicators/batch"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.post(url, headers=headers, json={"indicators": indicators})
    return response.json()

indicators = [
    {
        "type": "ip",
        "value": "203.0.113.1",
        "confidence": 80,
        "source": "external_feed",
        "tags": ["malware", "c2"],
        "expiration": "2023-12-31T23:59:59Z"
    },
    {
        "type": "domain",
        "value": "malicious-domain.com",
        "confidence": 90,
        "source": "external_feed",
        "tags": ["phishing"],
        "expiration": "2023-12-31T23:59:59Z"
    }
]

result = upload_indicators(indicators, "your-api-key")
```

## Custom Plugins

### Plugin Architecture

The SecurityAI Platform supports custom plugins for extending functionality:

1. **Plugin Types**:
   - Data Source plugins: Collect data from external sources
   - Enrichment plugins: Enrich alerts with additional context
   - Response plugins: Implement custom response actions
   - Visualization plugins: Create custom visualizations
   - Report plugins: Generate custom reports

2. **Plugin Structure**:
   - Manifest file: Plugin metadata and configuration
   - Code files: Implementation of plugin functionality
   - Dependencies: Required libraries and resources

### Creating a Custom Plugin

1. **Create the plugin structure**:

```
plugin-name/
├── manifest.json
├── main.py
├── requirements.txt
└── config_schema.json
```

2. **Define the manifest**:

```json
{
  "name": "custom-enrichment-plugin",
  "version": "1.0.0",
  "description": "Custom enrichment plugin for SecurityAI Platform",
  "author": "Your Name",
  "email": "your.email@example.com",
  "type": "enrichment",
  "entry_point": "main:CustomEnrichmentPlugin",
  "requirements": ["requirements.txt"],
  "config_schema": "config_schema.json",
  "min_platform_version": "2.0.0"
}
```

3. **Implement the plugin**:

```python
# main.py
from securityai.plugins import EnrichmentPlugin

class CustomEnrichmentPlugin(EnrichmentPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.api_key = config.get("api_key")
        self.api_url = config.get("api_url")
    
    def enrich(self, alert):
        # Implement enrichment logic
        enriched_data = self._get_external_data(alert)
        
        # Return enriched alert
        alert["enriched"] = enriched_data
        return alert
    
    def _get_external_data(self, alert):
        # Implement API call to external service
        # ...
        return {"external_data": "value"}
```

4. **Define configuration schema**:

```json
{
  "type": "object",
  "properties": {
    "api_key": {
      "type": "string",
      "description": "API key for external service"
    },
    "api_url": {
      "type": "string",
      "description": "URL of external service API",
      "default": "https://api.external-service.com/v1"
    }
  },
  "required": ["api_key"]
}
```

5. **Package and install the plugin**:

```bash
# Create a zip archive
zip -r custom-enrichment-plugin.zip custom-enrichment-plugin/

# Install via platform UI or API
```

## Best Practices

### API Usage

1. **Rate Limiting**:
   - Implement exponential backoff for rate limit errors
   - Cache responses when appropriate
   - Batch requests when possible

2. **Error Handling**:
   - Handle HTTP error codes appropriately
   - Implement retry logic for transient errors
   - Log detailed error information

3. **Authentication**:
   - Rotate API keys regularly
   - Use the principle of least privilege
   - Store credentials securely

### Data Exchange

1. **Data Validation**:
   - Validate data before sending to the platform
   - Handle validation errors gracefully
   - Implement schema validation

2. **Data Transformation**:
   - Normalize data formats
   - Handle time zones consistently
   - Preserve original data when possible

3. **Data Volume**:
   - Implement pagination for large data sets
   - Use compression for large payloads
   - Consider batch processing for high-volume data

### Integration Testing

1. **Test Environment**:
   - Use a dedicated test environment
   - Test with realistic data volumes
   - Simulate error conditions

2. **Monitoring**:
   - Monitor integration health
   - Set up alerts for integration failures
   - Track API usage and performance

3. **Documentation**:
   - Document integration architecture
   - Maintain configuration details
   - Document troubleshooting procedures

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Verify API key or OAuth credentials
   - Check for expired tokens
   - Ensure correct permissions are assigned

2. **Rate Limiting**:
   - Check response headers for rate limit information
   - Implement backoff and retry logic
   - Consider optimizing request patterns

3. **Data Format Issues**:
   - Validate payload against schema
   - Check for encoding issues
   - Verify required fields are present

4. **Webhook Delivery Failures**:
   - Check network connectivity
   - Verify endpoint is accessible
   - Check for firewall or proxy issues

### Debugging Tools

1. **API Logs**:
   - Enable detailed API logging
   - Review request and response details
   - Check for error messages

2. **Webhook Testing**:
   - Use webhook testing tools
   - Verify signature validation
   - Check payload format

3. **Integration Monitoring**:
   - Monitor integration status
   - Track success and failure rates
   - Set up alerts for integration issues

## Reference Implementations

### Python Client

```python
import requests
import json

class SecurityAIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def get_alerts(self, params=None):
        url = f"{self.base_url}/v1/alerts"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()["data"]
    
    def get_alert(self, alert_id):
        url = f"{self.base_url}/v1/alerts/{alert_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]
    
    def update_alert(self, alert_id, data):
        url = f"{self.base_url}/v1/alerts/{alert_id}"
        response = requests.patch(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()["data"]
    
    def get_assets(self, params=None):
        url = f"{self.base_url}/v1/assets"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()["data"]
    
    def get_asset(self, asset_id):
        url = f"{self.base_url}/v1/assets/{asset_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]
    
    def predict_threat(self, data, model_id="threat-detection-v2"):
        url = f"{self.base_url}/v1/ml/predict"
        payload = {"data": data, "model_id": model_id}
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()["data"]

# Usage example
client = SecurityAIClient("https://api.securityai.example.com", "your-api-key")

# Get recent high severity alerts
alerts = client.get_alerts({"severity": "high", "limit": 10})

# Update an alert
client.update_alert("alert-123", {"status": "acknowledged"})

# Get asset details
asset = client.get_asset("asset-456")

# Make a prediction
prediction = client.predict_threat({
    "source_ip": "192.168.1.100",
    "destination_ip": "203.0.113.10",
    "destination_port": 445,
    "protocol": "tcp"
})
```

### JavaScript Client

```javascript
class SecurityAIClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.headers = {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };
  }

  async getAlerts(params = {}) {
    const url = new URL(`${this.baseUrl}/v1/alerts`);
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
    
    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    return data.data;
  }

  async getAlert(alertId) {
    const response = await fetch(`${this.baseUrl}/v1/alerts/${alertId}`, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    return data.data;
  }

  async updateAlert(alertId, data) {
    const response = await fetch(`${this.baseUrl}/v1/alerts/${alertId}`, {
      method: 'PATCH',
      headers: this.headers,
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    
    const responseData = await response.json();
    return responseData.data;
  }

  async getAssets(params = {}) {
    const url = new URL(`${this.baseUrl}/v1/assets`);
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
    
    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    return data.data;
  }

  async predictThreat(data, modelId = 'threat-detection-v2') {
    const response = await fetch(`${this.baseUrl}/v1/ml/predict`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({
        data: data,
        model_id: modelId
      })
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }
    
    const responseData = await response.json();
    return responseData.data;
  }
}

// Usage example
const client = new SecurityAIClient('https://api.securityai.example.com', 'your-api-key');

// Get recent high severity alerts
client.getAlerts({ severity: 'high', limit: 10 })
  .then(alerts => console.log(alerts))
  .catch(error => console.error(error));

// Update an alert
client.updateAlert('alert-123', { status: 'acknowledged' })
  .then(alert => console.log(alert))
  .catch(error => console.error(error));

// Make a prediction
client.predictThreat({
  source_ip: '192.168.1.100',
  destination_ip: '203.0.113.10',
  destination_port: 445,
  protocol: 'tcp'
})
  .then(prediction => console.log(prediction))
  .catch(error => console.error(error));
```

## Appendix

### API Status Codes

| Status Code | Description |
|-------------|-------------|
| 200 | OK - The request was successful |
| 201 | Created - The resource was successfully created |
| 204 | No Content - The request was successful but returns no content |
| 400 | Bad Request - The request was malformed or contained invalid parameters |
| 401 | Unauthorized - Authentication failed or was not provided |
| 403 | Forbidden - The authenticated user does not have permission to access the resource |
| 404 | Not Found - The requested resource was not found |
| 409 | Conflict - The request conflicts with the current state of the resource |
| 422 | Unprocessable Entity - The request contained invalid data |
| 429 | Too Many Requests - The rate limit has been exceeded |
| 500 | Internal Server Error - An internal server error occurred |

### Common Error Codes

| Error Code | Description |
|------------|-------------|
| `invalid_request` | The request was malformed or contained invalid parameters |
| `unauthorized` | Authentication failed or was not provided |
| `forbidden` | The authenticated user does not have permission to access the resource |
| `not_found` | The requested resource was not found |
| `conflict` | The request conflicts with the current state of the resource |
| `validation_error` | The request contained invalid data |
| `rate_limit_exceeded` | The rate limit has been exceeded |
| `internal_error` | An internal server error occurred |

### Glossary

| Term | Definition |
|------|------------|
| **API** | Application Programming Interface - A set of rules that allows one software application to interact with another |
| **REST** | Representational State Transfer - An architectural style for designing networked applications |
| **JSON** | JavaScript Object Notation - A lightweight data interchange format |
| **OAuth** | Open Authorization - An open standard for access delegation |
| **Webhook** | A method of augmenting or altering the behavior of a web page or web application with custom callbacks |
| **SIEM** | Security Information and Event Management - A solution that provides real-time analysis of security alerts |
| **SOAR** | Security Orchestration, Automation, and Response - A solution stack that allows organizations to collect security data and perform security operations |
| **EDR** | Endpoint Detection and Response - A security solution that continuously monitors endpoints to detect and respond to cyber threats |
| **XDR** | Extended Detection and Response - A security solution that provides holistic protection across endpoints, networks, and cloud workloads |
| **STIX** | Structured Threat Information Expression - A language for sharing cyber threat intelligence |
| **TAXII** | Trusted Automated Exchange of Intelligence Information - A protocol for exchanging cyber threat intelligence |