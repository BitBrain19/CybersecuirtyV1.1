# Integration Examples

## Overview

This document provides practical examples of integrating external systems with the SecurityAI Platform. These examples demonstrate how to leverage the platform's API for various integration scenarios, including data ingestion, alert management, and automated response.

## Prerequisites

Before implementing any integration, ensure you have:

1. A valid API key with appropriate permissions
2. Basic understanding of REST API concepts
3. Familiarity with the programming language of your choice
4. Access to the SecurityAI Platform API documentation

## Authentication Examples

### API Key Authentication

#### Python Example

```python
import requests

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

response = requests.get(f"{BASE_URL}/alerts", headers=headers)

if response.status_code == 200:
    alerts = response.json()
    print(f"Retrieved {len(alerts['data'])} alerts")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

#### JavaScript Example

```javascript
const API_KEY = "your-api-key";
const BASE_URL = "https://api.securityai-platform.example.com/v1";

async function getAlerts() {
  try {
    const response = await fetch(`${BASE_URL}/alerts`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`Retrieved ${data.data.length} alerts`);
    return data;
  } catch (error) {
    console.error('Error fetching alerts:', error);
  }
}

getAlerts();
```

### OAuth 2.0 Authentication

#### Python Example

```python
import requests

CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
TOKEN_URL = "https://api.securityai-platform.example.com/v1/oauth/token"
BASE_URL = "https://api.securityai-platform.example.com/v1"

# Get OAuth token
def get_oauth_token():
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    
    response = requests.post(TOKEN_URL, data=data)
    
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception(f"Failed to get token: {response.status_code} - {response.text}")

# Use token for API requests
def get_alerts():
    token = get_oauth_token()
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers)
    
    if response.status_code == 200:
        alerts = response.json()
        print(f"Retrieved {len(alerts['data'])} alerts")
        return alerts
    else:
        print(f"Error: {response.status_code} - {response.text}")

alerts = get_alerts()
```

## Data Ingestion Examples

### Sending Logs

#### Python Example

```python
import requests
import json
import time

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Example firewall logs
firewall_logs = [
    {
        "timestamp": int(time.time()),
        "source_ip": "192.168.1.100",
        "destination_ip": "203.0.113.10",
        "source_port": 49123,
        "destination_port": 443,
        "protocol": "TCP",
        "action": "ALLOW",
        "bytes": 1024,
        "device_name": "fw-edge-01"
    },
    {
        "timestamp": int(time.time()),
        "source_ip": "10.0.0.15",
        "destination_ip": "10.0.0.1",
        "source_port": 53124,
        "destination_port": 22,
        "protocol": "TCP",
        "action": "BLOCK",
        "bytes": 512,
        "device_name": "fw-internal-01"
    }
]

# Send logs to the platform
response = requests.post(
    f"{BASE_URL}/ingest/logs/firewall",
    headers=headers,
    data=json.dumps({"logs": firewall_logs})
)

if response.status_code == 202:
    print("Logs sent successfully")
else:
    print(f"Error sending logs: {response.status_code} - {response.text}")
```

### Sending Threat Intelligence

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Example threat intelligence indicators
threat_indicators = [
    {
        "type": "ip",
        "value": "185.143.223.12",
        "confidence": 90,
        "threat_type": "c2",
        "source": "external-ti-feed",
        "first_seen": "2023-06-15T08:30:00Z",
        "last_seen": "2023-06-20T14:22:10Z",
        "tags": ["ransomware", "lockbit"]
    },
    {
        "type": "domain",
        "value": "malicious-domain.example",
        "confidence": 85,
        "threat_type": "phishing",
        "source": "external-ti-feed",
        "first_seen": "2023-06-18T10:15:30Z",
        "last_seen": "2023-06-20T09:45:22Z",
        "tags": ["phishing", "credential-theft"]
    },
    {
        "type": "file_hash",
        "value": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "hash_type": "sha256",
        "confidence": 95,
        "threat_type": "malware",
        "source": "external-ti-feed",
        "first_seen": "2023-06-17T22:10:45Z",
        "last_seen": "2023-06-20T11:30:15Z",
        "tags": ["trojan", "infostealer"]
    }
]

# Send threat intelligence to the platform
response = requests.post(
    f"{BASE_URL}/ingest/threat-intelligence",
    headers=headers,
    data=json.dumps({"indicators": threat_indicators})
)

if response.status_code == 202:
    print("Threat intelligence sent successfully")
else:
    print(f"Error sending threat intelligence: {response.status_code} - {response.text}")
```

### Sending Vulnerability Data

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Example vulnerability scan results
vulnerability_data = {
    "scan_id": "scan-2023-06-20-001",
    "scanner": "external-vulnerability-scanner",
    "scan_time": "2023-06-20T08:00:00Z",
    "assets": [
        {
            "hostname": "web-server-01",
            "ip_address": "10.0.1.15",
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-2023-12345",
                    "name": "Apache Log4j Remote Code Execution",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "affected_component": "log4j-core-2.14.1.jar",
                    "status": "open",
                    "detection_time": "2023-06-20T08:15:22Z"
                },
                {
                    "vulnerability_id": "CVE-2023-67890",
                    "name": "OpenSSL Buffer Overflow",
                    "severity": "high",
                    "cvss_score": 8.2,
                    "affected_component": "openssl-1.1.1k",
                    "status": "open",
                    "detection_time": "2023-06-20T08:16:05Z"
                }
            ]
        },
        {
            "hostname": "db-server-01",
            "ip_address": "10.0.1.20",
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-2023-54321",
                    "name": "PostgreSQL Privilege Escalation",
                    "severity": "medium",
                    "cvss_score": 6.5,
                    "affected_component": "postgresql-13.2",
                    "status": "open",
                    "detection_time": "2023-06-20T08:22:18Z"
                }
            ]
        }
    ]
}

# Send vulnerability data to the platform
response = requests.post(
    f"{BASE_URL}/ingest/vulnerabilities",
    headers=headers,
    data=json.dumps(vulnerability_data)
)

if response.status_code == 202:
    print("Vulnerability data sent successfully")
else:
    print(f"Error sending vulnerability data: {response.status_code} - {response.text}")
```

## Alert Management Examples

### Retrieving Alerts

#### Python Example

```python
import requests

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Get alerts with filtering
def get_filtered_alerts(severity=None, status=None, limit=100, offset=0):
    params = {
        "limit": limit,
        "offset": offset
    }
    
    if severity:
        params["filter[severity]"] = severity
    
    if status:
        params["filter[status]"] = status
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Get high severity open alerts
high_alerts = get_filtered_alerts(severity="high,critical", status="open")

if high_alerts:
    print(f"Retrieved {len(high_alerts['data'])} high/critical severity open alerts")
    
    # Print alert details
    for alert in high_alerts['data']:
        print(f"Alert ID: {alert['id']}")
        print(f"Title: {alert['title']}")
        print(f"Severity: {alert['severity']}")
        print(f"Created: {alert['created_at']}")
        print("---")
```

### Updating Alert Status

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Update alert status
def update_alert_status(alert_id, status, comment=None):
    data = {
        "status": status
    }
    
    if comment:
        data["comment"] = comment
    
    response = requests.patch(
        f"{BASE_URL}/alerts/{alert_id}",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Update an alert to acknowledged status
updated_alert = update_alert_status(
    "alert-123456",
    "acknowledged",
    "Investigating this alert - John Doe"
)

if updated_alert:
    print(f"Alert {updated_alert['id']} updated to {updated_alert['status']}")
```

### Creating a Case from Alerts

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Create a case from alerts
def create_case_from_alerts(title, description, alert_ids, severity="medium", assignee=None):
    data = {
        "title": title,
        "description": description,
        "alert_ids": alert_ids,
        "severity": severity
    }
    
    if assignee:
        data["assignee"] = assignee
    
    response = requests.post(
        f"{BASE_URL}/cases",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code == 201:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Create a case from multiple related alerts
case = create_case_from_alerts(
    "Potential Data Exfiltration from Finance Department",
    "Multiple alerts indicating unusual data transfer from finance department systems to external destinations.",
    ["alert-123456", "alert-123457", "alert-123458"],
    "high",
    "security-analyst@example.com"
)

if case:
    print(f"Case created with ID: {case['id']}")
```

## Asset Management Examples

### Retrieving Asset Information

#### Python Example

```python
import requests

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Get asset details by ID
def get_asset_by_id(asset_id):
    response = requests.get(f"{BASE_URL}/assets/{asset_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Get asset by IP address
def get_asset_by_ip(ip_address):
    params = {
        "filter[ip_address]": ip_address
    }
    
    response = requests.get(f"{BASE_URL}/assets", headers=headers, params=params)
    
    if response.status_code == 200:
        assets = response.json()
        if assets['data']:
            return assets['data'][0]
        else:
            print(f"No asset found with IP: {ip_address}")
            return None
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Get asset details
asset = get_asset_by_ip("10.0.1.15")

if asset:
    print(f"Asset ID: {asset['id']}")
    print(f"Hostname: {asset['hostname']}")
    print(f"IP Address: {asset['ip_address']}")
    print(f"Operating System: {asset['operating_system']}")
    print(f"Criticality: {asset['criticality']}")
    
    # Get vulnerabilities for this asset
    params = {
        "filter[asset_id]": asset['id'],
        "limit": 100
    }
    
    response = requests.get(f"{BASE_URL}/vulnerabilities", headers=headers, params=params)
    
    if response.status_code == 200:
        vulnerabilities = response.json()
        print(f"\nVulnerabilities: {len(vulnerabilities['data'])}")
        
        for vuln in vulnerabilities['data']:
            print(f"- {vuln['vulnerability_id']}: {vuln['name']} (Severity: {vuln['severity']})")
```

### Updating Asset Information

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Update asset information
def update_asset(asset_id, updates):
    response = requests.patch(
        f"{BASE_URL}/assets/{asset_id}",
        headers=headers,
        data=json.dumps(updates)
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Update asset criticality and add tags
updated_asset = update_asset(
    "asset-123456",
    {
        "criticality": "high",
        "tags": ["production", "pci-scope", "customer-data"],
        "owner": "finance-department",
        "notes": "This server processes customer payment information and falls under PCI DSS scope."
    }
)

if updated_asset:
    print(f"Asset {updated_asset['id']} updated successfully")
```

## Response Automation Examples

### Executing Response Actions

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Execute a response action
def execute_response_action(action_type, parameters):
    data = {
        "action_type": action_type,
        "parameters": parameters
    }
    
    response = requests.post(
        f"{BASE_URL}/response/actions",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code == 202:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Isolate an endpoint
isolation_action = execute_response_action(
    "isolate_endpoint",
    {
        "asset_id": "asset-123456",
        "isolation_level": "full",
        "reason": "Suspected malware infection"
    }
)

if isolation_action:
    print(f"Action initiated: {isolation_action['id']}")
    print(f"Status: {isolation_action['status']}")

# Block an IP address
block_action = execute_response_action(
    "block_ip",
    {
        "ip_address": "203.0.113.100",
        "direction": "both",
        "duration_hours": 24,
        "reason": "Suspicious scanning activity"
    }
)

if block_action:
    print(f"Action initiated: {block_action['id']}")
    print(f"Status: {block_action['status']}")
```

### Checking Action Status

#### Python Example

```python
import requests
import time

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Check status of a response action
def check_action_status(action_id):
    response = requests.get(f"{BASE_URL}/response/actions/{action_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Wait for action to complete
def wait_for_action_completion(action_id, timeout_seconds=60, poll_interval=5):
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        action_status = check_action_status(action_id)
        
        if not action_status:
            return None
        
        if action_status['status'] in ['completed', 'failed']:
            return action_status
        
        print(f"Action status: {action_status['status']} - waiting...")
        time.sleep(poll_interval)
    
    print("Timeout waiting for action completion")
    return check_action_status(action_id)

# Wait for an action to complete
final_status = wait_for_action_completion("action-123456")

if final_status:
    print(f"Final status: {final_status['status']}")
    
    if final_status['status'] == 'completed':
        print("Action completed successfully")
        print(f"Result: {final_status['result']}")
    elif final_status['status'] == 'failed':
        print(f"Action failed: {final_status['error']}")
```

## Webhook Integration Examples

### Setting Up a Webhook Receiver

#### Python Example (Flask)

```python
from flask import Flask, request, jsonify
import hmac
import hashlib
import time

app = Flask(__name__)

# Your webhook secret from the SecurityAI Platform
WEBHOOK_SECRET = "your-webhook-secret"

# Verify webhook signature
def verify_signature(request_data, signature_header, timestamp_header):
    if not signature_header or not timestamp_header:
        return False
    
    # Check if timestamp is recent (within 5 minutes)
    timestamp = int(timestamp_header)
    current_time = int(time.time())
    if abs(current_time - timestamp) > 300:
        return False
    
    # Calculate expected signature
    message = f"{timestamp}:{request_data}"
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    return hmac.compare_digest(expected_signature, signature_header)

@app.route('/webhook/securityai', methods=['POST'])
def webhook_receiver():
    # Get request data
    request_data = request.get_data(as_text=True)
    signature = request.headers.get('X-SecurityAI-Signature')
    timestamp = request.headers.get('X-SecurityAI-Timestamp')
    
    # Verify signature
    if not verify_signature(request_data, signature, timestamp):
        return jsonify({"error": "Invalid signature"}), 401
    
    # Process webhook data
    try:
        webhook_data = request.json
        event_type = webhook_data.get('event_type')
        
        print(f"Received webhook: {event_type}")
        
        # Handle different event types
        if event_type == 'alert.created':
            handle_alert_created(webhook_data['data'])
        elif event_type == 'vulnerability.detected':
            handle_vulnerability_detected(webhook_data['data'])
        elif event_type == 'threat.detected':
            handle_threat_detected(webhook_data['data'])
        else:
            print(f"Unhandled event type: {event_type}")
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error processing webhook: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Handler functions for different event types
def handle_alert_created(alert_data):
    alert_id = alert_data['id']
    severity = alert_data['severity']
    title = alert_data['title']
    
    print(f"New alert: {alert_id} - {title} (Severity: {severity})")
    
    # Add your custom logic here
    # For example, create a ticket in your ticketing system
    if severity in ['high', 'critical']:
        create_ticket_in_external_system(alert_data)

def handle_vulnerability_detected(vulnerability_data):
    vuln_id = vulnerability_data['id']
    severity = vulnerability_data['severity']
    name = vulnerability_data['name']
    asset_id = vulnerability_data['asset_id']
    
    print(f"New vulnerability: {vuln_id} - {name} on asset {asset_id} (Severity: {severity})")
    
    # Add your custom logic here

def handle_threat_detected(threat_data):
    threat_id = threat_data['id']
    threat_type = threat_data['threat_type']
    confidence = threat_data['confidence']
    
    print(f"New threat: {threat_id} - {threat_type} (Confidence: {confidence})")
    
    # Add your custom logic here

# Example function to create a ticket in an external system
def create_ticket_in_external_system(alert_data):
    # This is a placeholder for your integration code
    print(f"Creating ticket for alert {alert_data['id']} in external system")
    # Your code to create a ticket in your ticketing system

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Configuring Webhook in the Platform

#### Python Example

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Create a webhook configuration
def create_webhook(url, events, description=None):
    data = {
        "url": url,
        "events": events
    }
    
    if description:
        data["description"] = description
    
    response = requests.post(
        f"{BASE_URL}/webhooks",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code == 201:
        webhook = response.json()
        print(f"Webhook created with ID: {webhook['id']}")
        print(f"Secret: {webhook['secret']}")
        return webhook
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

# Create a webhook for alert and vulnerability events
webhook = create_webhook(
    "https://your-server.example.com/webhook/securityai",
    ["alert.created", "alert.updated", "vulnerability.detected", "threat.detected"],
    "Production webhook for security events"
)

if webhook:
    print("Webhook configured successfully")
    print("IMPORTANT: Save the webhook secret securely!")
```

## SIEM Integration Examples

### Splunk Integration

#### Python Example (Splunk HTTP Event Collector)

```python
import requests
import json
import time

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

# Splunk configuration
SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector"
SPLUNK_HEC_TOKEN = "your-splunk-hec-token"

# Get alerts from SecurityAI Platform
def get_alerts(since_timestamp):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    params = {
        "filter[created_at]": f"gt:{since_timestamp}",
        "limit": 100
    }
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()['data']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

# Send events to Splunk
def send_to_splunk(events):
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Send events in batches
    batch_size = 50
    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        payload = ""
        
        for event in batch:
            event_data = {
                "time": int(time.mktime(time.strptime(event['created_at'], "%Y-%m-%dT%H:%M:%SZ"))),
                "host": "securityai-platform",
                "source": "securityai-alerts",
                "sourcetype": "securityai:alert",
                "index": "security",
                "event": event
            }
            payload += json.dumps(event_data) + "\n"
        
        response = requests.post(SPLUNK_HEC_URL, headers=headers, data=payload)
        
        if response.status_code != 200:
            print(f"Error sending to Splunk: {response.status_code} - {response.text}")
            return False
    
    return True

# Main function to sync alerts to Splunk
def sync_alerts_to_splunk():
    # Get timestamp of last sync (in production, store this persistently)
    last_sync = "2023-06-01T00:00:00Z"  # Example timestamp
    
    # Get new alerts
    alerts = get_alerts(last_sync)
    print(f"Retrieved {len(alerts)} new alerts")
    
    if alerts:
        # Send to Splunk
        success = send_to_splunk(alerts)
        
        if success:
            print("Alerts sent to Splunk successfully")
            # Update last sync time (in production, store this persistently)
            if alerts:
                last_sync = alerts[-1]['created_at']
        else:
            print("Failed to send alerts to Splunk")

# Run the sync
sync_alerts_to_splunk()
```

### Elastic Stack Integration

#### Python Example (Elasticsearch API)

```python
import requests
import json
from elasticsearch import Elasticsearch
import time

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

# Elasticsearch configuration
ES_HOST = "elasticsearch.example.com"
ES_PORT = 9200
ES_USER = "elastic"
ES_PASSWORD = "your-elasticsearch-password"
ES_INDEX = "securityai-alerts"

# Get alerts from SecurityAI Platform
def get_alerts(since_timestamp):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    params = {
        "filter[created_at]": f"gt:{since_timestamp}",
        "limit": 100
    }
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()['data']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

# Send events to Elasticsearch
def send_to_elasticsearch(alerts):
    # Connect to Elasticsearch
    es = Elasticsearch(
        [f"https://{ES_HOST}:{ES_PORT}"],
        http_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False  # In production, set to True and configure proper certificates
    )
    
    # Check if index exists, create if not
    if not es.indices.exists(index=ES_INDEX):
        # Define index mapping
        mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "description": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "source": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "asset_id": {"type": "keyword"},
                    "user_id": {"type": "keyword"},
                    "tags": {"type": "keyword"}
                }
            }
        }
        
        es.indices.create(index=ES_INDEX, body=mapping)
    
    # Index alerts
    for alert in alerts:
        # Convert timestamp to proper format if needed
        if 'created_at' in alert:
            alert['created_at'] = alert['created_at']
        
        if 'updated_at' in alert:
            alert['updated_at'] = alert['updated_at']
        
        # Index the document
        es.index(index=ES_INDEX, id=alert['id'], body=alert)
    
    # Refresh index to make documents immediately available for search
    es.indices.refresh(index=ES_INDEX)
    
    return True

# Main function to sync alerts to Elasticsearch
def sync_alerts_to_elasticsearch():
    # Get timestamp of last sync (in production, store this persistently)
    last_sync = "2023-06-01T00:00:00Z"  # Example timestamp
    
    # Get new alerts
    alerts = get_alerts(last_sync)
    print(f"Retrieved {len(alerts)} new alerts")
    
    if alerts:
        # Send to Elasticsearch
        success = send_to_elasticsearch(alerts)
        
        if success:
            print("Alerts sent to Elasticsearch successfully")
            # Update last sync time (in production, store this persistently)
            if alerts:
                last_sync = alerts[-1]['created_at']
        else:
            print("Failed to send alerts to Elasticsearch")

# Run the sync
sync_alerts_to_elasticsearch()
```

## Ticketing System Integration Examples

### Jira Integration

#### Python Example

```python
import requests
import json
from jira import JIRA

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

# Jira configuration
JIRA_URL = "https://your-jira-instance.atlassian.net"
JIRA_USER = "your-jira-email@example.com"
JIRA_API_TOKEN = "your-jira-api-token"
JIRA_PROJECT = "SEC"  # Security project key

# Get high severity alerts
def get_high_severity_alerts():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    params = {
        "filter[severity]": "high,critical",
        "filter[status]": "open",
        "filter[has_ticket]": "false",  # Custom field indicating if a ticket exists
        "limit": 50
    }
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()['data']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

# Create Jira tickets for alerts
def create_jira_tickets(alerts):
    # Connect to Jira
    jira = JIRA(
        server=JIRA_URL,
        basic_auth=(JIRA_USER, JIRA_API_TOKEN)
    )
    
    for alert in alerts:
        # Prepare issue fields
        issue_dict = {
            'project': {'key': JIRA_PROJECT},
            'summary': f"[SecurityAI] {alert['title']}",
            'description': f"{alert['description']}\n\n" +
                          f"**Alert ID:** {alert['id']}\n" +
                          f"**Severity:** {alert['severity']}\n" +
                          f"**Created:** {alert['created_at']}\n\n" +
                          f"**Source IP:** {alert.get('source_ip', 'N/A')}\n" +
                          f"**Destination IP:** {alert.get('destination_ip', 'N/A')}\n\n" +
                          f"View in SecurityAI Platform: {BASE_URL.replace('/v1', '')}/alerts/{alert['id']}",
            'issuetype': {'name': 'Security Incident'},
            'priority': {'name': 'High' if alert['severity'] == 'critical' else 'Medium'}
        }
        
        # Create the issue
        try:
            new_issue = jira.create_issue(fields=issue_dict)
            print(f"Created Jira ticket {new_issue.key} for alert {alert['id']}")
            
            # Update the alert with ticket information
            update_alert_with_ticket_info(alert['id'], new_issue.key)
        except Exception as e:
            print(f"Error creating Jira ticket for alert {alert['id']}: {str(e)}")

# Update alert with ticket information
def update_alert_with_ticket_info(alert_id, ticket_id):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "ticket_id": ticket_id,
        "has_ticket": True
    }
    
    response = requests.patch(
        f"{BASE_URL}/alerts/{alert_id}",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code != 200:
        print(f"Error updating alert with ticket info: {response.status_code} - {response.text}")

# Main function
def sync_alerts_to_jira():
    # Get alerts that need tickets
    alerts = get_high_severity_alerts()
    print(f"Found {len(alerts)} high severity alerts without tickets")
    
    if alerts:
        # Create tickets
        create_jira_tickets(alerts)

# Run the sync
sync_alerts_to_jira()
```

### ServiceNow Integration

#### Python Example

```python
import requests
import json
import base64

API_KEY = "your-api-key"
BASE_URL = "https://api.securityai-platform.example.com/v1"

# ServiceNow configuration
SN_INSTANCE = "your-instance.service-now.com"
SN_USER = "servicenow-user"
SN_PASSWORD = "servicenow-password"

# Get high severity alerts
def get_high_severity_alerts():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    params = {
        "filter[severity]": "high,critical",
        "filter[status]": "open",
        "filter[has_ticket]": "false",  # Custom field indicating if a ticket exists
        "limit": 50
    }
    
    response = requests.get(f"{BASE_URL}/alerts", headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()['data']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return []

# Create ServiceNow incidents for alerts
def create_servicenow_incidents(alerts):
    # ServiceNow API endpoint
    url = f"https://{SN_INSTANCE}/api/now/table/incident"
    
    # Basic auth headers
    auth_header = base64.b64encode(f"{SN_USER}:{SN_PASSWORD}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    for alert in alerts:
        # Prepare incident data
        incident_data = {
            "short_description": f"[SecurityAI] {alert['title']}",
            "description": f"{alert['description']}\n\n" +
                          f"Alert ID: {alert['id']}\n" +
                          f"Severity: {alert['severity']}\n" +
                          f"Created: {alert['created_at']}\n\n" +
                          f"Source IP: {alert.get('source_ip', 'N/A')}\n" +
                          f"Destination IP: {alert.get('destination_ip', 'N/A')}\n\n" +
                          f"View in SecurityAI Platform: {BASE_URL.replace('/v1', '')}/alerts/{alert['id']}",
            "category": "security",
            "impact": "1" if alert['severity'] == 'critical' else "2",
            "urgency": "1" if alert['severity'] == 'critical' else "2",
            "caller_id": "security.operations@example.com"
        }
        
        # Create the incident
        try:
            response = requests.post(
                url,
                headers=headers,
                data=json.dumps(incident_data)
            )
            
            if response.status_code == 201:
                incident = response.json()['result']
                print(f"Created ServiceNow incident {incident['number']} for alert {alert['id']}")
                
                # Update the alert with ticket information
                update_alert_with_ticket_info(alert['id'], incident['number'])
            else:
                print(f"Error creating ServiceNow incident: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error creating ServiceNow incident for alert {alert['id']}: {str(e)}")

# Update alert with ticket information
def update_alert_with_ticket_info(alert_id, ticket_id):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "ticket_id": ticket_id,
        "has_ticket": True
    }
    
    response = requests.patch(
        f"{BASE_URL}/alerts/{alert_id}",
        headers=headers,
        data=json.dumps(data)
    )
    
    if response.status_code != 200:
        print(f"Error updating alert with ticket info: {response.status_code} - {response.text}")

# Main function
def sync_alerts_to_servicenow():
    # Get alerts that need tickets
    alerts = get_high_severity_alerts()
    print(f"Found {len(alerts)} high severity alerts without tickets")
    
    if alerts:
        # Create incidents
        create_servicenow_incidents(alerts)

# Run the sync
sync_alerts_to_servicenow()
```

## Best Practices

### Error Handling

Implement robust error handling in your integrations:

```python
def api_request(method, endpoint, headers=None, params=None, data=None, max_retries=3, retry_delay=1):
    """Generic API request function with retry logic"""
    url = f"{BASE_URL}/{endpoint}"
    
    if headers is None:
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
    
    retries = 0
    while retries <= max_retries:
        try:
            if method.lower() == 'get':
                response = requests.get(url, headers=headers, params=params)
            elif method.lower() == 'post':
                response = requests.post(url, headers=headers, params=params, data=json.dumps(data) if data else None)
            elif method.lower() == 'put':
                response = requests.put(url, headers=headers, params=params, data=json.dumps(data) if data else None)
            elif method.lower() == 'patch':
                response = requests.patch(url, headers=headers, params=params, data=json.dumps(data) if data else None)
            elif method.lower() == 'delete':
                response = requests.delete(url, headers=headers, params=params)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Check for rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', retry_delay))
                print(f"Rate limited. Retrying after {retry_after} seconds")
                time.sleep(retry_after)
                retries += 1
                continue
            
            # Check for server errors
            if response.status_code >= 500:
                print(f"Server error: {response.status_code}. Retrying in {retry_delay} seconds")
                time.sleep(retry_delay)
                retries += 1
                continue
            
            # Return response for other status codes
            return response
        
        except requests.exceptions.RequestException as e:
            print(f"Request exception: {str(e)}. Retrying in {retry_delay} seconds")
            time.sleep(retry_delay)
            retries += 1
    
    raise Exception(f"Failed after {max_retries} retries")
```

### Pagination

Handle pagination for large result sets:

```python
def get_all_items(endpoint, params=None):
    """Get all items from a paginated endpoint"""
    if params is None:
        params = {}
    
    all_items = []
    params['limit'] = 100  # Maximum items per page
    params['offset'] = 0
    
    while True:
        response = api_request('get', endpoint, params=params)
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            break
        
        data = response.json()
        items = data.get('data', [])
        
        if not items:
            break
        
        all_items.extend(items)
        
        # Check if we've reached the end
        if len(items) < params['limit']:
            break
        
        # Update offset for next page
        params['offset'] += params['limit']
    
    return all_items
```

### Rate Limiting

Implement rate limiting to avoid API throttling:

```python
import time
from functools import wraps

def rate_limit(calls_per_second=1):
    """Decorator to rate limit API calls"""
    min_interval = 1.0 / calls_per_second
    last_call_time = [0.0]  # Use list for mutable closure state
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            elapsed = current_time - last_call_time[0]
            
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                time.sleep(sleep_time)
            
            result = func(*args, **kwargs)
            last_call_time[0] = time.time()
            return result
        return wrapper
    return decorator

@rate_limit(calls_per_second=5)
def get_alert(alert_id):
    # API call implementation
    pass
```

### Secure Credential Management

Store API keys and credentials securely:

```python
import os
from dotenv import load_dotenv
import keyring

# Option 1: Environment variables with .env file
load_dotenv()
API_KEY = os.getenv("SECURITYAI_API_KEY")

# Option 2: System keyring
def get_api_key():
    api_key = keyring.get_password("securityai", "api_key")
    if not api_key:
        # Prompt user for API key and store it
        api_key = input("Enter your SecurityAI API key: ")
        keyring.set_password("securityai", "api_key", api_key)
    return api_key

API_KEY = get_api_key()
```

## Troubleshooting

### Common Issues and Solutions

1. **Authentication Failures**
   - Verify API key is correct and not expired
   - Check if the API key has the required permissions
   - Ensure the API key is being sent in the correct format

2. **Rate Limiting**
   - Implement exponential backoff and retry logic
   - Reduce the frequency of API calls
   - Batch operations when possible

3. **Data Format Issues**
   - Validate data against the API schema before sending
   - Check for required fields
   - Ensure date formats are correct (ISO 8601 format)

4. **Webhook Verification Failures**
   - Verify the webhook secret is correct
   - Check that the signature calculation matches the platform's method
   - Ensure the timestamp is within the allowed window

### Debugging Tips

1. **Enable Verbose Logging**

```python
import logging
import http.client as http_client

# Enable HTTP request/response logging
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
```

2. **Create a Test Script**

```python
def test_api_connectivity():
    """Test basic API connectivity and authentication"""
    try:
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(f"{BASE_URL}/health", headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("API connection successful!")
        elif response.status_code == 401:
            print("Authentication failed. Check your API key.")
        elif response.status_code == 403:
            print("Permission denied. Your API key may not have the required permissions.")
        else:
            print(f"Unexpected status code: {response.status_code}")
    
    except Exception as e:
        print(f"Connection error: {str(e)}")

test_api_connectivity()
```

## Conclusion

This document provides practical examples for integrating external systems with the SecurityAI Platform. By leveraging these examples, you can build robust integrations that enhance your security operations and automate key workflows.

For additional assistance, refer to the complete API documentation or contact the SecurityAI Platform support team.