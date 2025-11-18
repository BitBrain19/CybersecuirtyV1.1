# Advanced Features Guide

## Overview

This guide provides detailed information on the advanced features of the SecurityAI Platform. These features are designed for experienced users who want to leverage the full power of the platform for enhanced security operations, threat detection, and response.

## Advanced Threat Detection

### Custom Detection Rules

The SecurityAI Platform allows you to create custom detection rules to identify specific threats in your environment.

#### Creating Custom Detection Rules

1. Navigate to Security Operations > Detection Rules
2. Click "Create Rule"
3. Select the rule type:
   - Query-based rule
   - ML-assisted rule
   - Composite rule
4. Configure the rule parameters:
   - Name and description
   - Data sources
   - Detection logic
   - Severity and MITRE ATT&CK mapping
   - Response actions
5. Test the rule against historical data
6. Enable and save the rule

#### Query-Based Rules

Query-based rules use a query language similar to SQL to detect patterns in your security data.

Example query for detecting multiple failed login attempts:

```sql
SELECT source_ip, username, COUNT(*) as attempt_count
FROM authentication_logs
WHERE event_type = 'login_failure'
  AND timestamp > NOW() - INTERVAL 10 MINUTE
GROUP BY source_ip, username
HAVING attempt_count >= 5
```

#### ML-Assisted Rules

ML-assisted rules combine traditional rule logic with machine learning models for more accurate detection.

Example ML-assisted rule configuration:

```json
{
  "rule_type": "ml_assisted",
  "base_query": "SELECT * FROM network_flows WHERE destination_port = 445",
  "ml_model": "lateral_movement_detector",
  "ml_threshold": 0.75,
  "ml_features": ["source_ip", "destination_ip", "bytes_sent", "bytes_received", "duration"]
}
```

#### Composite Rules

Composite rules combine multiple detection signals to identify complex attack patterns.

Example composite rule:

```json
{
  "rule_type": "composite",
  "rule_name": "Potential Ransomware Activity",
  "conditions": [
    {
      "rule_id": "rule-123",  // Multiple failed login attempts
      "window": "1h"
    },
    {
      "rule_id": "rule-456",  // Suspicious PowerShell execution
      "window": "30m"
    },
    {
      "rule_id": "rule-789",  // Mass file modifications
      "window": "15m"
    }
  ],
  "logic": "1 AND (2 OR 3)",
  "min_confidence": 80
}
```

### Threat Hunting

The platform provides advanced threat hunting capabilities to proactively search for threats in your environment.

#### Creating Hunting Queries

1. Navigate to Security Operations > Threat Hunting
2. Click "New Hunt"
3. Define your hunting hypothesis
4. Create your hunting query
5. Select the data sources to search
6. Execute the hunt and analyze results

Example hunting query for potential data exfiltration:

```sql
SELECT source_ip, destination_ip, SUM(bytes_sent) as total_bytes_sent
FROM network_flows
WHERE destination_ip NOT IN (SELECT ip_address FROM known_destinations)
  AND timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY source_ip, destination_ip
HAVING total_bytes_sent > 100000000  -- 100MB
ORDER BY total_bytes_sent DESC
```

#### Hunting Playbooks

The platform includes pre-defined hunting playbooks for common threat hunting scenarios:

1. **Lateral Movement Hunting**
   - Identify unusual internal network connections
   - Detect credential usage across multiple systems
   - Find unusual process executions on multiple hosts

2. **Data Exfiltration Hunting**
   - Identify large outbound data transfers
   - Detect unusual cloud storage access
   - Find sensitive data access followed by external communications

3. **Persistence Mechanism Hunting**
   - Identify new scheduled tasks and services
   - Detect modifications to startup locations
   - Find unusual registry modifications

#### Converting Hunting Queries to Detection Rules

When a hunting query successfully identifies threats, you can convert it to a persistent detection rule:

1. From the hunting results page, click "Convert to Rule"
2. Configure the rule parameters:
   - Adjust the query if needed
   - Set severity and response actions
   - Configure alert aggregation
3. Test the rule against historical data
4. Enable and save the rule

## Advanced Analytics

### User and Entity Behavior Analytics (UEBA)

The UEBA module uses machine learning to establish behavioral baselines and detect anomalies.

#### Configuring UEBA

1. Navigate to Analytics > UEBA Configuration
2. Configure entity types to monitor:
   - Users
   - Endpoints
   - Applications
   - Network devices
3. Configure data sources for behavioral analysis
4. Set baseline learning period (default: 30 days)
5. Configure anomaly detection sensitivity
6. Enable automated responses (optional)

#### Behavioral Baselines

The UEBA module establishes baselines for various behaviors:

1. **User Baselines**
   - Login times and locations
   - Resource access patterns
   - Command execution patterns
   - Data access volumes

2. **Endpoint Baselines**
   - Running processes
   - Network connections
   - File system activity
   - Resource utilization

3. **Application Baselines**
   - API call patterns
   - Authentication patterns
   - Data access patterns
   - Error rates

#### Analyzing Behavioral Anomalies

1. Navigate to Analytics > UEBA > Anomalies
2. Filter anomalies by:
   - Entity type
   - Anomaly type
   - Severity
   - Time range
3. Select an anomaly to view details:
   - Anomaly description
   - Affected entity
   - Behavioral baseline
   - Observed behavior
   - Related events
4. Take action on the anomaly:
   - Investigate
   - Acknowledge
   - Dismiss as false positive
   - Create case

### Risk Scoring

The platform uses a multi-factor risk scoring system to prioritize security issues.

#### Understanding Risk Scores

Risk scores are calculated on a scale of 0-100 based on multiple factors:

1. **Threat Intelligence**: Matches with known IOCs
2. **Behavioral Analysis**: Deviation from established baselines
3. **Vulnerability Data**: Known vulnerabilities and their severity
4. **Asset Criticality**: Importance of the affected asset
5. **Historical Context**: Previous security incidents

#### Customizing Risk Scoring

1. Navigate to Analytics > Risk Scoring > Configuration
2. Adjust factor weights:
   - Threat Intelligence weight (default: 20%)
   - Behavioral Analysis weight (default: 25%)
   - Vulnerability Data weight (default: 20%)
   - Asset Criticality weight (default: 25%)
   - Historical Context weight (default: 10%)
3. Configure risk thresholds:
   - Low risk: 0-39
   - Medium risk: 40-69
   - High risk: 70-89
   - Critical risk: 90-100
4. Save your configuration

#### Risk Dashboards

1. Navigate to Analytics > Risk Dashboards
2. View overall risk posture:
   - Risk score distribution
   - Risk trend over time
   - Top risk contributors
3. Drill down by:
   - Asset
   - User
   - Vulnerability
   - Threat type

### Attack Path Analysis

The Attack Path Analysis feature identifies potential paths attackers could take through your environment.

#### Running Attack Path Analysis

1. Navigate to Analytics > Attack Paths
2. Click "Run Analysis"
3. Configure analysis parameters:
   - Starting points (e.g., internet-facing assets)
   - Target assets (e.g., critical servers)
   - Analysis depth
4. Start the analysis
5. View the results when complete

#### Interpreting Attack Paths

The attack path visualization shows:

1. **Nodes**: Assets in your environment
2. **Edges**: Potential attack vectors between assets
3. **Colors**: Risk level of each node and edge
4. **Labels**: Asset information and attack techniques

You can:

- Zoom and pan the visualization
- Filter by risk level
- Focus on specific assets
- View detailed information for each node and edge

#### Remediating Attack Paths

1. Select a critical attack path
2. View the "choke points" - key nodes that appear in multiple attack paths
3. Generate remediation recommendations:
   - Patch vulnerabilities
   - Adjust firewall rules
   - Implement network segmentation
   - Apply principle of least privilege
4. Create remediation tasks
5. Track remediation progress

## Advanced Response Capabilities

### Security Orchestration, Automation, and Response (SOAR)

The SOAR module enables automated response to security incidents.

#### Creating Response Playbooks

1. Navigate to Response > Playbooks
2. Click "Create Playbook"
3. Configure playbook triggers:
   - Alert creation
   - Threshold breach
   - Manual trigger
4. Design the playbook workflow:
   - Add actions and decision points
   - Configure action parameters
   - Set conditions for decisions
5. Test the playbook
6. Enable and save the playbook

#### Available Playbook Actions

The platform includes a wide range of built-in actions:

1. **Enrichment Actions**
   - Threat intelligence lookup
   - User information lookup
   - Asset information lookup
   - Vulnerability lookup
   - Historical alert lookup

2. **Containment Actions**
   - Isolate endpoint
   - Block IP address
   - Disable user account
   - Block domain
   - Quarantine file

3. **Investigation Actions**
   - Collect forensic data
   - Run remote commands
   - Capture network traffic
   - Take memory snapshot
   - Analyze file

4. **Remediation Actions**
   - Remove malware
   - Reset password
   - Apply patch
   - Restore from backup
   - Update firewall rules

5. **Notification Actions**
   - Send email
   - Send SMS
   - Create ticket
   - Post to chat
   - Call API

#### Example Phishing Response Playbook

```yaml
name: Phishing Email Response
trigger:
  type: alert
  conditions:
    alert_type: phishing
actions:
  - name: Enrich Email
    type: enrichment
    action: email_header_analysis
    parameters:
      email_id: "{{trigger.alert.email_id}}"
    output_variable: email_analysis
  
  - name: Check Reputation
    type: enrichment
    action: check_sender_reputation
    parameters:
      sender: "{{email_analysis.sender}}"
    output_variable: sender_reputation
  
  - name: Decision Point
    type: decision
    conditions:
      - condition: "{{sender_reputation.score < 30}}"
        actions:
          - name: Block Sender
            type: containment
            action: block_email_sender
            parameters:
              sender: "{{email_analysis.sender}}"
          
          - name: Search Similar Emails
            type: investigation
            action: search_similar_emails
            parameters:
              sender: "{{email_analysis.sender}}"
              subject_keywords: "{{email_analysis.subject_keywords}}"
            output_variable: similar_emails
          
          - name: Quarantine Similar Emails
            type: containment
            action: quarantine_emails
            parameters:
              email_ids: "{{similar_emails.ids}}"
          
          - name: Create Incident
            type: notification
            action: create_incident_ticket
            parameters:
              title: "Phishing Campaign - {{email_analysis.subject}}"
              description: "Detected phishing campaign from {{email_analysis.sender}}"
              severity: high
      
      - condition: "default"
        actions:
          - name: Create Alert
            type: notification
            action: create_alert
            parameters:
              title: "Potential Phishing Email - {{email_analysis.subject}}"
              description: "Potential phishing email from {{email_analysis.sender}}"
              severity: medium
```

### Endpoint Detection and Response (EDR)

The EDR module provides advanced endpoint protection and response capabilities.

#### EDR Agent Configuration

1. Navigate to Endpoints > Agent Configuration
2. Create or modify a configuration profile
3. Configure detection settings:
   - Process monitoring
   - File monitoring
   - Network monitoring
   - Memory monitoring
   - Script monitoring
4. Configure prevention settings:
   - Malware prevention
   - Exploit prevention
   - Behavioral prevention
   - Application control
5. Configure response settings:
   - Automated response actions
   - Data collection
   - Performance impact
6. Save the configuration profile
7. Assign the profile to endpoint groups

#### Remote Endpoint Investigation

1. Navigate to Endpoints > Endpoint List
2. Select an endpoint to investigate
3. Click "Investigate"
4. Available investigation actions:
   - View running processes
   - View network connections
   - View loaded modules
   - View file system
   - View registry (Windows)
   - View logs
5. Run live queries on the endpoint
6. Collect forensic evidence

Example live query for suspicious processes:

```sql
SELECT name, pid, path, cmd_line, parent_pid, user
FROM processes
WHERE 
  (name LIKE '%powershell%' AND cmd_line LIKE '%encode%') OR
  (name LIKE '%cmd.exe%' AND parent_name NOT IN ('explorer.exe', 'userinit.exe')) OR
  (name LIKE '%rundll32.exe%' AND cmd_line NOT LIKE '%shell32.dll%')
```

#### Endpoint Isolation and Remediation

1. Navigate to Endpoints > Endpoint List
2. Select an endpoint to remediate
3. Available remediation actions:
   - Isolate endpoint
   - Kill process
   - Delete file
   - Block hash
   - Run script
   - Restore from backup
4. For isolation, select isolation level:
   - Full isolation (no network communication)
   - Limited isolation (only management traffic)
   - Custom isolation (specify allowed traffic)
5. Execute the remediation action
6. Monitor the action status
7. Return endpoint to normal operation when remediation is complete

### Extended Detection and Response (XDR)

The XDR module correlates data across multiple security layers for comprehensive threat detection and response.

#### XDR Data Sources

Configure data sources for XDR correlation:

1. Navigate to XDR > Data Sources
2. Configure integration with:
   - Endpoint security (EDR)
   - Network security
   - Email security
   - Cloud security
   - Identity and access management
3. Configure data collection settings:
   - Collection frequency
   - Data retention
   - Data filtering

#### XDR Correlation Rules

Create rules to correlate events across different security layers:

1. Navigate to XDR > Correlation Rules
2. Click "Create Rule"
3. Configure rule parameters:
   - Name and description
   - Data sources to correlate
   - Correlation logic
   - Time window
   - Severity and MITRE ATT&CK mapping
4. Test the rule against historical data
5. Enable and save the rule

Example XDR correlation rule:

```json
{
  "rule_name": "Multi-stage Phishing Attack",
  "description": "Detects phishing email followed by suspicious endpoint activity",
  "data_sources": ["email_security", "edr", "network_security"],
  "correlation_logic": {
    "sequence": [
      {
        "source": "email_security",
        "event_type": "phishing_detected",
        "output_variables": {
          "recipient": "event.recipient",
          "attachment_hash": "event.attachment_hash"
        }
      },
      {
        "source": "edr",
        "event_type": "file_execution",
        "conditions": {
          "file_hash": "{{attachment_hash}}",
          "user": "{{recipient}}"
        },
        "within_seconds": 3600
      },
      {
        "source": "network_security",
        "event_type": "outbound_connection",
        "conditions": {
          "destination_reputation": "suspicious",
          "process_hash": "{{attachment_hash}}"
        },
        "within_seconds": 300
      }
    ]
  },
  "severity": "high",
  "mitre_techniques": ["T1566", "T1204", "T1071"]
}
```

#### XDR Investigation

1. Navigate to XDR > Incidents
2. Select an incident to investigate
3. View the incident timeline showing events across all security layers
4. Analyze the attack chain visualization
5. View affected assets and users
6. Access detailed event information from each security layer
7. Take response actions directly from the investigation interface

## Advanced Reporting and Visualization

### Custom Dashboards

Create personalized dashboards to visualize security data relevant to your role.

#### Creating Custom Dashboards

1. Navigate to Reporting > Dashboards
2. Click "Create Dashboard"
3. Configure dashboard properties:
   - Name and description
   - Default time range
   - Auto-refresh interval
   - Access permissions
4. Add widgets to the dashboard:
   - Charts (bar, line, pie, area)
   - Tables
   - Metrics
   - Text
   - Images
5. Configure each widget:
   - Data source
   - Query or metric
   - Visualization options
   - Filtering
6. Arrange widgets using drag-and-drop
7. Save the dashboard

#### Dashboard Widgets

Example widget configurations:

1. **Alert Trend Chart**

```json
{
  "widget_type": "line_chart",
  "title": "Alert Trend by Severity",
  "data_source": "alerts",
  "query": "SELECT DATE_TRUNC('day', created_at) as day, severity, COUNT(*) as count FROM alerts WHERE created_at >= :from AND created_at <= :to GROUP BY day, severity ORDER BY day",
  "x_axis": "day",
  "y_axis": "count",
  "series": "severity",
  "stacked": true
}
```

2. **Top Vulnerable Assets**

```json
{
  "widget_type": "table",
  "title": "Top Vulnerable Assets",
  "data_source": "assets",
  "query": "SELECT a.name, a.ip_address, a.criticality, COUNT(v.id) as vuln_count FROM assets a JOIN vulnerabilities v ON a.id = v.asset_id WHERE v.status = 'open' GROUP BY a.id ORDER BY vuln_count DESC LIMIT 10",
  "columns": [
    {"field": "name", "title": "Asset Name"},
    {"field": "ip_address", "title": "IP Address"},
    {"field": "criticality", "title": "Criticality"},
    {"field": "vuln_count", "title": "Open Vulnerabilities"}
  ]
}
```

3. **Risk Score Gauge**

```json
{
  "widget_type": "gauge",
  "title": "Overall Risk Score",
  "data_source": "metrics",
  "metric": "avg_risk_score",
  "min": 0,
  "max": 100,
  "thresholds": [
    {"value": 40, "color": "green"},
    {"value": 70, "color": "yellow"},
    {"value": 90, "color": "orange"},
    {"value": 100, "color": "red"}
  ]
}
```

### Advanced Reporting

Create detailed reports for security stakeholders and compliance requirements.

#### Creating Custom Reports

1. Navigate to Reporting > Reports
2. Click "Create Report"
3. Configure report properties:
   - Name and description
   - Report format (PDF, HTML, CSV)
   - Schedule (one-time, daily, weekly, monthly)
   - Distribution list
4. Design the report content:
   - Add sections and subsections
   - Add charts and tables
   - Add text and images
   - Add dynamic content
5. Configure data sources for each component
6. Preview the report
7. Save and schedule the report

#### Report Templates

The platform includes several report templates:

1. **Executive Summary Report**
   - Overall security posture
   - Key risk indicators
   - Notable security incidents
   - Compliance status

2. **Threat Intelligence Report**
   - Emerging threats
   - Threat actor activity
   - Industry-specific threats
   - Recommended actions

3. **Vulnerability Management Report**
   - Vulnerability trends
   - Top vulnerable assets
   - Remediation progress
   - Risk reduction metrics

4. **Compliance Report**
   - Compliance framework status
   - Control effectiveness
   - Audit findings
   - Remediation status

#### Compliance Reporting

Generate reports for specific compliance frameworks:

1. Navigate to Reporting > Compliance
2. Select a compliance framework:
   - PCI DSS
   - HIPAA
   - GDPR
   - ISO 27001
   - NIST CSF
   - SOC 2
3. Configure report parameters:
   - Reporting period
   - Scope (systems, departments)
   - Control mapping
4. Generate the report
5. Review compliance status and gaps
6. Export the report in the required format

## Advanced Configuration

### API Integration

Leverage the platform's API for custom integrations and automation.

#### API Authentication

1. Navigate to Administration > API Management
2. Click "Create API Key"
3. Configure key properties:
   - Name and description
   - Permissions
   - Expiration (optional)
4. Save and securely store the API key

#### Common API Use Cases

1. **Custom Dashboards and Reporting**
   - Retrieve security data for external dashboards
   - Incorporate security data into business intelligence tools

2. **Security Automation**
   - Trigger automated workflows based on security events
   - Integrate with custom security tools

3. **Data Integration**
   - Push security data to data lakes
   - Correlate security data with business context

4. **Custom Alerting**
   - Create custom alert notifications
   - Route alerts to specialized teams

Example API request to retrieve alerts:

```python
import requests

api_key = "your-api-key"
url = "https://securityai.example.com/api/v1/alerts"

params = {
    "severity": "high,critical",
    "status": "open",
    "from_date": "2023-01-01T00:00:00Z",
    "limit": 100
}

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers, params=params)
data = response.json()

for alert in data["data"]:
    print(f"Alert: {alert['title']} (Severity: {alert['severity']})")
```

### Custom Integrations

Extend the platform's capabilities with custom integrations.

#### Integration Types

1. **Data Source Integrations**
   - Ingest data from custom or proprietary systems
   - Transform and normalize data for the platform

2. **Enrichment Integrations**
   - Add business context to security data
   - Incorporate external threat intelligence

3. **Response Integrations**
   - Execute custom response actions
   - Integrate with specialized security tools

#### Creating Custom Integrations

1. Navigate to Administration > Integrations > Custom Integrations
2. Click "Create Integration"
3. Configure integration properties:
   - Name and description
   - Integration type
   - Authentication method
4. Implement the integration using:
   - REST API
   - Webhook
   - Custom connector
5. Test the integration
6. Enable and save the integration

### Advanced Search

Use the platform's advanced search capabilities to find specific security information.

#### Search Query Language

The platform uses a powerful query language for searching security data:

1. **Field Searches**
   - `field:value` - Exact match
   - `field:"multi word value"` - Phrase match
   - `field:>value` - Greater than
   - `field:<value` - Less than
   - `field:*value*` - Wildcard search

2. **Boolean Operators**
   - `AND` - Both conditions must match
   - `OR` - Either condition can match
   - `NOT` - Exclude matches
   - `()` - Group conditions

3. **Special Operators**
   - `NEAR/n` - Proximity search
   - `IN` - Value in list
   - `BETWEEN` - Value in range

Example search queries:

```
# Find high severity alerts related to authentication
severity:high AND category:authentication

# Find suspicious PowerShell commands
process_name:powershell.exe AND command_line:(*encode* OR *bypass* OR *hidden* OR *downloadstring*)

# Find large outbound transfers to unusual destinations
destination_ip:NOT(internal_network) AND bytes_sent:>10000000

# Find recently created service accounts
user_type:service AND created_at:>now-7d
```

#### Saved Searches

Save frequently used searches for quick access:

1. Execute a search query
2. Click "Save Search"
3. Provide a name and description
4. Configure sharing options
5. Optionally, set up alerts based on the search

## Best Practices

### Detection Engineering

1. **Coverage Mapping**
   - Map detection rules to MITRE ATT&CK techniques
   - Identify and address coverage gaps
   - Prioritize detection development based on risk

2. **Rule Tuning**
   - Monitor rule performance metrics
   - Adjust thresholds to reduce false positives
   - Use suppression lists for known exceptions

3. **Testing and Validation**
   - Test rules against historical data
   - Conduct regular red team exercises
   - Validate detection coverage with attack simulations

### Incident Response

1. **Playbook Development**
   - Create playbooks for common incident types
   - Document manual steps for complex scenarios
   - Regularly review and update playbooks

2. **Response Automation**
   - Automate routine response actions
   - Implement human approval for critical actions
   - Monitor automation effectiveness

3. **Post-Incident Analysis**
   - Conduct thorough post-incident reviews
   - Document lessons learned
   - Update detection and response capabilities

### Performance Optimization

1. **Query Optimization**
   - Use specific field searches instead of full-text search
   - Limit time ranges to relevant periods
   - Use aggregation for large data sets

2. **Resource Management**
   - Monitor platform resource usage
   - Schedule intensive operations during off-peak hours
   - Archive older data to optimize performance

3. **Scaling Considerations**
   - Monitor data ingestion rates
   - Plan capacity based on growth projections
   - Implement data tiering for cost-effective storage

## Troubleshooting

### Common Issues

1. **Detection Issues**
   - **Issue**: Rules not triggering as expected
   - **Solution**: Verify data sources are properly configured, check rule logic, and validate against test data

2. **Performance Issues**
   - **Issue**: Slow dashboard loading or query execution
   - **Solution**: Optimize queries, check resource utilization, and consider increasing allocated resources

3. **Integration Issues**
   - **Issue**: Data not flowing from integrated systems
   - **Solution**: Check connection settings, verify credentials, and review integration logs

### Diagnostic Tools

1. **Query Analyzer**
   - Navigate to Tools > Query Analyzer
   - Paste your query
   - Analyze query execution plan
   - Identify performance bottlenecks

2. **Log Explorer**
   - Navigate to Tools > Log Explorer
   - Select log type (application, audit, integration)
   - Filter logs by component and severity
   - Identify error patterns

3. **Health Monitor**
   - Navigate to Administration > System Health
   - View component status
   - Monitor resource utilization
   - Check for system warnings

## Appendix

### Advanced Query Examples

#### Complex Detection Queries

```sql
-- Detect potential pass-the-hash attacks
SELECT source_host, destination_host, user_name, COUNT(*) as auth_count
FROM authentication_logs
WHERE auth_package = 'NTLM'
  AND logon_type = 3
  AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY source_host, destination_host, user_name
HAVING COUNT(DISTINCT source_host) > 3

-- Detect potential data staging before exfiltration
SELECT host, user_name, SUM(file_size) as total_size
FROM file_events
WHERE file_path LIKE '%temp%'
  AND file_operation = 'create'
  AND file_type IN ('zip', 'rar', '7z', 'tar', 'gz')
  AND timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY host, user_name
HAVING SUM(file_size) > 100000000  -- 100MB

-- Detect suspicious PowerShell execution chains
SELECT e1.host, e1.user_name, e1.process_guid as parent_guid, e2.process_guid as child_guid,
       e1.process_name as parent_name, e2.process_name as child_name,
       e2.command_line
FROM process_events e1
JOIN process_events e2 ON e1.process_guid = e2.parent_process_guid
WHERE e1.process_name IN ('cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe')
  AND e2.process_name = 'powershell.exe'
  AND e2.command_line LIKE '%encode%'
  AND e1.timestamp > NOW() - INTERVAL 24 HOUR
```

#### Advanced Hunting Queries

```sql
-- Hunt for suspicious scheduled tasks
SELECT host, user_name, task_name, command, author, 
       creation_time, next_run_time
FROM scheduled_tasks
WHERE 
  (command LIKE '%powershell%' AND command LIKE '%hidden%') OR
  (command LIKE '%cmd%' AND command LIKE '%/c%') OR
  command LIKE '%rundll32%' OR
  command LIKE '%regsvr32%' OR
  command LIKE '%bitsadmin%' OR
  (creation_time > NOW() - INTERVAL 7 DAY AND author NOT IN (SELECT name FROM trusted_admins))

-- Hunt for suspicious registry persistence
SELECT host, user_name, registry_path, registry_value, registry_data,
       timestamp
FROM registry_events
WHERE 
  (registry_path LIKE '%\\Run%' OR
   registry_path LIKE '%\\RunOnce%' OR
   registry_path LIKE '%\\WinLogon%' OR
   registry_path LIKE '%\\Terminal Server\\\\AddIns%' OR
   registry_path LIKE '%\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects%')
  AND timestamp > NOW() - INTERVAL 7 DAY
  AND registry_data NOT IN (SELECT hash FROM trusted_binaries)

-- Hunt for suspicious login activity
SELECT user_name, source_ip, COUNT(DISTINCT destination_host) as host_count,
       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
FROM authentication_logs
WHERE 
  authentication_result = 'success'
  AND timestamp > NOW() - INTERVAL 24 HOUR
  AND user_name IN (SELECT name FROM privileged_accounts)
GROUP BY user_name, source_ip
HAVING COUNT(DISTINCT destination_host) > 5
```

### MITRE ATT&CK Mapping

The platform maps detection rules and security events to the MITRE ATT&CK framework:

1. **Initial Access**
   - T1566: Phishing
   - T1190: Exploit Public-Facing Application
   - T1133: External Remote Services

2. **Execution**
   - T1059: Command and Scripting Interpreter
   - T1204: User Execution
   - T1047: Windows Management Instrumentation

3. **Persistence**
   - T1547: Boot or Logon Autostart Execution
   - T1136: Create Account
   - T1098: Account Manipulation

4. **Privilege Escalation**
   - T1548: Abuse Elevation Control Mechanism
   - T1134: Access Token Manipulation
   - T1068: Exploitation for Privilege Escalation

5. **Defense Evasion**
   - T1070: Indicator Removal on Host
   - T1027: Obfuscated Files or Information
   - T1055: Process Injection

6. **Credential Access**
   - T1110: Brute Force
   - T1003: OS Credential Dumping
   - T1056: Input Capture

7. **Discovery**
   - T1087: Account Discovery
   - T1082: System Information Discovery
   - T1016: System Network Configuration Discovery

8. **Lateral Movement**
   - T1021: Remote Services
   - T1091: Replication Through Removable Media
   - T1072: Software Deployment Tools

9. **Collection**
   - T1560: Archive Collected Data
   - T1113: Screen Capture
   - T1114: Email Collection

10. **Command and Control**
    - T1071: Application Layer Protocol
    - T1105: Ingress Tool Transfer
    - T1095: Non-Application Layer Protocol

11. **Exfiltration**
    - T1048: Exfiltration Over Alternative Protocol
    - T1041: Exfiltration Over C2 Channel
    - T1567: Exfiltration Over Web Service

12. **Impact**
    - T1486: Data Encrypted for Impact
    - T1489: Service Stop
    - T1529: System Shutdown/Reboot

### Glossary

| Term | Definition |
|------|------------|
| **APT** | Advanced Persistent Threat - A sophisticated threat actor with significant resources |
| **C2** | Command and Control - Infrastructure used by attackers to communicate with compromised systems |
| **EDR** | Endpoint Detection and Response - Security technology that monitors and responds to threats on endpoints |
| **IOC** | Indicator of Compromise - Forensic evidence of potential intrusion |
| **SIEM** | Security Information and Event Management - Technology that provides real-time analysis of security alerts |
| **SOAR** | Security Orchestration, Automation, and Response - Technology that enables automated security operations |
| **TTP** | Tactics, Techniques, and Procedures - The patterns of activities and methods associated with threat actors |
| **UEBA** | User and Entity Behavior Analytics - Technology that uses analytics to detect abnormal behavior |
| **XDR** | Extended Detection and Response - Security technology that unifies multiple security products |
| **Zero Day** | A previously unknown vulnerability with no available patch |