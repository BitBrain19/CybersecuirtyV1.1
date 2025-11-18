#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SOAR playbooks for security automation workflows.

This module provides pre-defined security playbooks for common security scenarios:
- Malware detection response
- Phishing incident response
- Brute force attack response
- Data exfiltration response
- Suspicious login response
"""

import os
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime

from core.logging_system import app_logger
from .workflow_engine import Workflow, WorkflowStep, TriggerType, workflow_engine
from .actions import EmailNotificationAction, TicketCreationAction, EndpointIsolationAction, ThreatIntelligenceLookupAction, FirewallRuleAction
from .conditions import AlertSeverityCondition, ThreatIntelligenceCondition, EntityRiskScoreCondition


def load_default_playbooks():
    """Load and register default SOAR playbooks."""
    # Ensure actions and conditions are registered
    from .actions import register_actions
    from .conditions import register_conditions
    
    register_actions()
    register_conditions()
    
    # Create and register default playbooks
    playbooks = [
        create_malware_response_playbook(),
        create_phishing_response_playbook(),
        create_brute_force_response_playbook(),
        create_suspicious_login_playbook(),
        create_data_exfiltration_playbook()
    ]
    
    for playbook in playbooks:
        workflow_engine.register_workflow(playbook)
    
    app_logger.info(f"Loaded {len(playbooks)} default SOAR playbooks")
    
    # Load custom playbooks from directory
    playbooks_dir = os.path.join(os.path.dirname(__file__), "playbooks")
    if os.path.exists(playbooks_dir):
        workflow_engine.load_workflows_from_directory(playbooks_dir)


def create_malware_response_playbook() -> Workflow:
    """Create a playbook for malware detection response."""
    playbook = Workflow(
        id="malware_response",
        name="Malware Detection Response",
        description="Automated response to malware detection alerts"
    )
    
    # Add triggers
    playbook.add_trigger(
        trigger_type=TriggerType.ALERT,
        trigger_config={
            "alert_types": ["malware_detection", "antivirus_alert"],
            "min_severity": "medium"
        }
    )
    
    # Create workflow steps
    
    # Step 1: Lookup threat intelligence for the malware hash
    step1 = WorkflowStep(
        id="lookup_threat_intel",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "hash",
            "indicator_value": "{{trigger.alert.indicators.hash}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["isolate_endpoint_decision"]
    )
    
    # Step 2: Decision point for endpoint isolation based on threat intel score
    step2 = WorkflowStep(
        id="isolate_endpoint_decision",
        action=EndpointIsolationAction(),
        params={
            "endpoint_id": "{{trigger.alert.endpoint_id}}",
            "hostname": "{{trigger.alert.hostname}}",
            "reason": "Malware detection: {{trigger.alert.title}}",
            "duration": 7200  # 2 hours
        },
        conditions=[ThreatIntelligenceCondition(indicator_type="hash", min_score=0.7)],
        next_steps=["create_ticket"],
        on_failure=["create_ticket"]
    )
    
    # Step 3: Create a ticket
    step3 = WorkflowStep(
        id="create_ticket",
        action=TicketCreationAction(),
        params={
            "title": "Malware Detection: {{trigger.alert.title}}",
            "description": "Malware detected on endpoint {{trigger.alert.hostname}}\n\n" +
                          "Alert Details:\n" +
                          "- Severity: {{trigger.alert.severity}}\n" +
                          "- Detection Time: {{trigger.alert.detection_time}}\n" +
                          "- Malware Type: {{trigger.alert.malware_type}}\n" +
                          "- File Hash: {{trigger.alert.indicators.hash}}\n\n" +
                          "Threat Intelligence: {{artifacts.threat_intel}}\n\n" +
                          "Automated Actions:\n" +
                          "- Endpoint Isolation: {{artifacts.isolations[0].id if 'isolations' in artifacts else 'Not performed'}}\n",
            "priority": "high",
            "ticket_type": "incident"
        },
        next_steps=["send_notification"]
    )
    
    # Step 4: Send notification
    step4 = WorkflowStep(
        id="send_notification",
        action=EmailNotificationAction(),
        params={
            "recipients": ["security-team@example.com"],
            "subject": "[SECURITY] Malware Detection: {{trigger.alert.title}}",
            "body": "Malware has been detected on endpoint {{trigger.alert.hostname}}.\n\n" +
                    "Alert Details:\n" +
                    "- Severity: {{trigger.alert.severity}}\n" +
                    "- Detection Time: {{trigger.alert.detection_time}}\n" +
                    "- Malware Type: {{trigger.alert.malware_type}}\n" +
                    "- File Hash: {{trigger.alert.indicators.hash}}\n\n" +
                    "Automated Actions:\n" +
                    "- Endpoint Isolation: {{artifacts.isolations[0].id if 'isolations' in artifacts else 'Not performed'}}\n" +
                    "- Ticket Created: {{artifacts.tickets[0].id}}\n\n" +
                    "Please investigate this incident immediately."
        }
    )
    
    # Add steps to workflow
    playbook.add_step(step1)
    playbook.add_step(step2)
    playbook.add_step(step3)
    playbook.add_step(step4)
    
    return playbook


def create_phishing_response_playbook() -> Workflow:
    """Create a playbook for phishing incident response."""
    playbook = Workflow(
        id="phishing_response",
        name="Phishing Incident Response",
        description="Automated response to phishing incidents"
    )
    
    # Add triggers
    playbook.add_trigger(
        trigger_type=TriggerType.ALERT,
        trigger_config={
            "alert_types": ["phishing", "suspicious_email"],
            "min_severity": "low"
        }
    )
    
    # Create workflow steps
    
    # Step 1: Lookup threat intelligence for URLs and sender
    step1 = WorkflowStep(
        id="lookup_threat_intel",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "url",
            "indicator_value": "{{trigger.alert.indicators.url}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["lookup_sender"]
    )
    
    # Step 2: Lookup sender domain
    step2 = WorkflowStep(
        id="lookup_sender",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "domain",
            "indicator_value": "{{trigger.alert.indicators.sender_domain}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["block_url_decision"]
    )
    
    # Step 3: Decision to block URL
    step3 = WorkflowStep(
        id="block_url_decision",
        action=FirewallRuleAction(),
        params={
            "action": "block",
            "rule_type": "url",
            "value": "{{trigger.alert.indicators.url}}",
            "direction": "outbound",
            "description": "Phishing URL from alert: {{trigger.alert.id}}",
            "duration": 86400  # 24 hours
        },
        conditions=[ThreatIntelligenceCondition(indicator_type="url", min_score=0.6)],
        next_steps=["create_ticket"],
        on_failure=["create_ticket"]
    )
    
    # Step 4: Create a ticket
    step4 = WorkflowStep(
        id="create_ticket",
        action=TicketCreationAction(),
        params={
            "title": "Phishing Incident: {{trigger.alert.title}}",
            "description": "Phishing email detected\n\n" +
                          "Alert Details:\n" +
                          "- Severity: {{trigger.alert.severity}}\n" +
                          "- Detection Time: {{trigger.alert.detection_time}}\n" +
                          "- Sender: {{trigger.alert.indicators.sender}}\n" +
                          "- Subject: {{trigger.alert.indicators.subject}}\n" +
                          "- URL: {{trigger.alert.indicators.url}}\n\n" +
                          "Threat Intelligence:\n" +
                          "- URL Score: {{artifacts.threat_intel[trigger.alert.indicators.url].malicious_score}}\n" +
                          "- Sender Domain Score: {{artifacts.threat_intel[trigger.alert.indicators.sender_domain].malicious_score}}\n\n" +
                          "Automated Actions:\n" +
                          "- URL Blocking: {{artifacts.firewall_rules[0].id if 'firewall_rules' in artifacts else 'Not performed'}}\n",
            "priority": "medium",
            "ticket_type": "incident"
        },
        next_steps=["send_notification"]
    )
    
    # Step 5: Send notification
    step5 = WorkflowStep(
        id="send_notification",
        action=EmailNotificationAction(),
        params={
            "recipients": ["security-team@example.com"],
            "subject": "[SECURITY] Phishing Incident: {{trigger.alert.title}}",
            "body": "A phishing email has been detected.\n\n" +
                    "Alert Details:\n" +
                    "- Severity: {{trigger.alert.severity}}\n" +
                    "- Detection Time: {{trigger.alert.detection_time}}\n" +
                    "- Sender: {{trigger.alert.indicators.sender}}\n" +
                    "- Subject: {{trigger.alert.indicators.subject}}\n" +
                    "- URL: {{trigger.alert.indicators.url}}\n\n" +
                    "Automated Actions:\n" +
                    "- URL Blocking: {{artifacts.firewall_rules[0].id if 'firewall_rules' in artifacts else 'Not performed'}}\n" +
                    "- Ticket Created: {{artifacts.tickets[0].id}}\n\n" +
                    "Please review this incident."
        }
    )
    
    # Add steps to workflow
    playbook.add_step(step1)
    playbook.add_step(step2)
    playbook.add_step(step3)
    playbook.add_step(step4)
    playbook.add_step(step5)
    
    return playbook


def create_brute_force_response_playbook() -> Workflow:
    """Create a playbook for brute force attack response."""
    playbook = Workflow(
        id="brute_force_response",
        name="Brute Force Attack Response",
        description="Automated response to brute force login attempts"
    )
    
    # Add triggers
    playbook.add_trigger(
        trigger_type=TriggerType.ALERT,
        trigger_config={
            "alert_types": ["brute_force", "multiple_auth_failures"],
            "min_severity": "medium"
        }
    )
    
    # Create workflow steps
    
    # Step 1: Block source IP
    step1 = WorkflowStep(
        id="block_source_ip",
        action=FirewallRuleAction(),
        params={
            "action": "block",
            "rule_type": "ip",
            "value": "{{trigger.alert.indicators.source_ip}}",
            "direction": "inbound",
            "description": "Brute force attack from IP: {{trigger.alert.indicators.source_ip}}",
            "duration": 3600  # 1 hour
        },
        next_steps=["lookup_threat_intel"]
    )
    
    # Step 2: Lookup threat intelligence for source IP
    step2 = WorkflowStep(
        id="lookup_threat_intel",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "ip",
            "indicator_value": "{{trigger.alert.indicators.source_ip}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["create_ticket"]
    )
    
    # Step 3: Create a ticket
    step3 = WorkflowStep(
        id="create_ticket",
        action=TicketCreationAction(),
        params={
            "title": "Brute Force Attack: {{trigger.alert.title}}",
            "description": "Brute force login attempts detected\n\n" +
                          "Alert Details:\n" +
                          "- Severity: {{trigger.alert.severity}}\n" +
                          "- Detection Time: {{trigger.alert.detection_time}}\n" +
                          "- Source IP: {{trigger.alert.indicators.source_ip}}\n" +
                          "- Target Account: {{trigger.alert.indicators.username}}\n" +
                          "- Failed Attempts: {{trigger.alert.indicators.failed_attempts}}\n\n" +
                          "Threat Intelligence:\n" +
                          "- IP Reputation Score: {{artifacts.threat_intel[trigger.alert.indicators.source_ip].malicious_score}}\n\n" +
                          "Automated Actions:\n" +
                          "- IP Blocking: {{artifacts.firewall_rules[0].id}}\n",
            "priority": "high",
            "ticket_type": "incident"
        },
        next_steps=["send_notification"]
    )
    
    # Step 4: Send notification
    step4 = WorkflowStep(
        id="send_notification",
        action=EmailNotificationAction(),
        params={
            "recipients": ["security-team@example.com"],
            "subject": "[SECURITY] Brute Force Attack: {{trigger.alert.title}}",
            "body": "Brute force login attempts have been detected.\n\n" +
                    "Alert Details:\n" +
                    "- Severity: {{trigger.alert.severity}}\n" +
                    "- Detection Time: {{trigger.alert.detection_time}}\n" +
                    "- Source IP: {{trigger.alert.indicators.source_ip}}\n" +
                    "- Target Account: {{trigger.alert.indicators.username}}\n" +
                    "- Failed Attempts: {{trigger.alert.indicators.failed_attempts}}\n\n" +
                    "Automated Actions:\n" +
                    "- IP Blocking: {{artifacts.firewall_rules[0].id}}\n" +
                    "- Ticket Created: {{artifacts.tickets[0].id}}\n\n" +
                    "Please investigate this incident."
        }
    )
    
    # Add steps to workflow
    playbook.add_step(step1)
    playbook.add_step(step2)
    playbook.add_step(step3)
    playbook.add_step(step4)
    
    return playbook


def create_suspicious_login_playbook() -> Workflow:
    """Create a playbook for suspicious login response."""
    playbook = Workflow(
        id="suspicious_login_response",
        name="Suspicious Login Response",
        description="Automated response to suspicious login activities"
    )
    
    # Add triggers
    playbook.add_trigger(
        trigger_type=TriggerType.ALERT,
        trigger_config={
            "alert_types": ["suspicious_login", "anomalous_authentication"],
            "min_severity": "medium"
        }
    )
    
    # Create workflow steps
    
    # Step 1: Lookup threat intelligence for source IP
    step1 = WorkflowStep(
        id="lookup_threat_intel",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "ip",
            "indicator_value": "{{trigger.alert.indicators.source_ip}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["block_ip_decision"]
    )
    
    # Step 2: Decision to block IP based on threat intel
    step2 = WorkflowStep(
        id="block_ip_decision",
        action=FirewallRuleAction(),
        params={
            "action": "block",
            "rule_type": "ip",
            "value": "{{trigger.alert.indicators.source_ip}}",
            "direction": "inbound",
            "description": "Suspicious login from IP: {{trigger.alert.indicators.source_ip}}",
            "duration": 7200  # 2 hours
        },
        conditions=[ThreatIntelligenceCondition(indicator_type="ip", min_score=0.6)],
        next_steps=["create_ticket"],
        on_failure=["create_ticket"]
    )
    
    # Step 3: Create a ticket
    step3 = WorkflowStep(
        id="create_ticket",
        action=TicketCreationAction(),
        params={
            "title": "Suspicious Login: {{trigger.alert.title}}",
            "description": "Suspicious login activity detected\n\n" +
                          "Alert Details:\n" +
                          "- Severity: {{trigger.alert.severity}}\n" +
                          "- Detection Time: {{trigger.alert.detection_time}}\n" +
                          "- User: {{trigger.alert.indicators.username}}\n" +
                          "- Source IP: {{trigger.alert.indicators.source_ip}}\n" +
                          "- Location: {{trigger.alert.indicators.location}}\n" +
                          "- Device: {{trigger.alert.indicators.device}}\n\n" +
                          "Threat Intelligence:\n" +
                          "- IP Reputation Score: {{artifacts.threat_intel[trigger.alert.indicators.source_ip].malicious_score}}\n\n" +
                          "Automated Actions:\n" +
                          "- IP Blocking: {{artifacts.firewall_rules[0].id if 'firewall_rules' in artifacts else 'Not performed'}}\n",
            "priority": "high",
            "ticket_type": "incident"
        },
        next_steps=["send_notification"]
    )
    
    # Step 4: Send notification
    step4 = WorkflowStep(
        id="send_notification",
        action=EmailNotificationAction(),
        params={
            "recipients": ["security-team@example.com", "{{trigger.alert.indicators.manager_email}}"],
            "subject": "[SECURITY] Suspicious Login: {{trigger.alert.indicators.username}}",
            "body": "Suspicious login activity has been detected.\n\n" +
                    "Alert Details:\n" +
                    "- User: {{trigger.alert.indicators.username}}\n" +
                    "- Time: {{trigger.alert.detection_time}}\n" +
                    "- Source IP: {{trigger.alert.indicators.source_ip}}\n" +
                    "- Location: {{trigger.alert.indicators.location}}\n" +
                    "- Device: {{trigger.alert.indicators.device}}\n\n" +
                    "Automated Actions:\n" +
                    "- IP Blocking: {{artifacts.firewall_rules[0].id if 'firewall_rules' in artifacts else 'Not performed'}}\n" +
                    "- Ticket Created: {{artifacts.tickets[0].id}}\n\n" +
                    "Please verify if this login was legitimate."
        }
    )
    
    # Add steps to workflow
    playbook.add_step(step1)
    playbook.add_step(step2)
    playbook.add_step(step3)
    playbook.add_step(step4)
    
    return playbook


def create_data_exfiltration_playbook() -> Workflow:
    """Create a playbook for data exfiltration response."""
    playbook = Workflow(
        id="data_exfiltration_response",
        name="Data Exfiltration Response",
        description="Automated response to potential data exfiltration"
    )
    
    # Add triggers
    playbook.add_trigger(
        trigger_type=TriggerType.ALERT,
        trigger_config={
            "alert_types": ["data_exfiltration", "unusual_data_transfer"],
            "min_severity": "high"
        }
    )
    
    # Create workflow steps
    
    # Step 1: Isolate the endpoint
    step1 = WorkflowStep(
        id="isolate_endpoint",
        action=EndpointIsolationAction(),
        params={
            "endpoint_id": "{{trigger.alert.endpoint_id}}",
            "hostname": "{{trigger.alert.hostname}}",
            "reason": "Potential data exfiltration: {{trigger.alert.title}}",
            "duration": 14400  # 4 hours
        },
        next_steps=["block_destination"]
    )
    
    # Step 2: Block destination
    step2 = WorkflowStep(
        id="block_destination",
        action=FirewallRuleAction(),
        params={
            "action": "block",
            "rule_type": "{{trigger.alert.indicators.destination_type}}",  # ip, domain, or url
            "value": "{{trigger.alert.indicators.destination}}",
            "direction": "outbound",
            "description": "Data exfiltration destination: {{trigger.alert.indicators.destination}}",
            "duration": 86400  # 24 hours
        },
        next_steps=["lookup_threat_intel"]
    )
    
    # Step 3: Lookup threat intelligence
    step3 = WorkflowStep(
        id="lookup_threat_intel",
        action=ThreatIntelligenceLookupAction(),
        params={
            "indicator_type": "{{trigger.alert.indicators.destination_type}}",
            "indicator_value": "{{trigger.alert.indicators.destination}}",
            "platforms": ["virustotal", "alienvault"]
        },
        next_steps=["create_ticket"]
    )
    
    # Step 4: Create a high-priority ticket
    step4 = WorkflowStep(
        id="create_ticket",
        action=TicketCreationAction(),
        params={
            "title": "CRITICAL: Data Exfiltration: {{trigger.alert.title}}",
            "description": "Potential data exfiltration detected\n\n" +
                          "Alert Details:\n" +
                          "- Severity: {{trigger.alert.severity}}\n" +
                          "- Detection Time: {{trigger.alert.detection_time}}\n" +
                          "- Endpoint: {{trigger.alert.hostname}}\n" +
                          "- User: {{trigger.alert.indicators.username}}\n" +
                          "- Data Volume: {{trigger.alert.indicators.data_volume}}\n" +
                          "- Destination: {{trigger.alert.indicators.destination}}\n\n" +
                          "Threat Intelligence:\n" +
                          "- Destination Reputation: {{artifacts.threat_intel[trigger.alert.indicators.destination].malicious_score}}\n\n" +
                          "Automated Actions:\n" +
                          "- Endpoint Isolation: {{artifacts.isolations[0].id}}\n" +
                          "- Destination Blocking: {{artifacts.firewall_rules[0].id}}\n",
            "priority": "critical",
            "ticket_type": "incident"
        },
        next_steps=["send_notification"]
    )
    
    # Step 5: Send urgent notification
    step5 = WorkflowStep(
        id="send_notification",
        action=EmailNotificationAction(),
        params={
            "recipients": ["security-team@example.com", "incident-response@example.com", "ciso@example.com"],
            "subject": "[CRITICAL] Data Exfiltration Alert: {{trigger.alert.hostname}}",
            "body": "URGENT: Potential data exfiltration has been detected.\n\n" +
                    "Alert Details:\n" +
                    "- Severity: {{trigger.alert.severity}}\n" +
                    "- Detection Time: {{trigger.alert.detection_time}}\n" +
                    "- Endpoint: {{trigger.alert.hostname}}\n" +
                    "- User: {{trigger.alert.indicators.username}}\n" +
                    "- Data Volume: {{trigger.alert.indicators.data_volume}}\n" +
                    "- Destination: {{trigger.alert.indicators.destination}}\n\n" +
                    "Automated Actions:\n" +
                    "- Endpoint Isolation: {{artifacts.isolations[0].id}}\n" +
                    "- Destination Blocking: {{artifacts.firewall_rules[0].id}}\n" +
                    "- Ticket Created: {{artifacts.tickets[0].id}}\n\n" +
                    "IMMEDIATE RESPONSE REQUIRED: Please investigate this incident immediately."
        }
    )
    
    # Add steps to workflow
    playbook.add_step(step1)
    playbook.add_step(step2)
    playbook.add_step(step3)
    playbook.add_step(step4)
    playbook.add_step(step5)
    
    return playbook