#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SOAR actions for security automation workflows.

This module provides a collection of security actions that can be used in SOAR workflows:
- Email notifications
- Ticket creation
- Endpoint isolation
- User account management
- Threat intelligence lookups
- Log enrichment
- Firewall rule management
- Malware scanning
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import ipaddress
import re
import subprocess
import os

from ..core.config import settings
from ..core.logging_system import app_logger
from .workflow_engine import Action, ActionResult, ActionStatus, WorkflowContext


class EmailNotificationAction(Action):
    """Send email notifications."""
    
    def __init__(self):
        super().__init__(name="email_notification", description="Send email notifications")
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the email notification action."""
        try:
            # Extract parameters
            recipients = params.get("recipients", [])
            subject = params.get("subject", "Security Alert")
            body = params.get("body", "")
            html_body = params.get("html_body")
            
            if not recipients:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="No recipients specified"
                )
            
            # Create email message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.SMTP_SENDER
            msg["To"] = ", ".join(recipients)
            
            # Add plain text body
            msg.attach(MIMEText(body, "plain"))
            
            # Add HTML body if provided
            if html_body:
                msg.attach(MIMEText(html_body, "html"))
            
            # Send email
            if settings.SMTP_ENABLED:
                with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                    if settings.SMTP_USE_TLS:
                        server.starttls()
                    
                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    
                    server.send_message(msg)
                
                app_logger.info(f"Email notification sent to {len(recipients)} recipients")
                
                return ActionResult(
                    success=True,
                    status=ActionStatus.COMPLETED,
                    output={
                        "recipients": recipients,
                        "subject": subject,
                        "sent_at": datetime.now().isoformat()
                    }
                )
            else:
                app_logger.warning("Email notifications are disabled")
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Email notifications are disabled"
                )
        
        except Exception as e:
            app_logger.error(f"Failed to send email notification: {e}", error=e)
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=f"Failed to send email notification: {str(e)}"
            )


class TicketCreationAction(Action):
    """Create tickets in ticketing systems."""
    
    def __init__(self):
        super().__init__(name="create_ticket", description="Create a ticket in ticketing system")
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the ticket creation action."""
        try:
            # Extract parameters
            system = params.get("system", "default")
            title = params.get("title", "Security Incident")
            description = params.get("description", "")
            priority = params.get("priority", "medium")
            assignee = params.get("assignee")
            ticket_type = params.get("type", "incident")
            custom_fields = params.get("custom_fields", {})
            
            # Validate parameters
            if not title:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Ticket title is required"
                )
            
            # Create ticket based on the ticketing system
            ticket_id = None
            ticket_url = None
            
            if system == "jira" and settings.JIRA_ENABLED:
                # Create Jira ticket
                ticket_id, ticket_url = self._create_jira_ticket(
                    title, description, priority, assignee, ticket_type, custom_fields
                )
            
            elif system == "servicenow" and settings.SERVICENOW_ENABLED:
                # Create ServiceNow ticket
                ticket_id, ticket_url = self._create_servicenow_ticket(
                    title, description, priority, assignee, ticket_type, custom_fields
                )
            
            elif system == "default":
                # Create a mock ticket for demo purposes
                ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
                ticket_url = f"https://example.com/tickets/{ticket_id}"
                app_logger.info(f"Created mock ticket: {ticket_id}")
            
            else:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message=f"Unsupported ticketing system: {system}"
                )
            
            if ticket_id:
                # Store ticket information in context
                if "tickets" not in context.artifacts:
                    context.artifacts["tickets"] = []
                
                context.artifacts["tickets"].append({
                    "id": ticket_id,
                    "system": system,
                    "url": ticket_url,
                    "title": title,
                    "created_at": datetime.now().isoformat()
                })
                
                return ActionResult(
                    success=True,
                    status=ActionStatus.COMPLETED,
                    output={
                        "ticket_id": ticket_id,
                        "ticket_url": ticket_url,
                        "system": system
                    }
                )
            else:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Failed to create ticket"
                )
        
        except Exception as e:
            app_logger.error(f"Failed to create ticket: {e}", error=e)
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=f"Failed to create ticket: {str(e)}"
            )
    
    def _create_jira_ticket(self, title, description, priority, assignee, ticket_type, custom_fields):
        """Create a ticket in Jira."""
        # This is a placeholder implementation
        # In a real implementation, you would use the Jira API
        app_logger.info(f"Creating Jira ticket: {title}")
        ticket_id = f"JIRA-{uuid.uuid4().hex[:8].upper()}"
        ticket_url = f"{settings.JIRA_URL}/browse/{ticket_id}"
        return ticket_id, ticket_url
    
    def _create_servicenow_ticket(self, title, description, priority, assignee, ticket_type, custom_fields):
        """Create a ticket in ServiceNow."""
        # This is a placeholder implementation
        # In a real implementation, you would use the ServiceNow API
        app_logger.info(f"Creating ServiceNow ticket: {title}")
        ticket_id = f"INC{uuid.uuid4().hex[:8].upper()}"
        ticket_url = f"{settings.SERVICENOW_URL}/incident.do?sys_id={ticket_id}"
        return ticket_id, ticket_url


class EndpointIsolationAction(Action):
    """Isolate endpoints from the network."""
    
    def __init__(self):
        super().__init__(name="isolate_endpoint", description="Isolate an endpoint from the network")
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the endpoint isolation action."""
        try:
            # Extract parameters
            endpoint_id = params.get("endpoint_id")
            hostname = params.get("hostname")
            ip_address = params.get("ip_address")
            reason = params.get("reason", "Security incident")
            duration = params.get("duration", 3600)  # Default: 1 hour
            
            # Validate parameters
            if not any([endpoint_id, hostname, ip_address]):
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Either endpoint_id, hostname, or ip_address must be provided"
                )
            
            # Perform endpoint isolation based on the available EDR/XDR integration
            # This is a placeholder implementation
            app_logger.info(f"Isolating endpoint: {endpoint_id or hostname or ip_address}")
            
            # In a real implementation, you would call the EDR/XDR API
            # For now, we'll just simulate a successful isolation
            isolation_id = f"ISO-{uuid.uuid4().hex[:8]}"
            
            # Store isolation information in context
            if "isolations" not in context.artifacts:
                context.artifacts["isolations"] = []
            
            isolation_info = {
                "id": isolation_id,
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "reason": reason,
                "duration": duration,
                "isolated_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + datetime.timedelta(seconds=duration)).isoformat()
            }
            
            context.artifacts["isolations"].append(isolation_info)
            
            return ActionResult(
                success=True,
                status=ActionStatus.COMPLETED,
                output=isolation_info
            )
        
        except Exception as e:
            app_logger.error(f"Failed to isolate endpoint: {e}", error=e)
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=f"Failed to isolate endpoint: {str(e)}"
            )


class ThreatIntelligenceLookupAction(Action):
    """Look up indicators in threat intelligence platforms."""
    
    def __init__(self):
        super().__init__(name="threat_intel_lookup", description="Look up indicators in threat intelligence platforms")
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the threat intelligence lookup action."""
        try:
            # Extract parameters
            indicator_type = params.get("indicator_type", "ip")
            indicator_value = params.get("indicator_value")
            platforms = params.get("platforms", ["virustotal", "alienvault"])
            
            # Validate parameters
            if not indicator_value:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Indicator value is required"
                )
            
            # Validate indicator format based on type
            if not self._validate_indicator(indicator_type, indicator_value):
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message=f"Invalid {indicator_type} format: {indicator_value}"
                )
            
            # Look up indicator in specified platforms
            results = {}
            
            for platform in platforms:
                if platform == "virustotal":
                    results["virustotal"] = await self._lookup_virustotal(indicator_type, indicator_value)
                
                elif platform == "alienvault":
                    results["alienvault"] = await self._lookup_alienvault(indicator_type, indicator_value)
                
                # Add more platforms as needed
            
            # Determine overall maliciousness score
            malicious_score = self._calculate_malicious_score(results)
            
            # Store results in context
            if "threat_intel" not in context.artifacts:
                context.artifacts["threat_intel"] = {}
            
            context.artifacts["threat_intel"][indicator_value] = {
                "type": indicator_type,
                "results": results,
                "malicious_score": malicious_score,
                "lookup_time": datetime.now().isoformat()
            }
            
            return ActionResult(
                success=True,
                status=ActionStatus.COMPLETED,
                output={
                    "indicator": indicator_value,
                    "type": indicator_type,
                    "results": results,
                    "malicious_score": malicious_score
                }
            )
        
        except Exception as e:
            app_logger.error(f"Failed to perform threat intelligence lookup: {e}", error=e)
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=f"Failed to perform threat intelligence lookup: {str(e)}"
            )
    
    def _validate_indicator(self, indicator_type, indicator_value):
        """Validate indicator format based on type."""
        if indicator_type == "ip":
            try:
                ipaddress.ip_address(indicator_value)
                return True
            except ValueError:
                return False
        
        elif indicator_type == "domain":
            # Simple domain validation
            domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            return bool(re.match(domain_pattern, indicator_value))
        
        elif indicator_type == "url":
            # Simple URL validation
            url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
            return bool(re.match(url_pattern, indicator_value))
        
        elif indicator_type == "hash":
            # MD5, SHA1, or SHA256
            hash_patterns = {
                "md5": r'^[a-fA-F0-9]{32}$',
                "sha1": r'^[a-fA-F0-9]{40}$',
                "sha256": r'^[a-fA-F0-9]{64}$'
            }
            
            return any(bool(re.match(pattern, indicator_value)) for pattern in hash_patterns.values())
        
        # Default: assume valid
        return True
    
    async def _lookup_virustotal(self, indicator_type, indicator_value):
        """Look up indicator in VirusTotal."""
        # This is a placeholder implementation
        # In a real implementation, you would use the VirusTotal API
        await asyncio.sleep(0.5)  # Simulate API call
        
        # Simulate results
        return {
            "detected": True,
            "detection_ratio": "15/80",
            "first_seen": "2023-01-15T10:30:00Z",
            "last_seen": "2023-06-20T14:45:00Z",
            "categories": ["malware", "phishing"],
            "score": 0.75
        }
    
    async def _lookup_alienvault(self, indicator_type, indicator_value):
        """Look up indicator in AlienVault OTX."""
        # This is a placeholder implementation
        # In a real implementation, you would use the AlienVault OTX API
        await asyncio.sleep(0.3)  # Simulate API call
        
        # Simulate results
        return {
            "pulse_count": 5,
            "reputation": -2,
            "threat_score": 0.65,
            "tags": ["ransomware", "c2"],
            "first_seen": "2023-02-10T08:15:00Z"
        }
    
    def _calculate_malicious_score(self, results):
        """Calculate overall maliciousness score from multiple sources."""
        # This is a simple implementation
        # In a real implementation, you would use a more sophisticated algorithm
        scores = []
        
        if "virustotal" in results:
            vt_score = results["virustotal"].get("score", 0)
            scores.append(vt_score)
        
        if "alienvault" in results:
            av_score = results["alienvault"].get("threat_score", 0)
            scores.append(av_score)
        
        # Add more platforms as needed
        
        # Calculate average score
        if scores:
            return sum(scores) / len(scores)
        else:
            return 0.0


class FirewallRuleAction(Action):
    """Manage firewall rules."""
    
    def __init__(self):
        super().__init__(name="firewall_rule", description="Create or update firewall rules")
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the firewall rule action."""
        try:
            # Extract parameters
            action = params.get("action", "block")
            rule_type = params.get("rule_type", "ip")
            value = params.get("value")
            direction = params.get("direction", "inbound")
            duration = params.get("duration", 3600)  # Default: 1 hour
            description = params.get("description", "SOAR automated response")
            firewall = params.get("firewall", "default")
            
            # Validate parameters
            if not value:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Rule value is required"
                )
            
            if action not in ["block", "allow", "alert"]:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message=f"Invalid action: {action}"
                )
            
            # Create firewall rule based on the specified firewall
            rule_id = None
            
            if firewall == "palo_alto" and settings.PALO_ALTO_ENABLED:
                # Create rule in Palo Alto firewall
                rule_id = self._create_palo_alto_rule(
                    action, rule_type, value, direction, duration, description
                )
            
            elif firewall == "checkpoint" and settings.CHECKPOINT_ENABLED:
                # Create rule in Check Point firewall
                rule_id = self._create_checkpoint_rule(
                    action, rule_type, value, direction, duration, description
                )
            
            elif firewall == "default":
                # Create a mock rule for demo purposes
                rule_id = f"RULE-{uuid.uuid4().hex[:8].upper()}"
                app_logger.info(f"Created mock firewall rule: {rule_id} ({action} {rule_type}:{value})")
            
            else:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message=f"Unsupported firewall: {firewall}"
                )
            
            if rule_id:
                # Store rule information in context
                if "firewall_rules" not in context.artifacts:
                    context.artifacts["firewall_rules"] = []
                
                rule_info = {
                    "id": rule_id,
                    "firewall": firewall,
                    "action": action,
                    "rule_type": rule_type,
                    "value": value,
                    "direction": direction,
                    "duration": duration,
                    "description": description,
                    "created_at": datetime.now().isoformat(),
                    "expires_at": (datetime.now() + datetime.timedelta(seconds=duration)).isoformat() if duration else None
                }
                
                context.artifacts["firewall_rules"].append(rule_info)
                
                return ActionResult(
                    success=True,
                    status=ActionStatus.COMPLETED,
                    output=rule_info
                )
            else:
                return ActionResult(
                    success=False,
                    status=ActionStatus.FAILED,
                    error_message="Failed to create firewall rule"
                )
        
        except Exception as e:
            app_logger.error(f"Failed to manage firewall rule: {e}", error=e)
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=f"Failed to manage firewall rule: {str(e)}"
            )
    
    def _create_palo_alto_rule(self, action, rule_type, value, direction, duration, description):
        """Create a rule in Palo Alto firewall."""
        # This is a placeholder implementation
        # In a real implementation, you would use the Palo Alto API
        return f"PA-{uuid.uuid4().hex[:8].upper()}"
    
    def _create_checkpoint_rule(self, action, rule_type, value, direction, duration, description):
        """Create a rule in Check Point firewall."""
        # This is a placeholder implementation
        # In a real implementation, you would use the Check Point API
        return f"CP-{uuid.uuid4().hex[:8].upper()}"


# Register actions with the workflow engine
def register_actions():
    """Register all actions with the workflow engine."""
    from .workflow_engine import workflow_engine
    
    # Create and register actions
    actions = [
        EmailNotificationAction(),
        TicketCreationAction(),
        EndpointIsolationAction(),
        ThreatIntelligenceLookupAction(),
        FirewallRuleAction(),
        # Add more actions here
    ]
    
    for action in actions:
        workflow_engine.register_action(action)
    
    app_logger.info(f"Registered {len(actions)} SOAR actions")