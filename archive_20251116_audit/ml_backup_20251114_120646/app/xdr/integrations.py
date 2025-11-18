#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extended Detection and Response (XDR) integrations module.

This module provides:
- Integration with external security systems
- Data exchange with third-party platforms
- API connectors for security tools
- Standardized data formats for interoperability
- Configuration management for integrations
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from datetime import datetime
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import requests
from urllib.parse import urljoin

from pydantic import BaseModel, Field

from core.config import settings
from core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from core.monitoring import metrics_collector
from core.exceptions import SecurityAIException

# Import XDR components
from .xdr_platform import (
    XDRPlatform, XDREvent, XDRAlert, DataSourceType,
    CorrelationRule, CorrelationRuleType, ThreatHunt,
    xdr_platform
)


class IntegrationType(Enum):
    """Types of XDR integrations."""
    SIEM = "siem"                      # Security Information and Event Management
    EDR = "edr"                        # Endpoint Detection and Response
    SOAR = "soar"                      # Security Orchestration, Automation, and Response
    THREAT_INTEL = "threat_intel"      # Threat Intelligence Platform
    VULNERABILITY = "vulnerability"    # Vulnerability Management
    CLOUD_SECURITY = "cloud_security"  # Cloud Security Platform
    NETWORK_SECURITY = "network"       # Network Security Platform
    EMAIL_SECURITY = "email"           # Email Security Platform
    IAM = "iam"                        # Identity and Access Management
    TICKETING = "ticketing"            # Ticketing System


class IntegrationStatus(Enum):
    """Status of an integration."""
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    CONFIGURING = "configuring"


class IntegrationConfig(BaseModel):
    """Configuration for an integration."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    integration_type: IntegrationType
    vendor: str
    product: str
    version: str
    status: IntegrationStatus = IntegrationStatus.DISABLED
    config_data: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_sync: Optional[datetime] = None
    error_message: Optional[str] = None


class IntegrationCapability(Enum):
    """Capabilities of an integration."""
    INGEST_EVENTS = "ingest_events"            # Ingest events from external system
    SEND_EVENTS = "send_events"                # Send events to external system
    INGEST_ALERTS = "ingest_alerts"            # Ingest alerts from external system
    SEND_ALERTS = "send_alerts"                # Send alerts to external system
    QUERY_DATA = "query_data"                  # Query data from external system
    EXECUTE_ACTIONS = "execute_actions"        # Execute actions in external system
    THREAT_INTELLIGENCE = "threat_intelligence" # Exchange threat intelligence
    ASSET_INVENTORY = "asset_inventory"        # Retrieve asset inventory
    USER_DIRECTORY = "user_directory"          # Access user directory
    VULNERABILITY_DATA = "vulnerability_data"   # Exchange vulnerability data


class IntegrationMapping(BaseModel):
    """Mapping configuration for an integration."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    integration_id: str
    source_field: str
    target_field: str
    transformation: Optional[str] = None
    enabled: bool = True


class XDRIntegrationManager:
    """Manager for XDR integrations."""
    
    def __init__(self):
        self.integrations: Dict[str, IntegrationConfig] = {}
        self.mappings: Dict[str, List[IntegrationMapping]] = {}
        self._lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Create default integrations
        self._create_default_integrations()
        
        app_logger.info("XDR Integration Manager initialized")
    
    def _create_default_integrations(self):
        """Create default integrations."""
        # Splunk SIEM integration
        splunk_integration = IntegrationConfig(
            name="Splunk SIEM Integration",
            description="Integration with Splunk Enterprise Security SIEM",
            integration_type=IntegrationType.SIEM,
            vendor="Splunk",
            product="Enterprise Security",
            version="7.0",
            config_data={
                "url": settings.SPLUNK_URL,
                "api_key": settings.SPLUNK_API_KEY,
                "capabilities": [
                    IntegrationCapability.INGEST_EVENTS.value,
                    IntegrationCapability.INGEST_ALERTS.value,
                    IntegrationCapability.QUERY_DATA.value
                ],
                "sync_interval": 300  # seconds
            }
        )
        
        # CrowdStrike EDR integration
        crowdstrike_integration = IntegrationConfig(
            name="CrowdStrike EDR Integration",
            description="Integration with CrowdStrike Falcon EDR",
            integration_type=IntegrationType.EDR,
            vendor="CrowdStrike",
            product="Falcon",
            version="6.0",
            config_data={
                "url": settings.CROWDSTRIKE_URL,
                "client_id": settings.CROWDSTRIKE_CLIENT_ID,
                "client_secret": settings.CROWDSTRIKE_CLIENT_SECRET,
                "capabilities": [
                    IntegrationCapability.INGEST_EVENTS.value,
                    IntegrationCapability.INGEST_ALERTS.value,
                    IntegrationCapability.EXECUTE_ACTIONS.value,
                    IntegrationCapability.ASSET_INVENTORY.value
                ],
                "sync_interval": 300  # seconds
            }
        )
        
        # ServiceNow SOAR integration
        servicenow_integration = IntegrationConfig(
            name="ServiceNow SecOps Integration",
            description="Integration with ServiceNow Security Operations SOAR",
            integration_type=IntegrationType.SOAR,
            vendor="ServiceNow",
            product="Security Operations",
            version="Paris",
            config_data={
                "url": settings.SERVICENOW_URL,
                "username": settings.SERVICENOW_USERNAME,
                "password": settings.SERVICENOW_PASSWORD,
                "capabilities": [
                    IntegrationCapability.SEND_ALERTS.value,
                    IntegrationCapability.EXECUTE_ACTIONS.value,
                    IntegrationCapability.QUERY_DATA.value
                ],
                "sync_interval": 600  # seconds
            }
        )
        
        # VirusTotal Threat Intel integration
        virustotal_integration = IntegrationConfig(
            name="VirusTotal Integration",
            description="Integration with VirusTotal threat intelligence",
            integration_type=IntegrationType.THREAT_INTEL,
            vendor="VirusTotal",
            product="VirusTotal",
            version="3.0",
            config_data={
                "url": "https://www.virustotal.com/api/v3/",
                "api_key": settings.VIRUSTOTAL_API_KEY,
                "capabilities": [
                    IntegrationCapability.THREAT_INTELLIGENCE.value
                ],
                "sync_interval": 3600  # seconds
            }
        )
        
        # Tenable Vulnerability Management integration
        tenable_integration = IntegrationConfig(
            name="Tenable.io Integration",
            description="Integration with Tenable.io vulnerability management",
            integration_type=IntegrationType.VULNERABILITY,
            vendor="Tenable",
            product="Tenable.io",
            version="2.0",
            config_data={
                "url": "https://cloud.tenable.com/",
                "access_key": settings.TENABLE_ACCESS_KEY,
                "secret_key": settings.TENABLE_SECRET_KEY,
                "capabilities": [
                    IntegrationCapability.VULNERABILITY_DATA.value,
                    IntegrationCapability.ASSET_INVENTORY.value
                ],
                "sync_interval": 86400  # seconds (daily)
            }
        )
        
        # Add integrations to the manager
        self.integrations[splunk_integration.id] = splunk_integration
        self.integrations[crowdstrike_integration.id] = crowdstrike_integration
        self.integrations[servicenow_integration.id] = servicenow_integration
        self.integrations[virustotal_integration.id] = virustotal_integration
        self.integrations[tenable_integration.id] = tenable_integration
        
        # Create default mappings
        self._create_default_mappings()
    
    def _create_default_mappings(self):
        """Create default field mappings for integrations."""
        # For each integration, create mappings
        for integration_id, integration in self.integrations.items():
            self.mappings[integration_id] = []
            
            # Create mappings based on integration type
            if integration.integration_type == IntegrationType.SIEM:
                # Splunk SIEM mappings
                self.mappings[integration_id].extend([
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.source",
                        target_field="source_type"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.sourcetype",
                        target_field="source_name"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.host",
                        target_field="hostname"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.user",
                        target_field="user_id"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.src_ip",
                        target_field="ip_address"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.dest_ip",
                        target_field="data.destination_address"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.dest_port",
                        target_field="data.destination_port"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.severity",
                        target_field="severity"
                    )
                ])
            
            elif integration.integration_type == IntegrationType.EDR:
                # CrowdStrike EDR mappings
                self.mappings[integration_id].extend([
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.ComputerName",
                        target_field="hostname"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.LocalIP",
                        target_field="ip_address"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.UserName",
                        target_field="user_id"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.ProcessId",
                        target_field="data.process_id"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.ParentProcessId",
                        target_field="data.parent_process_id"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.CommandLine",
                        target_field="data.command_line"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.FileName",
                        target_field="data.file_path"
                    ),
                    IntegrationMapping(
                        integration_id=integration_id,
                        source_field="event.MD5HashData",
                        target_field="data.file_hash"
                    )
                ])
    
    def get_integration(self, integration_id: str) -> Optional[IntegrationConfig]:
        """Get an integration by ID."""
        return self.integrations.get(integration_id)
    
    def get_integration_by_type(self, integration_type: IntegrationType) -> Optional[IntegrationConfig]:
        """Get an integration by type."""
        for integration in self.integrations.values():
            if integration.integration_type == integration_type:
                return integration
        return None
    
    def get_integrations_by_capability(self, capability: IntegrationCapability) -> List[IntegrationConfig]:
        """Get integrations by capability."""
        result = []
        for integration in self.integrations.values():
            capabilities = integration.config_data.get("capabilities", [])
            if capability.value in capabilities:
                result.append(integration)
        return result
    
    def enable_integration(self, integration_id: str):
        """Enable an integration."""
        integration = self.get_integration(integration_id)
        if not integration:
            raise SecurityAIException(f"Integration {integration_id} not found")
        
        integration.status = IntegrationStatus.ENABLED
        integration.updated_at = datetime.now()
        app_logger.info(f"Enabled integration: {integration.name} ({integration_id})")
    
    def disable_integration(self, integration_id: str):
        """Disable an integration."""
        integration = self.get_integration(integration_id)
        if not integration:
            raise SecurityAIException(f"Integration {integration_id} not found")
        
        integration.status = IntegrationStatus.DISABLED
        integration.updated_at = datetime.now()
        app_logger.info(f"Disabled integration: {integration.name} ({integration_id})")
    
    def update_integration_config(self, integration_id: str, config_data: Dict[str, Any]):
        """Update an integration's configuration."""
        integration = self.get_integration(integration_id)
        if not integration:
            raise SecurityAIException(f"Integration {integration_id} not found")
        
        integration.config_data.update(config_data)
        integration.updated_at = datetime.now()
        app_logger.info(f"Updated configuration for integration: {integration.name} ({integration_id})")
    
    def get_mappings(self, integration_id: str) -> List[IntegrationMapping]:
        """Get mappings for an integration."""
        return self.mappings.get(integration_id, [])
    
    def add_mapping(self, mapping: IntegrationMapping):
        """Add a mapping for an integration."""
        if mapping.integration_id not in self.integrations:
            raise SecurityAIException(f"Integration {mapping.integration_id} not found")
        
        if mapping.integration_id not in self.mappings:
            self.mappings[mapping.integration_id] = []
        
        self.mappings[mapping.integration_id].append(mapping)
        app_logger.info(f"Added mapping for integration {mapping.integration_id}: {mapping.source_field} -> {mapping.target_field}")
    
    def remove_mapping(self, mapping_id: str):
        """Remove a mapping."""
        for integration_id, mappings in self.mappings.items():
            for i, mapping in enumerate(mappings):
                if mapping.id == mapping_id:
                    del self.mappings[integration_id][i]
                    app_logger.info(f"Removed mapping {mapping_id} for integration {integration_id}")
                    return
        
        raise SecurityAIException(f"Mapping {mapping_id} not found")
    
    async def ingest_from_integration(self, integration_id: str):
        """Ingest data from an integration."""
        integration = self.get_integration(integration_id)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            return
        
        try:
            # Check capabilities
            capabilities = integration.config_data.get("capabilities", [])
            
            # Ingest events if supported
            if IntegrationCapability.INGEST_EVENTS.value in capabilities:
                await self._ingest_events(integration)
            
            # Ingest alerts if supported
            if IntegrationCapability.INGEST_ALERTS.value in capabilities:
                await self._ingest_alerts(integration)
            
            # Update last sync time
            integration.last_sync = datetime.now()
            app_logger.info(f"Completed ingestion from {integration.name}")
        
        except Exception as e:
            app_logger.error(f"Error ingesting from integration {integration.name}: {e}", error=e)
            integration.error_message = str(e)
            integration.status = IntegrationStatus.ERROR
    
    async def _ingest_events(self, integration: IntegrationConfig):
        """Ingest events from an integration."""
        app_logger.info(f"Ingesting events from {integration.name}")
        
        # In a real implementation, you would call the integration's API to get events
        # For now, just log the action
        app_logger.debug(f"Would ingest events from {integration.name}")
        
        # For demonstration, create a sample event
        if integration.integration_type == IntegrationType.SIEM:
            # Create a sample SIEM event
            event = XDREvent(
                source_type=DataSourceType.SIEM,
                source_id=f"sample-{uuid.uuid4()}",
                source_name=integration.product,
                event_type="network_connection",
                severity="medium",
                hostname="sample-host",
                ip_address="192.168.1.100",
                data={
                    "destination_address": "203.0.113.1",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": 1024,
                    "bytes_received": 2048
                }
            )
            
            # Add to XDR platform
            await xdr_platform._event_queue.put(event)
            app_logger.debug(f"Added sample SIEM event to XDR platform")
        
        elif integration.integration_type == IntegrationType.EDR:
            # Create a sample EDR event
            event = XDREvent(
                source_type=DataSourceType.EDR,
                source_id=f"sample-{uuid.uuid4()}",
                source_name=integration.product,
                event_type="process_create",
                severity="medium",
                hostname="sample-host",
                ip_address="192.168.1.100",
                user_id="user123",
                data={
                    "process_name": "powershell.exe",
                    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "process_id": 1234,
                    "parent_process_id": 5678,
                    "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass -EncodedCommand...",
                    "integrity_level": "high"
                }
            )
            
            # Add to XDR platform
            await xdr_platform._event_queue.put(event)
            app_logger.debug(f"Added sample EDR event to XDR platform")
    
    async def _ingest_alerts(self, integration: IntegrationConfig):
        """Ingest alerts from an integration."""
        app_logger.info(f"Ingesting alerts from {integration.name}")
        
        # In a real implementation, you would call the integration's API to get alerts
        # For now, just log the action
        app_logger.debug(f"Would ingest alerts from {integration.name}")
        
        # For demonstration, create a sample alert
        if integration.integration_type == IntegrationType.SIEM:
            # Create a sample SIEM alert
            alert = XDRAlert(
                title=f"Sample {integration.product} Alert",
                description="Suspicious network connection detected",
                severity="medium",
                source_type=DataSourceType.SIEM,
                source_id=f"sample-{uuid.uuid4()}",
                source_name=integration.product,
                hostname="sample-host",
                ip_address="192.168.1.100",
                data={
                    "destination_address": "203.0.113.1",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "rule_name": "Suspicious Outbound Connection"
                }
            )
            
            # Add to XDR platform
            await xdr_platform._alert_queue.put(alert)
            app_logger.debug(f"Added sample SIEM alert to XDR platform")
        
        elif integration.integration_type == IntegrationType.EDR:
            # Create a sample EDR alert
            alert = XDRAlert(
                title=f"Sample {integration.product} Alert",
                description="Suspicious PowerShell execution detected",
                severity="high",
                source_type=DataSourceType.EDR,
                source_id=f"sample-{uuid.uuid4()}",
                source_name=integration.product,
                hostname="sample-host",
                ip_address="192.168.1.100",
                user_id="user123",
                mitre_techniques=["T1059.001"],
                data={
                    "process_name": "powershell.exe",
                    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass -EncodedCommand...",
                    "detection_type": "Suspicious PowerShell Command"
                }
            )
            
            # Add to XDR platform
            await xdr_platform._alert_queue.put(alert)
            app_logger.debug(f"Added sample EDR alert to XDR platform")
    
    async def send_to_integration(self, integration_id: str, data_type: str, data: Union[XDREvent, XDRAlert]):
        """Send data to an integration."""
        integration = self.get_integration(integration_id)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            return
        
        try:
            # Check capabilities
            capabilities = integration.config_data.get("capabilities", [])
            
            # Send events if supported
            if data_type == "event" and IntegrationCapability.SEND_EVENTS.value in capabilities:
                await self._send_event(integration, data)
            
            # Send alerts if supported
            elif data_type == "alert" and IntegrationCapability.SEND_ALERTS.value in capabilities:
                await self._send_alert(integration, data)
            
            # Update last sync time
            integration.last_sync = datetime.now()
            app_logger.info(f"Sent {data_type} to {integration.name}")
        
        except Exception as e:
            app_logger.error(f"Error sending to integration {integration.name}: {e}", error=e)
            integration.error_message = str(e)
    
    async def _send_event(self, integration: IntegrationConfig, event: XDREvent):
        """Send an event to an integration."""
        app_logger.info(f"Sending event to {integration.name}")
        
        # In a real implementation, you would call the integration's API to send the event
        # For now, just log the action
        app_logger.debug(f"Would send event {event.id} to {integration.name}")
        
        # Apply mappings to transform the event
        transformed_event = self._apply_mappings(integration.id, event)
        
        # In a real implementation, you would send the transformed event
        app_logger.debug(f"Would send transformed event to {integration.name}")
    
    async def _send_alert(self, integration: IntegrationConfig, alert: XDRAlert):
        """Send an alert to an integration."""
        app_logger.info(f"Sending alert to {integration.name}")
        
        # In a real implementation, you would call the integration's API to send the alert
        # For now, just log the action
        app_logger.debug(f"Would send alert {alert.id} to {integration.name}")
        
        # Apply mappings to transform the alert
        transformed_alert = self._apply_mappings(integration.id, alert)
        
        # In a real implementation, you would send the transformed alert
        app_logger.debug(f"Would send transformed alert to {integration.name}")
    
    def _apply_mappings(self, integration_id: str, data: Union[XDREvent, XDRAlert]) -> Dict[str, Any]:
        """Apply mappings to transform data for an integration."""
        result = {}
        mappings = self.get_mappings(integration_id)
        
        for mapping in mappings:
            if not mapping.enabled:
                continue
            
            # Get source value using dot notation
            source_parts = mapping.source_field.split('.')
            source_obj = data
            
            try:
                for part in source_parts:
                    if hasattr(source_obj, part):
                        source_obj = getattr(source_obj, part)
                    elif isinstance(source_obj, dict) and part in source_obj:
                        source_obj = source_obj[part]
                    else:
                        source_obj = None
                        break
                
                # If source value found, apply transformation if needed
                if source_obj is not None:
                    target_value = source_obj
                    
                    # Apply transformation if specified
                    if mapping.transformation:
                        # In a real implementation, you would apply the transformation
                        # For now, just use the original value
                        pass
                    
                    # Set target value using dot notation
                    target_parts = mapping.target_field.split('.')
                    target_obj = result
                    
                    for i, part in enumerate(target_parts):
                        if i == len(target_parts) - 1:
                            target_obj[part] = target_value
                        else:
                            if part not in target_obj:
                                target_obj[part] = {}
                            target_obj = target_obj[part]
            
            except Exception as e:
                app_logger.error(f"Error applying mapping {mapping.id}: {e}", error=e)
        
        return result
    
    async def query_integration(self, integration_id: str, query_type: str, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query data from an integration."""
        integration = self.get_integration(integration_id)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            raise SecurityAIException(f"Integration {integration_id} not available")
        
        # Check capabilities
        capabilities = integration.config_data.get("capabilities", [])
        if IntegrationCapability.QUERY_DATA.value not in capabilities:
            raise SecurityAIException(f"Integration {integration.name} does not support querying data")
        
        try:
            app_logger.info(f"Querying {query_type} from {integration.name}")
            
            # In a real implementation, you would call the integration's API to query data
            # For now, just return a sample response
            if integration.integration_type == IntegrationType.SIEM:
                if query_type == "events":
                    return {
                        "events": [
                            {"id": "sample-1", "type": "network_connection", "timestamp": datetime.now().isoformat()},
                            {"id": "sample-2", "type": "authentication", "timestamp": datetime.now().isoformat()}
                        ],
                        "total": 2
                    }
                elif query_type == "alerts":
                    return {
                        "alerts": [
                            {"id": "alert-1", "title": "Suspicious Login", "severity": "medium"},
                            {"id": "alert-2", "title": "Malware Detected", "severity": "high"}
                        ],
                        "total": 2
                    }
            
            elif integration.integration_type == IntegrationType.THREAT_INTEL:
                if query_type == "ip":
                    return {
                        "ip": query_params.get("value"),
                        "reputation": "malicious",
                        "categories": ["malware", "c2"],
                        "score": 85
                    }
                elif query_type == "file_hash":
                    return {
                        "hash": query_params.get("value"),
                        "type": "PE",
                        "malicious": True,
                        "detections": 15
                    }
            
            elif integration.integration_type == IntegrationType.VULNERABILITY:
                if query_type == "vulnerabilities":
                    return {
                        "vulnerabilities": [
                            {"id": "CVE-2021-1234", "severity": "critical", "hosts": ["host1", "host2"]},
                            {"id": "CVE-2021-5678", "severity": "high", "hosts": ["host3"]}
                        ],
                        "total": 2
                    }
            
            # Default response
            return {"status": "success", "message": f"Query {query_type} not implemented for {integration.name}"}
        
        except Exception as e:
            app_logger.error(f"Error querying integration {integration.name}: {e}", error=e)
            integration.error_message = str(e)
            raise SecurityAIException(f"Error querying integration: {str(e)}")
    
    async def execute_action(self, integration_id: str, action_type: str, action_params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an action in an integration."""
        integration = self.get_integration(integration_id)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            raise SecurityAIException(f"Integration {integration_id} not available")
        
        # Check capabilities
        capabilities = integration.config_data.get("capabilities", [])
        if IntegrationCapability.EXECUTE_ACTIONS.value not in capabilities:
            raise SecurityAIException(f"Integration {integration.name} does not support executing actions")
        
        try:
            app_logger.info(f"Executing {action_type} in {integration.name}")
            
            # In a real implementation, you would call the integration's API to execute the action
            # For now, just return a sample response
            if integration.integration_type == IntegrationType.EDR:
                if action_type == "isolate_host":
                    return {
                        "status": "success",
                        "action": "isolate_host",
                        "host": action_params.get("hostname"),
                        "timestamp": datetime.now().isoformat()
                    }
                elif action_type == "block_hash":
                    return {
                        "status": "success",
                        "action": "block_hash",
                        "hash": action_params.get("file_hash"),
                        "timestamp": datetime.now().isoformat()
                    }
            
            elif integration.integration_type == IntegrationType.SOAR:
                if action_type == "create_incident":
                    return {
                        "status": "success",
                        "action": "create_incident",
                        "incident_id": f"INC{uuid.uuid4().hex[:8]}",
                        "timestamp": datetime.now().isoformat()
                    }
                elif action_type == "update_incident":
                    return {
                        "status": "success",
                        "action": "update_incident",
                        "incident_id": action_params.get("incident_id"),
                        "timestamp": datetime.now().isoformat()
                    }
            
            # Default response
            return {"status": "success", "message": f"Action {action_type} not implemented for {integration.name}"}
        
        except Exception as e:
            app_logger.error(f"Error executing action in integration {integration.name}: {e}", error=e)
            integration.error_message = str(e)
            raise SecurityAIException(f"Error executing action: {str(e)}")


# Create singleton instance
xdr_integration_manager = XDRIntegrationManager()


# Initialize XDR integration manager
async def initialize_xdr_integrations():
    """Initialize the XDR integration manager."""
    app_logger.info("Initializing XDR integration manager")
    
    # Enable default integrations if configured
    if settings.ENABLE_SIEM_INTEGRATION:
        for integration in xdr_integration_manager.integrations.values():
            if integration.integration_type == IntegrationType.SIEM:
                xdr_integration_manager.enable_integration(integration.id)
    
    if settings.ENABLE_EDR_INTEGRATION:
        for integration in xdr_integration_manager.integrations.values():
            if integration.integration_type == IntegrationType.EDR:
                xdr_integration_manager.enable_integration(integration.id)
    
    if settings.ENABLE_SOAR_INTEGRATION:
        for integration in xdr_integration_manager.integrations.values():
            if integration.integration_type == IntegrationType.SOAR:
                xdr_integration_manager.enable_integration(integration.id)
    
    if settings.ENABLE_THREAT_INTEL_INTEGRATION:
        for integration in xdr_integration_manager.integrations.values():
            if integration.integration_type == IntegrationType.THREAT_INTEL:
                xdr_integration_manager.enable_integration(integration.id)
    
    app_logger.info("XDR integration manager initialized")


# Shutdown XDR integration manager
async def shutdown_xdr_integrations():
    """Shutdown the XDR integration manager."""
    app_logger.info("Shutting down XDR integration manager")
    
    # Disable all integrations
    for integration_id in xdr_integration_manager.integrations:
        xdr_integration_manager.disable_integration(integration_id)
    
    app_logger.info("XDR integration manager shutdown complete")


# Start periodic sync tasks
async def start_integration_sync_tasks():
    """Start periodic integration synchronization tasks."""
    app_logger.info("Starting integration sync tasks")
    
    while True:
        try:
            # Sync with each enabled integration
            for integration_id, integration in xdr_integration_manager.integrations.items():
                if integration.status == IntegrationStatus.ENABLED:
                    # Check if it's time to sync
                    sync_interval = integration.config_data.get("sync_interval", 3600)  # Default 1 hour
                    last_sync = integration.last_sync
                    
                    if last_sync is None or (datetime.now() - last_sync).total_seconds() >= sync_interval:
                        await xdr_integration_manager.ingest_from_integration(integration_id)
            
            # Wait for a minute before checking again
            await asyncio.sleep(60)
        
        except asyncio.CancelledError:
            break
        
        except Exception as e:
            app_logger.error(f"Error in integration sync task: {e}", error=e)
            await asyncio.sleep(60)  # Wait a minute before retrying
    
    app_logger.info("Integration sync tasks stopped")