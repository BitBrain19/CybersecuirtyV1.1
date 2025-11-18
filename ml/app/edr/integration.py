#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Endpoint Detection and Response (EDR) integration module.

This module provides:
- Integration with SIEM components
- Integration with SOAR workflows
- Integration with UEBA for behavioral analytics
- Integration with threat intelligence platforms
- Data enrichment and correlation
- Unified alert management
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import os

from pydantic import BaseModel, Field

from ..core.config import settings
from ..core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from ..core.monitoring import metrics_collector
from ..core.exceptions import SecurityAIException

# Import EDR components
from .agent import (
    EndpointAgent, EndpointInfo, EndpointEvent, EndpointThreatDetection,
    EndpointEventType, ThreatCategory, EndpointIsolationLevel,
    edr_agent_registry
)
from .manager import (
    EDRManager, PolicyType, PolicyAction, PolicyCondition, PolicyRule,
    Policy, EndpointGroup, ThreatHuntingQuery, ThreatHuntingResult,
    ForensicArtifactType, ForensicArtifact, edr_manager
)

# Import SOAR components
from ..soar.workflow_engine import (
    WorkflowEngine, Workflow, WorkflowStep, Action, Condition,
    Incident, IncidentSeverity, IncidentStatus, WorkflowContext,
    workflow_engine
)

# Import UEBA components
from ..ueba.behavior_analytics import (
    UEBAService, BehaviorProfiler, BehaviorAnomalyDetector,
    BehaviorEvent, BehaviorProfile, BehaviorAnomaly,
    EntityType, BehaviorCategory, ueba_service
)


class IntegrationType(Enum):
    """Types of EDR integrations."""
    SIEM = "siem"                      # Security Information and Event Management
    SOAR = "soar"                      # Security Orchestration, Automation, and Response
    UEBA = "ueba"                      # User and Entity Behavior Analytics
    TIP = "tip"                        # Threat Intelligence Platform
    CMDB = "cmdb"                      # Configuration Management Database
    IAM = "iam"                        # Identity and Access Management
    VULNERABILITY = "vulnerability"    # Vulnerability Management
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
    status: IntegrationStatus = IntegrationStatus.DISABLED
    config_data: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_sync: Optional[datetime] = None
    error_message: Optional[str] = None


class EDRIntegrationManager:
    """Manager for EDR integrations."""
    
    def __init__(self):
        self.integrations: Dict[str, IntegrationConfig] = {}
        self._lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Create default integrations
        self._create_default_integrations()
        
        app_logger.info("EDR Integration Manager initialized")
    
    def _create_default_integrations(self):
        """Create default integrations."""
        # SIEM integration
        siem_integration = IntegrationConfig(
            name="SIEM Integration",
            description="Integration with Security Information and Event Management",
            integration_type=IntegrationType.SIEM,
            config_data={
                "siem_url": getattr(settings, "SIEM_URL", "http://localhost:9200"),
                "siem_api_key": getattr(settings, "SIEM_API_KEY", ""),
                "event_types": ["endpoint_event", "threat_detection"],
                "sync_interval": getattr(settings, "SIEM_SYNC_INTERVAL", 60)  # seconds
            }
        )
        
        # SOAR integration
        soar_integration = IntegrationConfig(
            name="SOAR Integration",
            description="Integration with Security Orchestration, Automation, and Response",
            integration_type=IntegrationType.SOAR,
            config_data={
                "trigger_workflows": True,
                "incident_creation": True,
                "automated_response": True
            }
        )
        
        # UEBA integration
        ueba_integration = IntegrationConfig(
            name="UEBA Integration",
            description="Integration with User and Entity Behavior Analytics",
            integration_type=IntegrationType.UEBA,
            config_data={
                "send_events": True,
                "receive_anomalies": True,
                "risk_score_threshold": 0.7
            }
        )
        
        # Add integrations to the manager
        self.integrations[siem_integration.id] = siem_integration
        self.integrations[soar_integration.id] = soar_integration
        self.integrations[ueba_integration.id] = ueba_integration
    
    def get_integration(self, integration_id: str) -> Optional[IntegrationConfig]:
        """Get an integration by ID."""
        return self.integrations.get(integration_id)
    
    def get_integration_by_type(self, integration_type: IntegrationType) -> Optional[IntegrationConfig]:
        """Get an integration by type."""
        for integration in self.integrations.values():
            if integration.integration_type == integration_type:
                return integration
        return None
    
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
    
    async def process_endpoint_event(self, event: EndpointEvent):
        """Process an endpoint event through integrations."""
        # Process through each enabled integration
        for integration in self.integrations.values():
            if integration.status != IntegrationStatus.ENABLED:
                continue
            
            try:
                if integration.integration_type == IntegrationType.SIEM:
                    await self._process_siem_event(integration, event)
                
                elif integration.integration_type == IntegrationType.UEBA:
                    await self._process_ueba_event(integration, event)
            
            except Exception as e:
                app_logger.error(f"Error processing event through integration {integration.name}: {e}", error=e)
                integration.error_message = str(e)
    
    async def process_threat_detection(self, detection: EndpointThreatDetection):
        """Process a threat detection through integrations."""
        # Process through each enabled integration
        for integration in self.integrations.values():
            if integration.status != IntegrationStatus.ENABLED:
                continue
            
            try:
                if integration.integration_type == IntegrationType.SIEM:
                    await self._process_siem_detection(integration, detection)
                
                elif integration.integration_type == IntegrationType.SOAR:
                    await self._process_soar_detection(integration, detection)
            
            except Exception as e:
                app_logger.error(f"Error processing detection through integration {integration.name}: {e}", error=e)
                integration.error_message = str(e)
    
    async def _process_siem_event(self, integration: IntegrationConfig, event: EndpointEvent):
        """Process an endpoint event through SIEM integration."""
        # Check if event type is configured for SIEM
        event_types = integration.config_data.get("event_types", [])
        if "endpoint_event" not in event_types:
            return
        
        # In a real implementation, you would send the event to the SIEM
        # For now, just log the action
        app_logger.debug(f"Would send event {event.id} to SIEM: {event.event_type.value} on {event.hostname}")
        
        # Update last sync time
        integration.last_sync = datetime.now()
    
    async def _process_siem_detection(self, integration: IntegrationConfig, detection: EndpointThreatDetection):
        """Process a threat detection through SIEM integration."""
        # Check if detection type is configured for SIEM
        event_types = integration.config_data.get("event_types", [])
        if "threat_detection" not in event_types:
            return
        
        # In a real implementation, you would send the detection to the SIEM
        # For now, just log the action
        app_logger.debug(f"Would send detection {detection.id} to SIEM: {detection.threat_name} on {detection.hostname}")
        
        # Update last sync time
        integration.last_sync = datetime.now()
    
    async def _process_ueba_event(self, integration: IntegrationConfig, event: EndpointEvent):
        """Process an endpoint event through UEBA integration."""
        # Check if sending events is enabled
        if not integration.config_data.get("send_events", False):
            return
        
        # Convert EDR event to UEBA behavior event
        behavior_event = await self._convert_to_behavior_event(event)
        
        # Send to UEBA service
        if behavior_event:
            await ueba_service.process_behavior_event(behavior_event)
            app_logger.debug(f"Sent event {event.id} to UEBA service")
        
        # Update last sync time
        integration.last_sync = datetime.now()
    
    async def _process_soar_detection(self, integration: IntegrationConfig, detection: EndpointThreatDetection):
        """Process a threat detection through SOAR integration."""
        # Check if incident creation is enabled
        if not integration.config_data.get("incident_creation", False):
            return
        
        # Create an incident in SOAR
        incident = await self._create_soar_incident(detection)
        
        # Trigger workflows if enabled
        if integration.config_data.get("trigger_workflows", False):
            await self._trigger_soar_workflows(incident, detection)
        
        app_logger.info(f"Created SOAR incident {incident.id} for detection {detection.id}")
        
        # Update last sync time
        integration.last_sync = datetime.now()
    
    async def _convert_to_behavior_event(self, event: EndpointEvent) -> Optional[BehaviorEvent]:
        """Convert an EDR event to a UEBA behavior event."""
        # Map event type to behavior category
        category_mapping = {
            EndpointEventType.PROCESS_CREATE: BehaviorCategory.PROCESS,
            EndpointEventType.PROCESS_TERMINATE: BehaviorCategory.PROCESS,
            EndpointEventType.FILE_CREATE: BehaviorCategory.FILE,
            EndpointEventType.FILE_MODIFY: BehaviorCategory.FILE,
            EndpointEventType.FILE_DELETE: BehaviorCategory.FILE,
            EndpointEventType.REGISTRY_MODIFY: BehaviorCategory.REGISTRY,
            EndpointEventType.NETWORK_CONNECTION: BehaviorCategory.NETWORK,
            EndpointEventType.NETWORK_LISTEN: BehaviorCategory.NETWORK,
            EndpointEventType.MODULE_LOAD: BehaviorCategory.PROCESS,
            EndpointEventType.SCRIPT_EXECUTE: BehaviorCategory.PROCESS,
            EndpointEventType.USER_LOGIN: BehaviorCategory.AUTHENTICATION,
            EndpointEventType.USER_LOGOUT: BehaviorCategory.AUTHENTICATION,
            EndpointEventType.SCHEDULED_TASK: BehaviorCategory.SYSTEM,
            EndpointEventType.SERVICE_INSTALL: BehaviorCategory.SYSTEM,
            EndpointEventType.MEMORY_SCAN: BehaviorCategory.SYSTEM
        }
        
        category = category_mapping.get(event.event_type)
        if not category:
            return None
        
        # Determine entity type and ID
        entity_type = EntityType.ENDPOINT
        entity_id = event.endpoint_id
        
        if event.username:
            # If username is available, create a user behavior event
            entity_type = EntityType.USER
            entity_id = event.username
        
        # Create behavior event
        behavior_event = BehaviorEvent(
            entity_type=entity_type,
            entity_id=entity_id,
            category=category,
            activity_type=event.event_type.value,
            timestamp=event.timestamp,
            source="edr",
            source_id=event.id,
            properties={
                "endpoint_id": event.endpoint_id,
                "hostname": event.hostname,
                "process_name": event.process_name,
                "process_path": event.process_path,
                "file_path": event.file_path,
                "registry_key": event.registry_key,
                "destination_address": event.destination_address,
                "destination_port": event.destination_port
            }
        )
        
        return behavior_event
    
    async def _create_soar_incident(self, detection: EndpointThreatDetection) -> Incident:
        """Create a SOAR incident from a threat detection."""
        # Map severity
        severity_mapping = {
            AlertSeverity.LOW: IncidentSeverity.LOW,
            AlertSeverity.MEDIUM: IncidentSeverity.MEDIUM,
            AlertSeverity.HIGH: IncidentSeverity.HIGH,
            AlertSeverity.CRITICAL: IncidentSeverity.CRITICAL
        }
        
        # Create the incident
        incident = Incident(
            title=f"EDR: {detection.threat_name}",
            description=detection.description,
            severity=severity_mapping.get(detection.severity, IncidentSeverity.MEDIUM),
            status=IncidentStatus.NEW,
            source="edr",
            source_id=detection.id,
            details={
                "endpoint_id": detection.endpoint_id,
                "hostname": detection.hostname,
                "ip_address": detection.ip_address,
                "username": detection.username,
                "process_name": detection.process_name,
                "process_path": detection.process_path,
                "file_path": detection.file_path,
                "file_hash": detection.file_hash,
                "threat_category": detection.threat_category.value,
                "confidence": detection.confidence,
                "mitre_techniques": detection.mitre_techniques,
                "indicators": detection.indicators,
                "recommended_actions": detection.recommended_actions
            }
        )
        
        # Add the incident to the workflow engine
        workflow_engine.add_incident(incident)
        
        return incident
    
    async def _trigger_soar_workflows(self, incident: Incident, detection: EndpointThreatDetection):
        """Trigger SOAR workflows for an incident."""
        # Find applicable workflows based on the threat category
        applicable_workflows = []
        
        # Map threat categories to workflow types
        category_workflow_mapping = {
            ThreatCategory.MALWARE: "malware_response",
            ThreatCategory.EXPLOIT: "exploit_response",
            ThreatCategory.PERSISTENCE: "persistence_response",
            ThreatCategory.PRIVILEGE_ESCALATION: "privilege_escalation_response",
            ThreatCategory.DEFENSE_EVASION: "defense_evasion_response",
            ThreatCategory.CREDENTIAL_ACCESS: "credential_access_response",
            ThreatCategory.DISCOVERY: "discovery_response",
            ThreatCategory.LATERAL_MOVEMENT: "lateral_movement_response",
            ThreatCategory.COLLECTION: "collection_response",
            ThreatCategory.EXFILTRATION: "exfiltration_response",
            ThreatCategory.COMMAND_AND_CONTROL: "command_and_control_response",
            ThreatCategory.IMPACT: "impact_response",
            ThreatCategory.INITIAL_ACCESS: "initial_access_response",
            ThreatCategory.EXECUTION: "execution_response"
        }
        
        # Get workflow type for this threat category
        workflow_type = category_workflow_mapping.get(detection.threat_category)
        
        if workflow_type:
            # Find workflows of this type
            for workflow in workflow_engine.get_workflows():
                if workflow.workflow_type == workflow_type:
                    applicable_workflows.append(workflow)
        
        # Always include generic threat response workflow
        for workflow in workflow_engine.get_workflows():
            if workflow.workflow_type == "generic_threat_response":
                applicable_workflows.append(workflow)
        
        # Trigger each applicable workflow
        for workflow in applicable_workflows:
            await workflow_engine.trigger_workflow(workflow.id, incident.id)
            app_logger.info(f"Triggered workflow {workflow.name} for incident {incident.id}")
    
    async def sync_with_siem(self):
        """Synchronize with SIEM."""
        # Get SIEM integration
        integration = self.get_integration_by_type(IntegrationType.SIEM)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            return
        
        try:
            # In a real implementation, you would sync data with the SIEM
            # For now, just log the action
            app_logger.info(f"Synchronizing with SIEM: {integration.name}")
            
            # Update last sync time
            integration.last_sync = datetime.now()
        
        except Exception as e:
            app_logger.error(f"Error synchronizing with SIEM: {e}", error=e)
            integration.error_message = str(e)
    
    async def sync_with_ueba(self):
        """Synchronize with UEBA."""
        # Get UEBA integration
        integration = self.get_integration_by_type(IntegrationType.UEBA)
        if not integration or integration.status != IntegrationStatus.ENABLED:
            return
        
        try:
            # Check if receiving anomalies is enabled
            if integration.config_data.get("receive_anomalies", False):
                # Get anomalies from UEBA service
                risk_threshold = integration.config_data.get("risk_score_threshold", 0.7)
                anomalies = await ueba_service.get_anomalies(min_risk_score=risk_threshold)
                
                # Process each anomaly
                for anomaly in anomalies:
                    await self._process_ueba_anomaly(anomaly)
            
            # Update last sync time
            integration.last_sync = datetime.now()
            app_logger.info(f"Synchronized with UEBA: {integration.name}")
        
        except Exception as e:
            app_logger.error(f"Error synchronizing with UEBA: {e}", error=e)
            integration.error_message = str(e)
    
    async def _process_ueba_anomaly(self, anomaly: BehaviorAnomaly):
        """Process a UEBA anomaly."""
        # Map severity
        severity_mapping = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL
        }
        
        # Create alert details
        details = {
            "entity_type": anomaly.entity_type.value,
            "entity_id": anomaly.entity_id,
            "category": anomaly.category.value,
            "activity_type": anomaly.activity_type,
            "risk_score": anomaly.risk_score,
            "anomaly_factors": anomaly.anomaly_factors,
            "baseline_deviation": anomaly.baseline_deviation,
            "related_events": [event.source_id for event in anomaly.related_events]
        }
        
        # Create alert
        create_alert(
            title=f"UEBA: {anomaly.description}",
            description=f"Behavioral anomaly detected: {anomaly.description}",
            severity=severity_mapping.get(anomaly.severity, AlertSeverity.MEDIUM),
            source=f"ueba:{anomaly.entity_type.value}:{anomaly.entity_id}",
            tags={"type": "ueba", "category": anomaly.category.value},
            metadata=details
        )
        
        # If anomaly is for an endpoint, update endpoint risk score
        if anomaly.entity_type == EntityType.ENDPOINT:
            agent = edr_agent_registry.get_agent(anomaly.entity_id)
            if agent:
                agent.endpoint_info.risk_score = max(agent.endpoint_info.risk_score, anomaly.risk_score)
                app_logger.info(f"Updated risk score for endpoint {agent.hostname} to {agent.endpoint_info.risk_score}")
        
        # If anomaly severity is high or critical, create a SOAR incident
        if anomaly.severity in ["high", "critical"]:
            # Get SOAR integration
            integration = self.get_integration_by_type(IntegrationType.SOAR)
            if integration and integration.status == IntegrationStatus.ENABLED and integration.config_data.get("incident_creation", False):
                # Create incident
                incident = Incident(
                    title=f"UEBA: {anomaly.description}",
                    description=f"Behavioral anomaly detected: {anomaly.description}",
                    severity=IncidentSeverity(anomaly.severity),
                    status=IncidentStatus.NEW,
                    source="ueba",
                    source_id=anomaly.id,
                    details=details
                )
                
                # Add the incident to the workflow engine
                workflow_engine.add_incident(incident)
                
                # Trigger workflows if enabled
                if integration.config_data.get("trigger_workflows", False):
                    # Find applicable workflows
                    for workflow in workflow_engine.get_workflows():
                        if workflow.workflow_type == "ueba_anomaly_response":
                            await workflow_engine.trigger_workflow(workflow.id, incident.id)
                            app_logger.info(f"Triggered workflow {workflow.name} for UEBA anomaly incident {incident.id}")


# Create singleton instance
edr_integration_manager = EDRIntegrationManager()


# Initialize EDR integration manager
async def initialize_edr_integration():
    """Initialize the EDR integration manager."""
    app_logger.info("Initializing EDR integration manager")
    
    # Enable default integrations if configured
    if settings.ENABLE_SIEM_INTEGRATION:
        siem_integration = edr_integration_manager.get_integration_by_type(IntegrationType.SIEM)
        if siem_integration:
            edr_integration_manager.enable_integration(siem_integration.id)
    
    if settings.ENABLE_SOAR_INTEGRATION:
        soar_integration = edr_integration_manager.get_integration_by_type(IntegrationType.SOAR)
        if soar_integration:
            edr_integration_manager.enable_integration(soar_integration.id)
    
    if settings.ENABLE_UEBA_INTEGRATION:
        ueba_integration = edr_integration_manager.get_integration_by_type(IntegrationType.UEBA)
        if ueba_integration:
            edr_integration_manager.enable_integration(ueba_integration.id)
    
    app_logger.info("EDR integration manager initialized")


# Shutdown EDR integration manager
async def shutdown_edr_integration():
    """Shutdown the EDR integration manager."""
    app_logger.info("Shutting down EDR integration manager")
    
    # Disable all integrations
    for integration_id in edr_integration_manager.integrations:
        edr_integration_manager.disable_integration(integration_id)
    
    app_logger.info("EDR integration manager shutdown complete")


# Start periodic sync tasks
async def start_integration_sync_tasks():
    """Start periodic integration synchronization tasks."""
    app_logger.info("Starting integration sync tasks")
    
    while True:
        try:
            # Sync with SIEM
            await edr_integration_manager.sync_with_siem()
            
            # Sync with UEBA
            await edr_integration_manager.sync_with_ueba()
            
            # Wait for next sync interval
            await asyncio.sleep(settings.INTEGRATION_SYNC_INTERVAL)
        
        except asyncio.CancelledError:
            break
        
        except Exception as e:
            app_logger.error(f"Error in integration sync task: {e}", error=e)
            await asyncio.sleep(60)  # Wait a minute before retrying
    
    app_logger.info("Integration sync tasks stopped")