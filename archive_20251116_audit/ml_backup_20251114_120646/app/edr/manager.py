#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Endpoint Detection and Response (EDR) manager module.

This module provides:
- Centralized management of EDR agents
- Endpoint inventory and status tracking
- Policy management and distribution
- Response action coordination
- Threat hunting capabilities
- Integration with SIEM and SOAR components
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import ipaddress
from pydantic import BaseModel, Field

from ..core.config import settings
from ..core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from ..core.monitoring import metrics_collector
from ..core.exceptions import SecurityAIException

# Import EDR agent components
from .agent import (
    EndpointAgent, EndpointInfo, EndpointEvent, EndpointThreatDetection,
    EndpointEventType, ThreatCategory, EndpointIsolationLevel,
    edr_agent_registry
)


class PolicyType(Enum):
    """Types of EDR policies."""
    MONITORING = "monitoring"          # What to monitor and collect
    DETECTION = "detection"            # Detection rules and thresholds
    RESPONSE = "response"              # Automated response actions
    ISOLATION = "isolation"            # Isolation policies
    DATA_COLLECTION = "data_collection" # What data to collect during incidents


class PolicyAction(Enum):
    """Actions that can be taken by policies."""
    ALERT = "alert"                    # Generate an alert
    ISOLATE = "isolate"                # Isolate the endpoint
    COLLECT_DATA = "collect_data"      # Collect forensic data
    TERMINATE_PROCESS = "terminate_process" # Terminate a process
    DELETE_FILE = "delete_file"        # Delete a file
    BLOCK_IP = "block_ip"              # Block an IP address
    BLOCK_DOMAIN = "block_domain"      # Block a domain
    CUSTOM_SCRIPT = "custom_script"    # Run a custom script


class PolicyCondition(Enum):
    """Conditions that can trigger policy actions."""
    EVENT_TYPE = "event_type"          # Match event type
    PROCESS_NAME = "process_name"      # Match process name
    FILE_PATH = "file_path"            # Match file path
    REGISTRY_KEY = "registry_key"      # Match registry key
    NETWORK_CONNECTION = "network_connection" # Match network connection
    THREAT_CATEGORY = "threat_category" # Match threat category
    THREAT_SEVERITY = "threat_severity" # Match threat severity
    MITRE_TECHNIQUE = "mitre_technique" # Match MITRE ATT&CK technique
    CUSTOM = "custom"                  # Custom condition


class PolicyRule(BaseModel):
    """Model for policy rules."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    enabled: bool = True
    condition_type: PolicyCondition
    condition_value: Any
    action_type: PolicyAction
    action_parameters: Dict[str, Any] = Field(default_factory=dict)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    tags: List[str] = Field(default_factory=list)


class Policy(BaseModel):
    """Model for EDR policies."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    policy_type: PolicyType
    enabled: bool = True
    rules: List[PolicyRule] = Field(default_factory=list)
    target_groups: List[str] = Field(default_factory=list)
    target_tags: List[str] = Field(default_factory=list)
    exclude_groups: List[str] = Field(default_factory=list)
    exclude_tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    version: int = 1


class EndpointGroup(BaseModel):
    """Model for endpoint groups."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    endpoints: List[str] = Field(default_factory=list)  # List of endpoint IDs
    parent_group: Optional[str] = None  # Parent group ID
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class ThreatHuntingQuery(BaseModel):
    """Model for threat hunting queries."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    query: str
    query_type: str  # SQL, Sigma, Yara, etc.
    target_data: str  # Events, Processes, Files, etc.
    created_by: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    tags: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class ThreatHuntingResult(BaseModel):
    """Model for threat hunting results."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str
    endpoint_id: str
    hostname: str
    timestamp: datetime = Field(default_factory=datetime.now)
    result_data: Dict[str, Any] = Field(default_factory=dict)
    matched_items: int
    severity: AlertSeverity = AlertSeverity.MEDIUM
    notes: Optional[str] = None


class ForensicArtifactType(Enum):
    """Types of forensic artifacts."""
    MEMORY_DUMP = "memory_dump"
    PROCESS_DUMP = "process_dump"
    FILE_CAPTURE = "file_capture"
    REGISTRY_SNAPSHOT = "registry_snapshot"
    EVENT_LOGS = "event_logs"
    NETWORK_CAPTURE = "network_capture"
    SYSTEM_INFO = "system_info"
    VOLATILE_DATA = "volatile_data"


class ForensicArtifact(BaseModel):
    """Model for forensic artifacts."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint_id: str
    hostname: str
    artifact_type: ForensicArtifactType
    artifact_name: str
    artifact_path: str
    artifact_size: int
    artifact_hash: str
    collection_timestamp: datetime = Field(default_factory=datetime.now)
    collection_reason: str
    collected_by: str
    incident_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EDRManager:
    """Manager for EDR agents and operations."""
    
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.endpoint_groups: Dict[str, EndpointGroup] = {}
        self.threat_hunting_queries: Dict[str, ThreatHuntingQuery] = {}
        self.forensic_artifacts: Dict[str, ForensicArtifact] = {}
        self.hunting_results: Dict[str, List[ThreatHuntingResult]] = {}
        
        self._lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Create default policies and groups
        self._create_default_policies()
        self._create_default_groups()
        
        app_logger.info("EDR Manager initialized")
    
    def _create_default_policies(self):
        """Create default EDR policies."""
        # Default monitoring policy
        monitoring_policy = Policy(
            name="Default Monitoring Policy",
            description="Default policy for endpoint monitoring",
            policy_type=PolicyType.MONITORING,
            rules=[
                PolicyRule(
                    name="Monitor Process Creation",
                    description="Monitor process creation events",
                    condition_type=PolicyCondition.EVENT_TYPE,
                    condition_value=EndpointEventType.PROCESS_CREATE.value,
                    action_type=PolicyAction.ALERT,
                    action_parameters={},
                    severity=AlertSeverity.LOW
                ),
                PolicyRule(
                    name="Monitor Network Connections",
                    description="Monitor network connection events",
                    condition_type=PolicyCondition.EVENT_TYPE,
                    condition_value=EndpointEventType.NETWORK_CONNECTION.value,
                    action_type=PolicyAction.ALERT,
                    action_parameters={},
                    severity=AlertSeverity.LOW
                )
            ]
        )
        
        # Default detection policy
        detection_policy = Policy(
            name="Default Detection Policy",
            description="Default policy for threat detection",
            policy_type=PolicyType.DETECTION,
            rules=[
                PolicyRule(
                    name="Detect Suspicious PowerShell",
                    description="Detect suspicious PowerShell commands",
                    condition_type=PolicyCondition.PROCESS_NAME,
                    condition_value="powershell.exe",
                    action_type=PolicyAction.ALERT,
                    action_parameters={},
                    severity=AlertSeverity.MEDIUM
                ),
                PolicyRule(
                    name="Detect Suspicious File Creation",
                    description="Detect suspicious file creation in temp directories",
                    condition_type=PolicyCondition.FILE_PATH,
                    condition_value="*\\temp\\*.exe",
                    action_type=PolicyAction.ALERT,
                    action_parameters={},
                    severity=AlertSeverity.HIGH
                )
            ]
        )
        
        # Default response policy
        response_policy = Policy(
            name="Default Response Policy",
            description="Default policy for automated response",
            policy_type=PolicyType.RESPONSE,
            rules=[
                PolicyRule(
                    name="Isolate on Critical Threat",
                    description="Isolate endpoint on critical threat detection",
                    condition_type=PolicyCondition.THREAT_SEVERITY,
                    condition_value=AlertSeverity.CRITICAL.value,
                    action_type=PolicyAction.ISOLATE,
                    action_parameters={"level": EndpointIsolationLevel.NETWORK.value},
                    severity=AlertSeverity.CRITICAL
                ),
                PolicyRule(
                    name="Collect Data on High Threat",
                    description="Collect forensic data on high threat detection",
                    condition_type=PolicyCondition.THREAT_SEVERITY,
                    condition_value=AlertSeverity.HIGH.value,
                    action_type=PolicyAction.COLLECT_DATA,
                    action_parameters={"artifacts": [ForensicArtifactType.PROCESS_DUMP.value, ForensicArtifactType.MEMORY_DUMP.value]},
                    severity=AlertSeverity.HIGH
                )
            ]
        )
        
        # Add policies to the manager
        self.policies[monitoring_policy.id] = monitoring_policy
        self.policies[detection_policy.id] = detection_policy
        self.policies[response_policy.id] = response_policy
    
    def _create_default_groups(self):
        """Create default endpoint groups."""
        # Default group for all endpoints
        all_endpoints = EndpointGroup(
            name="All Endpoints",
            description="Group containing all endpoints"
        )
        
        # Add groups to the manager
        self.endpoint_groups[all_endpoints.id] = all_endpoints
    
    def get_policies_for_endpoint(self, endpoint_id: str) -> List[Policy]:
        """Get policies applicable to an endpoint."""
        applicable_policies = []
        
        # Get endpoint info
        agent = edr_agent_registry.get_agent(endpoint_id)
        if not agent:
            return applicable_policies
        
        endpoint_info = agent.endpoint_info
        
        # Find groups containing this endpoint
        endpoint_group_ids = []
        for group_id, group in self.endpoint_groups.items():
            if endpoint_id in group.endpoints:
                endpoint_group_ids.append(group_id)
        
        # Check each policy
        for policy_id, policy in self.policies.items():
            if not policy.enabled:
                continue
            
            # Check if policy applies to this endpoint
            applies = False
            
            # Check target groups
            if policy.target_groups:
                if any(group_id in policy.target_groups for group_id in endpoint_group_ids):
                    applies = True
            
            # Check target tags
            if policy.target_tags:
                if any(tag in endpoint_info.tags for tag in policy.target_tags):
                    applies = True
            
            # If no targets specified, policy applies to all
            if not policy.target_groups and not policy.target_tags:
                applies = True
            
            # Check exclusions
            if applies:
                # Check exclude groups
                if policy.exclude_groups:
                    if any(group_id in policy.exclude_groups for group_id in endpoint_group_ids):
                        applies = False
                
                # Check exclude tags
                if policy.exclude_tags:
                    if any(tag in endpoint_info.tags for tag in policy.exclude_tags):
                        applies = False
            
            if applies:
                applicable_policies.append(policy)
        
        return applicable_policies
    
    def evaluate_policies(self, endpoint_id: str, event: EndpointEvent) -> List[PolicyRule]:
        """Evaluate policies for an endpoint event."""
        triggered_rules = []
        
        # Get applicable policies
        policies = self.get_policies_for_endpoint(endpoint_id)
        
        # Evaluate each policy
        for policy in policies:
            # Skip non-monitoring and non-detection policies for events
            if policy.policy_type not in [PolicyType.MONITORING, PolicyType.DETECTION]:
                continue
            
            # Evaluate each rule
            for rule in policy.rules:
                if not rule.enabled:
                    continue
                
                # Check if rule condition matches
                if self._evaluate_rule_condition(rule, event):
                    triggered_rules.append(rule)
        
        return triggered_rules
    
    def evaluate_threat_policies(self, endpoint_id: str, detection: EndpointThreatDetection) -> List[PolicyRule]:
        """Evaluate response policies for a threat detection."""
        triggered_rules = []
        
        # Get applicable policies
        policies = self.get_policies_for_endpoint(endpoint_id)
        
        # Evaluate each policy
        for policy in policies:
            # Only evaluate response policies
            if policy.policy_type != PolicyType.RESPONSE:
                continue
            
            # Evaluate each rule
            for rule in policy.rules:
                if not rule.enabled:
                    continue
                
                # Check if rule condition matches
                if self._evaluate_threat_rule_condition(rule, detection):
                    triggered_rules.append(rule)
        
        return triggered_rules
    
    def _evaluate_rule_condition(self, rule: PolicyRule, event: EndpointEvent) -> bool:
        """Evaluate if a rule condition matches an event."""
        condition_type = rule.condition_type
        condition_value = rule.condition_value
        
        if condition_type == PolicyCondition.EVENT_TYPE:
            return event.event_type.value == condition_value
        
        elif condition_type == PolicyCondition.PROCESS_NAME:
            if not event.process_name:
                return False
            
            # Support wildcard matching
            if "*" in condition_value:
                import fnmatch
                return fnmatch.fnmatch(event.process_name.lower(), condition_value.lower())
            else:
                return event.process_name.lower() == condition_value.lower()
        
        elif condition_type == PolicyCondition.FILE_PATH:
            if not event.file_path:
                return False
            
            # Support wildcard matching
            if "*" in condition_value:
                import fnmatch
                return fnmatch.fnmatch(event.file_path.lower(), condition_value.lower())
            else:
                return event.file_path.lower() == condition_value.lower()
        
        elif condition_type == PolicyCondition.REGISTRY_KEY:
            if not event.registry_key:
                return False
            
            # Support wildcard matching
            if "*" in condition_value:
                import fnmatch
                return fnmatch.fnmatch(event.registry_key.lower(), condition_value.lower())
            else:
                return event.registry_key.lower() == condition_value.lower()
        
        elif condition_type == PolicyCondition.NETWORK_CONNECTION:
            if not event.destination_address or not event.destination_port:
                return False
            
            # Parse condition value (format: "ip:port")
            try:
                ip, port = condition_value.split(":")
                port = int(port)
                
                # Check IP (support CIDR notation)
                ip_match = False
                if "/" in ip:
                    # CIDR notation
                    network = ipaddress.ip_network(ip)
                    ip_match = ipaddress.ip_address(event.destination_address) in network
                elif ip == "*":
                    # Any IP
                    ip_match = True
                else:
                    # Exact IP
                    ip_match = event.destination_address == ip
                
                # Check port
                port_match = False
                if port == 0:
                    # Any port
                    port_match = True
                else:
                    # Exact port
                    port_match = event.destination_port == port
                
                return ip_match and port_match
            
            except (ValueError, AttributeError):
                return False
        
        elif condition_type == PolicyCondition.CUSTOM:
            # Custom conditions would be implemented here
            # For now, return False
            return False
        
        # Default: no match
        return False
    
    def _evaluate_threat_rule_condition(self, rule: PolicyRule, detection: EndpointThreatDetection) -> bool:
        """Evaluate if a rule condition matches a threat detection."""
        condition_type = rule.condition_type
        condition_value = rule.condition_value
        
        if condition_type == PolicyCondition.THREAT_CATEGORY:
            return detection.threat_category.value == condition_value
        
        elif condition_type == PolicyCondition.THREAT_SEVERITY:
            return detection.severity.value == condition_value
        
        elif condition_type == PolicyCondition.MITRE_TECHNIQUE:
            return condition_value in detection.mitre_techniques
        
        elif condition_type == PolicyCondition.PROCESS_NAME:
            if not detection.process_name:
                return False
            
            # Support wildcard matching
            if "*" in condition_value:
                import fnmatch
                return fnmatch.fnmatch(detection.process_name.lower(), condition_value.lower())
            else:
                return detection.process_name.lower() == condition_value.lower()
        
        # Default: no match
        return False
    
    async def execute_rule_actions(self, endpoint_id: str, rules: List[PolicyRule], context: Dict[str, Any]):
        """Execute actions for triggered rules."""
        # Get endpoint agent
        agent = edr_agent_registry.get_agent(endpoint_id)
        if not agent:
            app_logger.error(f"Cannot execute rule actions: endpoint {endpoint_id} not found")
            return
        
        # Execute each rule action
        for rule in rules:
            action_type = rule.action_type
            action_params = rule.action_parameters
            
            app_logger.info(f"Executing rule action: {action_type.value} for endpoint {agent.hostname} ({endpoint_id})")
            
            try:
                if action_type == PolicyAction.ALERT:
                    await self._execute_alert_action(agent, rule, context)
                
                elif action_type == PolicyAction.ISOLATE:
                    await self._execute_isolate_action(agent, rule, context)
                
                elif action_type == PolicyAction.COLLECT_DATA:
                    await self._execute_collect_data_action(agent, rule, context)
                
                elif action_type == PolicyAction.TERMINATE_PROCESS:
                    await self._execute_terminate_process_action(agent, rule, context)
                
                elif action_type == PolicyAction.DELETE_FILE:
                    await self._execute_delete_file_action(agent, rule, context)
                
                elif action_type == PolicyAction.BLOCK_IP:
                    await self._execute_block_ip_action(agent, rule, context)
                
                elif action_type == PolicyAction.BLOCK_DOMAIN:
                    await self._execute_block_domain_action(agent, rule, context)
                
                elif action_type == PolicyAction.CUSTOM_SCRIPT:
                    await self._execute_custom_script_action(agent, rule, context)
            
            except Exception as e:
                app_logger.error(f"Error executing rule action {action_type.value}: {e}", error=e)
    
    async def _execute_alert_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute alert action."""
        # Extract event or detection from context
        event = context.get("event")
        detection = context.get("detection")
        
        if detection:
            # Alert already created for detections
            return
        
        elif event:
            # Create alert from event
            details = {
                "endpoint_id": agent.endpoint_id,
                "hostname": agent.hostname,
                "event_type": event.event_type.value,
                "process_name": event.process_name,
                "process_path": event.process_path,
                "file_path": event.file_path,
                "registry_key": event.registry_key,
                "network_connection": event.destination_address and event.destination_port and f"{event.destination_address}:{event.destination_port}" or None,
                "rule_name": rule.name,
                "rule_id": rule.id
            }
            
            create_alert(
                title=f"EDR Policy Alert: {rule.name}",
                description=f"EDR policy rule triggered: {rule.description}",
                severity=rule.severity,
                source=f"edr:policy:{rule.id}",
                tags={"type": "edr_policy"},
                metadata=details
            )
    
    async def _execute_isolate_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute isolate action."""
        # Get isolation level from parameters
        level_str = rule.action_parameters.get("level", EndpointIsolationLevel.NETWORK.value)
        level = EndpointIsolationLevel(level_str)
        
        # Isolate the endpoint
        reason = f"Automated response from policy rule: {rule.name}"
        await agent.isolate(level, reason)
    
    async def _execute_collect_data_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute collect data action."""
        # Get artifact types from parameters
        artifact_types = rule.action_parameters.get("artifacts", [])
        
        # In a real implementation, you would collect the specified artifacts
        # For now, just log the action
        app_logger.info(f"Would collect artifacts {artifact_types} from endpoint {agent.hostname}")
        
        # Create a simulated forensic artifact
        for artifact_type_str in artifact_types:
            try:
                artifact_type = ForensicArtifactType(artifact_type_str)
                
                # Create a simulated artifact
                artifact = ForensicArtifact(
                    endpoint_id=agent.endpoint_id,
                    hostname=agent.hostname,
                    artifact_type=artifact_type,
                    artifact_name=f"{artifact_type.value}_{int(time.time())}",
                    artifact_path=f"/artifacts/{agent.endpoint_id}/{artifact_type.value}_{int(time.time())}",
                    artifact_size=1024 * 1024,  # 1 MB
                    artifact_hash="simulated_hash_value",
                    collection_reason=f"Automated collection from policy rule: {rule.name}",
                    collected_by="system"
                )
                
                # Store the artifact
                self.forensic_artifacts[artifact.id] = artifact
                
                app_logger.info(f"Collected forensic artifact: {artifact.artifact_name} from {agent.hostname}")
            
            except ValueError:
                app_logger.error(f"Invalid artifact type: {artifact_type_str}")
    
    async def _execute_terminate_process_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute terminate process action."""
        # Get process ID from context or parameters
        process_id = None
        
        # Try to get process ID from event
        event = context.get("event")
        if event and event.process_id:
            process_id = event.process_id
        
        # Try to get process ID from detection
        detection = context.get("detection")
        if detection and detection.process_id:
            process_id = detection.process_id
        
        # Try to get process ID from parameters
        if not process_id:
            process_id = rule.action_parameters.get("process_id")
        
        if not process_id:
            app_logger.error(f"Cannot terminate process: no process ID provided")
            return
        
        # In a real implementation, you would terminate the process
        # For now, just log the action
        app_logger.info(f"Would terminate process {process_id} on endpoint {agent.hostname}")
    
    async def _execute_delete_file_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute delete file action."""
        # Get file path from context or parameters
        file_path = None
        
        # Try to get file path from event
        event = context.get("event")
        if event and event.file_path:
            file_path = event.file_path
        
        # Try to get file path from detection
        detection = context.get("detection")
        if detection and detection.file_path:
            file_path = detection.file_path
        
        # Try to get file path from parameters
        if not file_path:
            file_path = rule.action_parameters.get("file_path")
        
        if not file_path:
            app_logger.error(f"Cannot delete file: no file path provided")
            return
        
        # In a real implementation, you would delete the file
        # For now, just log the action
        app_logger.info(f"Would delete file {file_path} on endpoint {agent.hostname}")
    
    async def _execute_block_ip_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute block IP action."""
        # Get IP address from context or parameters
        ip_address = None
        
        # Try to get IP address from event
        event = context.get("event")
        if event and event.destination_address:
            ip_address = event.destination_address
        
        # Try to get IP address from detection
        detection = context.get("detection")
        if detection and detection.network_connection and "destination_address" in detection.network_connection:
            ip_address = detection.network_connection["destination_address"]
        
        # Try to get IP address from parameters
        if not ip_address:
            ip_address = rule.action_parameters.get("ip_address")
        
        if not ip_address:
            app_logger.error(f"Cannot block IP: no IP address provided")
            return
        
        # In a real implementation, you would block the IP
        # For now, just log the action
        app_logger.info(f"Would block IP {ip_address} on endpoint {agent.hostname}")
    
    async def _execute_block_domain_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute block domain action."""
        # Get domain from parameters
        domain = rule.action_parameters.get("domain")
        
        if not domain:
            app_logger.error(f"Cannot block domain: no domain provided")
            return
        
        # In a real implementation, you would block the domain
        # For now, just log the action
        app_logger.info(f"Would block domain {domain} on endpoint {agent.hostname}")
    
    async def _execute_custom_script_action(self, agent: EndpointAgent, rule: PolicyRule, context: Dict[str, Any]):
        """Execute custom script action."""
        # Get script from parameters
        script = rule.action_parameters.get("script")
        
        if not script:
            app_logger.error(f"Cannot execute custom script: no script provided")
            return
        
        # In a real implementation, you would execute the script
        # For now, just log the action
        app_logger.info(f"Would execute custom script on endpoint {agent.hostname}")
    
    async def run_threat_hunting_query(self, query_id: str, target_endpoints: Optional[List[str]] = None) -> List[ThreatHuntingResult]:
        """Run a threat hunting query across endpoints."""
        # Get the query
        query = self.threat_hunting_queries.get(query_id)
        if not query:
            raise SecurityAIException(f"Threat hunting query {query_id} not found")
        
        # Get target endpoints
        if target_endpoints is None:
            # Run on all endpoints
            target_endpoints = [agent.endpoint_id for agent in edr_agent_registry.get_all_agents()]
        
        # Run the query on each endpoint
        results = []
        for endpoint_id in target_endpoints:
            agent = edr_agent_registry.get_agent(endpoint_id)
            if not agent:
                app_logger.warning(f"Endpoint {endpoint_id} not found, skipping threat hunting query")
                continue
            
            # In a real implementation, you would run the query on the endpoint
            # For now, create a simulated result
            result = await self._simulate_threat_hunting_result(query, agent)
            results.append(result)
            
            # Store the result
            if query_id not in self.hunting_results:
                self.hunting_results[query_id] = []
            
            self.hunting_results[query_id].append(result)
        
        return results
    
    async def _simulate_threat_hunting_result(self, query: ThreatHuntingQuery, agent: EndpointAgent) -> ThreatHuntingResult:
        """Simulate a threat hunting result."""
        import random
        
        # Simulate matched items
        matched_items = random.randint(0, 10)
        
        # Create result data
        result_data = {}
        if matched_items > 0:
            result_data = {
                "matches": [
                    {
                        "process_name": random.choice(["svchost.exe", "powershell.exe", "cmd.exe", "explorer.exe"]),
                        "process_id": random.randint(1000, 5000),
                        "user": "Administrator",
                        "command_line": "example command line",
                        "start_time": (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat()
                    } for _ in range(min(matched_items, 5))
                ]
            }
        
        # Determine severity based on matched items
        severity = AlertSeverity.LOW
        if matched_items > 5:
            severity = AlertSeverity.HIGH
        elif matched_items > 0:
            severity = AlertSeverity.MEDIUM
        
        # Create the result
        result = ThreatHuntingResult(
            query_id=query.id,
            endpoint_id=agent.endpoint_id,
            hostname=agent.hostname,
            result_data=result_data,
            matched_items=matched_items,
            severity=severity
        )
        
        return result
    
    def add_endpoint_to_group(self, endpoint_id: str, group_id: str):
        """Add an endpoint to a group."""
        # Check if group exists
        if group_id not in self.endpoint_groups:
            raise SecurityAIException(f"Endpoint group {group_id} not found")
        
        # Check if endpoint exists
        if not edr_agent_registry.get_agent(endpoint_id):
            raise SecurityAIException(f"Endpoint {endpoint_id} not found")
        
        # Add endpoint to group
        group = self.endpoint_groups[group_id]
        if endpoint_id not in group.endpoints:
            group.endpoints.append(endpoint_id)
            group.updated_at = datetime.now()
            app_logger.info(f"Added endpoint {endpoint_id} to group {group.name} ({group_id})")
    
    def remove_endpoint_from_group(self, endpoint_id: str, group_id: str):
        """Remove an endpoint from a group."""
        # Check if group exists
        if group_id not in self.endpoint_groups:
            raise SecurityAIException(f"Endpoint group {group_id} not found")
        
        # Remove endpoint from group
        group = self.endpoint_groups[group_id]
        if endpoint_id in group.endpoints:
            group.endpoints.remove(endpoint_id)
            group.updated_at = datetime.now()
            app_logger.info(f"Removed endpoint {endpoint_id} from group {group.name} ({group_id})")
    
    def create_endpoint_group(self, name: str, description: str, parent_group_id: Optional[str] = None) -> EndpointGroup:
        """Create a new endpoint group."""
        # Check if parent group exists
        if parent_group_id and parent_group_id not in self.endpoint_groups:
            raise SecurityAIException(f"Parent group {parent_group_id} not found")
        
        # Create the group
        group = EndpointGroup(
            name=name,
            description=description,
            parent_group=parent_group_id
        )
        
        # Add to manager
        self.endpoint_groups[group.id] = group
        app_logger.info(f"Created endpoint group: {name} ({group.id})")
        
        return group
    
    def create_policy(self, name: str, description: str, policy_type: PolicyType) -> Policy:
        """Create a new policy."""
        # Create the policy
        policy = Policy(
            name=name,
            description=description,
            policy_type=policy_type
        )
        
        # Add to manager
        self.policies[policy.id] = policy
        app_logger.info(f"Created policy: {name} ({policy.id})")
        
        return policy
    
    def add_rule_to_policy(self, policy_id: str, rule: PolicyRule):
        """Add a rule to a policy."""
        # Check if policy exists
        if policy_id not in self.policies:
            raise SecurityAIException(f"Policy {policy_id} not found")
        
        # Add rule to policy
        policy = self.policies[policy_id]
        policy.rules.append(rule)
        policy.updated_at = datetime.now()
        policy.version += 1
        app_logger.info(f"Added rule {rule.name} to policy {policy.name} ({policy_id})")
    
    def create_threat_hunting_query(self, name: str, description: str, query: str, query_type: str, target_data: str, created_by: str) -> ThreatHuntingQuery:
        """Create a new threat hunting query."""
        # Create the query
        hunting_query = ThreatHuntingQuery(
            name=name,
            description=description,
            query=query,
            query_type=query_type,
            target_data=target_data,
            created_by=created_by
        )
        
        # Add to manager
        self.threat_hunting_queries[hunting_query.id] = hunting_query
        app_logger.info(f"Created threat hunting query: {name} ({hunting_query.id})")
        
        return hunting_query
    
    def get_forensic_artifacts_for_endpoint(self, endpoint_id: str) -> List[ForensicArtifact]:
        """Get forensic artifacts for an endpoint."""
        return [artifact for artifact in self.forensic_artifacts.values() if artifact.endpoint_id == endpoint_id]
    
    def get_threat_hunting_results_for_query(self, query_id: str) -> List[ThreatHuntingResult]:
        """Get threat hunting results for a query."""
        return self.hunting_results.get(query_id, [])
    
    def get_endpoint_status_summary(self) -> Dict[str, Any]:
        """Get a summary of endpoint status."""
        agents = edr_agent_registry.get_all_agents()
        
        # Count endpoints by status
        status_counts = {}
        for agent in agents:
            status = agent.endpoint_info.status
            if status not in status_counts:
                status_counts[status] = 0
            status_counts[status] += 1
        
        # Count endpoints by isolation level
        isolation_counts = {}
        for agent in agents:
            level = agent.endpoint_info.isolation_level.value
            if level not in isolation_counts:
                isolation_counts[level] = 0
            isolation_counts[level] += 1
        
        # Count endpoints by OS type
        os_counts = {}
        for agent in agents:
            os_type = agent.endpoint_info.os_type or "unknown"
            if os_type not in os_counts:
                os_counts[os_type] = 0
            os_counts[os_type] += 1
        
        return {
            "total_endpoints": len(agents),
            "status_counts": status_counts,
            "isolation_counts": isolation_counts,
            "os_counts": os_counts
        }


# Create singleton instance
edr_manager = EDRManager()


# Initialize EDR manager
async def initialize_edr_manager():
    """Initialize the EDR manager."""
    app_logger.info("Initializing EDR manager")
    
    # In a real implementation, you would load policies, groups, etc. from storage
    
    app_logger.info("EDR manager initialized")


# Shutdown EDR manager
async def shutdown_edr_manager():
    """Shutdown the EDR manager."""
    app_logger.info("Shutting down EDR manager")
    
    # In a real implementation, you would save policies, groups, etc. to storage
    
    app_logger.info("EDR manager shutdown complete")