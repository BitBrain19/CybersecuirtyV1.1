#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Endpoint Detection and Response (EDR) agent module - FIXED VERSION.

Fixes Applied:
1. Added missing 'import random' 
2. Added atexit cleanup for ThreadPoolExecutor
3. Added state validation in isolate() method
4. Minimized lock scope during long operations
5. Added proper error handling throughout

This module provides:
- Endpoint monitoring and telemetry collection
- Process and file system activity monitoring
- Network connection monitoring
- Behavioral analysis and anomaly detection
- Threat detection and response
- Endpoint isolation capabilities
"""

import asyncio
import json
import time
import uuid
import atexit
import random  # FIX #1: Added missing import
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import platform
import socket
import ipaddress
import hashlib
import base64

from pydantic import BaseModel, Field

from ..core.config import settings
from ..core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from ..core.monitoring import metrics_collector
from ..core.exceptions import SecurityAIException


class EndpointEventType(Enum):
    """Types of endpoint events."""
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    REGISTRY_MODIFY = "registry_modify"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTEN = "network_listen"
    MODULE_LOAD = "module_load"
    SCRIPT_EXECUTE = "script_execute"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE_INSTALL = "service_install"
    MEMORY_SCAN = "memory_scan"


class ThreatCategory(Enum):
    """Categories of endpoint threats."""
    MALWARE = "malware"
    EXPLOIT = "exploit"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    BEHAVIORAL = "behavioral"


class EndpointIsolationLevel(Enum):
    """Levels of endpoint isolation."""
    NONE = "none"                # No isolation
    NETWORK = "network"          # Block all network communications
    PARTIAL = "partial"          # Allow only management communications
    COMPLETE = "complete"        # Complete isolation including management


class EndpointEvent(BaseModel):
    """Model for endpoint events."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    event_type: EndpointEventType
    endpoint_id: str
    hostname: str
    ip_address: Optional[str] = None
    username: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    network_protocol: Optional[str] = None
    source_address: Optional[str] = None
    source_port: Optional[int] = None
    destination_address: Optional[str] = None
    destination_port: Optional[int] = None
    module_name: Optional[str] = None
    module_path: Optional[str] = None
    script_path: Optional[str] = None
    script_content_hash: Optional[str] = None
    task_name: Optional[str] = None
    service_name: Optional[str] = None
    memory_region: Optional[str] = None
    memory_protection: Optional[str] = None
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class EndpointThreatDetection(BaseModel):
    """Model for endpoint threat detections."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    endpoint_id: str
    hostname: str
    ip_address: Optional[str] = None
    username: Optional[str] = None
    threat_name: str
    threat_category: ThreatCategory
    severity: AlertSeverity
    confidence: float  # 0.0 to 1.0
    description: str
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    network_connection: Optional[Dict[str, Any]] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    indicators: Dict[str, Any] = Field(default_factory=dict)
    recommended_actions: List[str] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class EndpointInfo(BaseModel):
    """Model for endpoint information."""
    endpoint_id: str
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    domain: Optional[str] = None
    last_seen: datetime = Field(default_factory=datetime.now)
    agent_version: Optional[str] = None
    isolation_level: EndpointIsolationLevel = EndpointIsolationLevel.NONE
    isolation_timestamp: Optional[datetime] = None
    isolation_reason: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    status: str = "online"
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class EndpointAgent:
    """EDR agent for endpoint monitoring and threat detection."""
    
    def __init__(self, endpoint_id: str = None, hostname: str = None):
        # Generate endpoint ID if not provided
        self.endpoint_id = endpoint_id or str(uuid.uuid4())
        self.hostname = hostname or socket.gethostname()
        
        # Initialize agent state
        self.running = False
        self.event_queue = asyncio.Queue()
        self.isolation_level = EndpointIsolationLevel.NONE
        self.isolation_reason = None
        self.isolation_timestamp = None
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()
        
        # FIX #2: Register cleanup handler for ThreadPoolExecutor
        atexit.register(self._cleanup_resources)
        
        # Initialize endpoint info
        self.endpoint_info = self._collect_endpoint_info()
        
        # Initialize monitoring components
        self.process_monitor = None
        self.file_monitor = None
        self.network_monitor = None
        self.registry_monitor = None
        self.memory_scanner = None
        
        # Initialize detection components
        self.behavior_analyzer = None
        self.threat_detector = None
        self.ioc_matcher = None
        
        app_logger.info(f"EDR agent initialized for endpoint {self.hostname} ({self.endpoint_id})")
    
    # FIX #2: Add resource cleanup method
    def _cleanup_resources(self):
        """Clean up thread executor and other resources."""
        try:
            if hasattr(self, 'executor') and self.executor:
                self.executor.shutdown(wait=False)
                app_logger.info(f"Cleaned up ThreadPoolExecutor for endpoint {self.endpoint_id}")
        except Exception as e:
            app_logger.error(f"Error during resource cleanup: {e}", error=e)
    
    def _collect_endpoint_info(self) -> EndpointInfo:
        """Collect information about the endpoint."""
        try:
            # Get IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            # Get OS information
            os_type = platform.system()
            os_version = platform.version()
            architecture = platform.machine()
            
            # Get domain information
            domain = None
            if os_type == "Windows":
                try:
                    import wmi
                    c = wmi.WMI()
                    for system in c.Win32_ComputerSystem():
                        domain = system.Domain
                        break
                except ImportError:
                    domain = os.environ.get("USERDOMAIN", None)
            
            # Create endpoint info
            endpoint_info = EndpointInfo(
                endpoint_id=self.endpoint_id,
                hostname=self.hostname,
                ip_address=ip_address,
                os_type=os_type,
                os_version=os_version,
                architecture=architecture,
                domain=domain,
                agent_version=getattr(settings, "VERSION", "0.0.0"),
                isolation_level=self.isolation_level
            )
            
            return endpoint_info
        
        except Exception as e:
            app_logger.error(f"Failed to collect endpoint info: {e}", error=e)
            
            # Return minimal endpoint info
            return EndpointInfo(
                endpoint_id=self.endpoint_id,
                hostname=self.hostname,
                agent_version=getattr(settings, "VERSION", "0.0.0"),
                isolation_level=self.isolation_level
            )
    
    async def start(self):
        """Start the EDR agent."""
        if self.running:
            return
        
        self.running = True
        app_logger.info(f"Starting EDR agent on {self.hostname} ({self.endpoint_id})")
        
        # Start monitoring components
        await self._start_monitoring()
        
        # Start event processing loop
        asyncio.create_task(self._process_events())
    
    async def stop(self):
        """Stop the EDR agent."""
        if not self.running:
            return
        
        self.running = False
        app_logger.info(f"Stopping EDR agent on {self.hostname} ({self.endpoint_id})")
        
        # Stop monitoring components
        await self._stop_monitoring()
    
    async def _start_monitoring(self):
        """Start all monitoring components."""
        # This is a placeholder implementation
        # In a real implementation, you would initialize and start
        # platform-specific monitoring components
        
        # For demonstration purposes, we'll simulate some events
        asyncio.create_task(self._simulate_events())
    
    async def _stop_monitoring(self):
        """Stop all monitoring components."""
        # This is a placeholder implementation
        pass
    
    async def _simulate_events(self):
        """Simulate endpoint events for demonstration purposes."""
        if not getattr(settings, "DEMO_MODE", True):
            return
        
        app_logger.info(f"Starting event simulation for {self.hostname}")
        
        # Define some sample processes and files
        processes = [
            {"name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "pid": 1000},
            {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "pid": 1500},
            {"name": "outlook.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "pid": 2000},
            {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 2500},
            {"name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 3000}
        ]
        
        files = [
            "C:\\Users\\Administrator\\Documents\\report.docx",
            "C:\\Users\\Administrator\\Downloads\\setup.exe",
            "C:\\Program Files\\Example\\config.ini",
            "C:\\Windows\\Temp\\log.txt",
            "C:\\Users\\Administrator\\AppData\\Local\\Temp\\tmp0001.exe"
        ]
        
        # Generate events at random intervals
        while self.running:
            try:
                # Wait for a random interval
                await asyncio.sleep(2.0)
                
                # Generate a random event
                event_type = random.choice(list(EndpointEventType))
                event = self._create_simulated_event(event_type, processes, files)
                
                # Add event to queue
                await self.event_queue.put(event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                app_logger.error(f"Error in event simulation: {e}", error=e)
    
    def _create_simulated_event(self, event_type: EndpointEventType, processes: List[Dict[str, Any]], files: List[str]) -> EndpointEvent:
        """Create a simulated endpoint event."""
        # Base event data
        event_data = {
            "event_type": event_type,
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "ip_address": self.endpoint_info.ip_address,
            "username": "Administrator"
        }
        
        # Add event-specific data
        if event_type in [EndpointEventType.PROCESS_CREATE, EndpointEventType.PROCESS_TERMINATE]:
            process = random.choice(processes)
            parent_process = random.choice(processes)
            
            event_data.update({
                "process_id": process["pid"],
                "process_name": process["name"],
                "process_path": process["path"],
                "parent_process_id": parent_process["pid"],
                "parent_process_name": parent_process["name"],
                "command_line": f"\"{process['path']}\" --param1 --param2"
            })
        
        elif event_type in [EndpointEventType.FILE_CREATE, EndpointEventType.FILE_MODIFY, EndpointEventType.FILE_DELETE]:
            file_path = random.choice(files)
            process = random.choice(processes)
            
            event_data.update({
                "file_path": file_path,
                "file_hash": hashlib.md5(file_path.encode()).hexdigest(),
                "process_id": process["pid"],
                "process_name": process["name"],
                "process_path": process["path"]
            })
        
        elif event_type == EndpointEventType.REGISTRY_MODIFY:
            registry_keys = [
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            ]
            
            process = random.choice(processes)
            
            event_data.update({
                "registry_key": random.choice(registry_keys),
                "registry_value": "ExampleValue",
                "process_id": process["pid"],
                "process_name": process["name"],
                "process_path": process["path"]
            })
        
        elif event_type in [EndpointEventType.NETWORK_CONNECTION, EndpointEventType.NETWORK_LISTEN]:
            process = random.choice(processes)
            
            # Generate random IP and port
            ip = f"192.168.1.{random.randint(1, 254)}"
            port = random.randint(1024, 65535)
            
            event_data.update({
                "process_id": process["pid"],
                "process_name": process["name"],
                "process_path": process["path"],
                "network_protocol": random.choice(["TCP", "UDP"]),
                "source_address": self.endpoint_info.ip_address,
                "source_port": random.randint(49152, 65535),
                "destination_address": ip,
                "destination_port": port
            })
        
        elif event_type == EndpointEventType.MODULE_LOAD:
            process = random.choice(processes)
            modules = [
                "ntdll.dll",
                "kernel32.dll",
                "user32.dll",
                "advapi32.dll",
                "ws2_32.dll"
            ]
            
            event_data.update({
                "process_id": process["pid"],
                "process_name": process["name"],
                "process_path": process["path"],
                "module_name": random.choice(modules),
                "module_path": f"C:\\Windows\\System32\\{random.choice(modules)}"
            })
        
        # Create and return the event
        return EndpointEvent(**event_data)
    
    async def _process_events(self):
        """Process events from the event queue."""
        while self.running:
            try:
                # Get event from queue
                event = await self.event_queue.get()
                
                # Process the event
                await self._analyze_event(event)
                
                # Mark task as done
                self.event_queue.task_done()
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                app_logger.error(f"Error processing event: {e}", error=e)
    
    async def _analyze_event(self, event: EndpointEvent):
        """Analyze an endpoint event for threats."""
        try:
            # Log the event
            app_logger.debug(f"Processing event: {event.event_type.value} on {event.hostname}")
            
            # Check for suspicious indicators
            suspicious = await self._check_suspicious_indicators(event)
            
            if suspicious:
                # Create a threat detection
                detection = await self._create_threat_detection(event, suspicious)
                
                # Log the detection
                app_logger.info(f"Threat detected: {detection.threat_name} on {detection.hostname}")
                
                # Create an alert
                await self._create_alert(detection)
                
                # Take response actions if configured
                if getattr(settings, "EDR_AUTO_RESPONSE_ENABLED", False):
                    await self._take_response_actions(detection)
        
        except Exception as e:
            app_logger.error(f"Error analyzing event: {e}", error=e)
    
    async def _check_suspicious_indicators(self, event: EndpointEvent) -> Dict[str, Any]:
        """Check for suspicious indicators in an event."""
        # This is a simplified implementation for demonstration purposes
        # In a real implementation, you would use more sophisticated detection logic
        
        suspicious = {}
        
        # Check for suspicious process names
        if event.process_name and event.process_name.lower() in [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "mshta.exe"
        ]:
            suspicious["suspicious_process"] = event.process_name
        
        # Check for suspicious command lines
        if event.command_line and any(keyword in event.command_line.lower() for keyword in [
            "hidden", "bypass", "encodedcommand", "base64", "downloadstring", "iex", "invoke-expression"
        ]):
            suspicious["suspicious_command"] = event.command_line
        
        # Check for suspicious file paths
        if event.file_path and any(path in event.file_path.lower() for path in [
            "\\temp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\"
        ]):
            suspicious["suspicious_file_path"] = event.file_path
        
        # Check for suspicious registry keys
        if event.registry_key and any(key in event.registry_key.lower() for key in [
            "\\run", "\\runonce", "\\shellserviceobjectdelayload", "\\winlogon"
        ]):
            suspicious["suspicious_registry"] = event.registry_key
        
        # Check for suspicious network connections
        if event.destination_address and event.destination_port in [4444, 8080, 8443, 9001, 1337]:
            suspicious["suspicious_network"] = f"{event.destination_address}:{event.destination_port}"
        
        return suspicious
    
    async def _create_threat_detection(self, event: EndpointEvent, suspicious: Dict[str, Any]) -> EndpointThreatDetection:
        """Create a threat detection from an event."""
        # Determine threat category and severity
        if "suspicious_command" in suspicious and "base64" in suspicious["suspicious_command"].lower():
            category = ThreatCategory.EXECUTION
            severity = AlertSeverity.HIGH
            name = "Suspicious PowerShell Execution"
            description = "PowerShell execution with encoded commands detected"
            techniques = ["T1059.001"]
            confidence = 0.8
        
        elif "suspicious_registry" in suspicious and "\\run" in suspicious["suspicious_registry"].lower():
            category = ThreatCategory.PERSISTENCE
            severity = AlertSeverity.MEDIUM
            name = "Registry Run Key Modification"
            description = "Modification to registry run keys detected"
            techniques = ["T1547.001"]
            confidence = 0.7
        
        elif "suspicious_network" in suspicious:
            category = ThreatCategory.COMMAND_AND_CONTROL
            severity = AlertSeverity.HIGH
            name = "Suspicious Network Connection"
            description = "Connection to suspicious port detected"
            techniques = ["T1071"]
            confidence = 0.75
        
        elif "suspicious_file_path" in suspicious:
            category = ThreatCategory.DEFENSE_EVASION
            severity = AlertSeverity.MEDIUM
            name = "Suspicious File Creation"
            description = "File created in temporary directory"
            techniques = ["T1564"]
            confidence = 0.6
        
        else:
            category = ThreatCategory.DISCOVERY
            severity = AlertSeverity.LOW
            name = "Suspicious Process Activity"
            description = "Potentially suspicious process behavior detected"
            techniques = ["T1057"]
            confidence = 0.5
        
        # Create recommended actions
        recommended_actions = [
            "Investigate process execution context",
            "Check for additional suspicious activities from the same user or endpoint",
            "Review process lineage and parent-child relationships"
        ]
        
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            recommended_actions.extend([
                "Isolate endpoint from network",
                "Collect memory and disk forensic artifacts",
                "Terminate suspicious processes"
            ])
        
        # Create detection
        detection = EndpointThreatDetection(
            endpoint_id=event.endpoint_id,
            hostname=event.hostname,
            ip_address=event.ip_address,
            username=event.username,
            threat_name=name,
            threat_category=category,
            severity=severity,
            confidence=confidence,
            description=description,
            process_id=event.process_id,
            process_name=event.process_name,
            process_path=event.process_path,
            file_path=event.file_path,
            file_hash=event.file_hash,
            mitre_techniques=techniques,
            indicators=suspicious,
            recommended_actions=recommended_actions,
            related_events=[event.id]
        )
        
        return detection
    
    async def _create_alert(self, detection: EndpointThreatDetection):
        """Create an alert from a threat detection."""
        # Create alert details
        details = {
            "endpoint_id": detection.endpoint_id,
            "hostname": detection.hostname,
            "ip_address": detection.ip_address,
            "username": detection.username,
            "process_name": detection.process_name,
            "process_path": detection.process_path,
            "indicators": detection.indicators,
            "mitre_techniques": detection.mitre_techniques,
            "confidence": detection.confidence,
            "recommended_actions": detection.recommended_actions
        }
        
        # Create the alert
        create_alert(
            title=f"EDR: {detection.threat_name}",
            description=detection.description,
            severity=detection.severity,
            source=f"edr:endpoint:{detection.endpoint_id}",
            tags={"type": "edr", "category": detection.threat_category.value},
            metadata=details
        )
        
        # Log security event
        log_security_event(
            event_type=f"edr_detection:{detection.threat_category.value}",
            severity=detection.severity.value,
            source=f"endpoint:{detection.endpoint_id}",
            message=f"EDR detection: {detection.threat_name} on {detection.hostname}",
            details=details
        )
    
    async def _take_response_actions(self, detection: EndpointThreatDetection):
        """Take automated response actions based on threat detection."""
        # This is a simplified implementation for demonstration purposes
        # In a real implementation, you would implement actual response actions
        
        app_logger.info(f"Taking response actions for {detection.threat_name} on {detection.hostname}")
        
        # For high and critical severity threats, isolate the endpoint
        if detection.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL] and getattr(settings, "EDR_AUTO_ISOLATE_ENABLED", False):
            await self.isolate(EndpointIsolationLevel.NETWORK, f"Automated response to {detection.threat_name}")
    
    # FIX #3: Add state validation before isolation
    async def isolate(self, level: EndpointIsolationLevel, reason: str):
        """Isolate the endpoint."""
        # FIX #3: Check if already isolated at this level
        if self.isolation_level == level:
            app_logger.warning(f"Endpoint {self.hostname} already isolated at level {level.value}")
            return
        
        # FIX #4: Minimize lock scope (only for state updates)
        with self._lock:
            # Update isolation state
            self.isolation_level = level
            self.isolation_reason = reason
            self.isolation_timestamp = datetime.now()
            
            # Update endpoint info
            self.endpoint_info.isolation_level = level
            self.endpoint_info.isolation_reason = reason
            self.endpoint_info.isolation_timestamp = self.isolation_timestamp
        
        app_logger.info(f"Endpoint {self.hostname} isolated at level {level.value}: {reason}")
        
        # Log security event (outside lock)
        log_security_event(
            event_type="edr_isolation",
            severity="high",
            source=f"endpoint:{self.endpoint_id}",
            message=f"Endpoint {self.hostname} isolated at level {level.value}",
            details={
                "endpoint_id": self.endpoint_id,
                "hostname": self.hostname,
                "isolation_level": level.value,
                "reason": reason,
                "timestamp": self.isolation_timestamp.isoformat()
            }
        )
        
        # In a real implementation, you would implement actual isolation
        # by configuring firewall rules, network settings, etc.
    
    async def release_isolation(self):
        """Release endpoint isolation."""
        with self._lock:
            # Update isolation state
            old_level = self.isolation_level
            self.isolation_level = EndpointIsolationLevel.NONE
            self.isolation_reason = None
            self.isolation_timestamp = None
            
            # Update endpoint info
            self.endpoint_info.isolation_level = EndpointIsolationLevel.NONE
            self.endpoint_info.isolation_reason = None
            self.endpoint_info.isolation_timestamp = None
        
        app_logger.info(f"Endpoint {self.hostname} released from isolation (was: {old_level.value})")
        
        # Log security event
        log_security_event(
            event_type="edr_isolation_release",
            severity="medium",
            source=f"endpoint:{self.endpoint_id}",
            message=f"Endpoint {self.hostname} released from isolation",
            details={
                "endpoint_id": self.endpoint_id,
                "hostname": self.hostname,
                "previous_isolation_level": old_level.value,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        # In a real implementation, you would implement actual isolation release
        # by reverting firewall rules, network settings, etc.
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the EDR agent."""
        return {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "running": self.running,
            "isolation_level": self.isolation_level.value,
            "isolation_reason": self.isolation_reason,
            "isolation_timestamp": self.isolation_timestamp.isoformat() if self.isolation_timestamp else None,
            "queue_size": self.event_queue.qsize(),
            "endpoint_info": self.endpoint_info.dict()
        }


# Create a registry of EDR agents
class EDRAgentRegistry:
    """Registry for EDR agents."""
    
    def __init__(self):
        self.agents: Dict[str, EndpointAgent] = {}
        self._lock = threading.Lock()
    
    def register_agent(self, agent: EndpointAgent):
        """Register an EDR agent."""
        with self._lock:
            self.agents[agent.endpoint_id] = agent
            app_logger.info(f"Registered EDR agent for {agent.hostname} ({agent.endpoint_id})")
    
    def unregister_agent(self, endpoint_id: str):
        """Unregister an EDR agent."""
        with self._lock:
            if endpoint_id in self.agents:
                agent = self.agents.pop(endpoint_id)
                app_logger.info(f"Unregistered EDR agent for {agent.hostname} ({agent.endpoint_id})")
    
    def get_agent(self, endpoint_id: str) -> Optional[EndpointAgent]:
        """Get an EDR agent by endpoint ID."""
        return self.agents.get(endpoint_id)
    
    def get_all_agents(self) -> List[EndpointAgent]:
        """Get all registered EDR agents."""
        return list(self.agents.values())
    
    def get_agent_by_hostname(self, hostname: str) -> Optional[EndpointAgent]:
        """Get an EDR agent by hostname."""
        for agent in self.agents.values():
            if agent.hostname.lower() == hostname.lower():
                return agent
        return None
    
    async def start_all_agents(self):
        """Start all registered EDR agents."""
        for agent in self.agents.values():
            await agent.start()
    
    async def stop_all_agents(self):
        """Stop all registered EDR agents."""
        for agent in self.agents.values():
            await agent.stop()


# Create singleton instance
edr_agent_registry = EDRAgentRegistry()


# Initialize EDR system
async def initialize_edr_system():
    """Initialize the EDR system."""
    app_logger.info("Initializing EDR system")
    
    # Create a local agent if enabled
    if getattr(settings, "EDR_LOCAL_AGENT_ENABLED", False):
        local_agent = EndpointAgent()
        edr_agent_registry.register_agent(local_agent)
        await local_agent.start()
    
    # In a real implementation, you would also set up agent registration endpoints,
    # communication channels, etc.
    
    app_logger.info("EDR system initialized")


# Shutdown EDR system
async def shutdown_edr_system():
    """Shutdown the EDR system."""
    app_logger.info("Shutting down EDR system")
    
    # Stop all agents
    await edr_agent_registry.stop_all_agents()
    
    app_logger.info("EDR system shutdown complete")
