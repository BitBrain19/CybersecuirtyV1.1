#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extended Detection and Response (XDR) platform module.

This module provides:
- Unified security data collection and normalization
- Cross-component correlation and analysis
- Integrated threat detection across multiple security domains
- Coordinated response capabilities
- Centralized visibility and management
- Advanced threat hunting capabilities
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from datetime import datetime, timedelta
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

# Import SIEM components
# Optional SIEM components; not required for minimal training script
try:
    from ..siem.log_collector import LogCollector, LogSource, LogFormat
    from ..siem.log_parser import LogParser, ParsedLog
    from ..siem.alert_manager import AlertManager, Alert
except ImportError:
    LogCollector = LogSource = LogFormat = None
    LogParser = ParsedLog = None
    AlertManager = Alert = None

# Import UEBA components
from ..ueba.behavior_analytics import (
    UEBAService, BehaviorProfiler, BehaviorAnomalyDetector,
    BehaviorEvent, BehaviorProfile, BehaviorAnomaly,
    EntityType, BehaviorCategory, ueba_service
)

# Import SOAR components
from ..soar.workflow_engine import (
    WorkflowEngine, Workflow, WorkflowStep, Action, Condition,
    Incident, IncidentSeverity, IncidentStatus, WorkflowContext,
    workflow_engine
)

# Import EDR components
from ..edr.agent import (
    EndpointAgent, EndpointInfo, EndpointEvent, EndpointThreatDetection,
    EndpointEventType, ThreatCategory, EndpointIsolationLevel,
    edr_agent_registry
)
from ..edr.manager import (
    EDRManager, PolicyType, PolicyAction, PolicyCondition, PolicyRule,
    Policy, EndpointGroup, ThreatHuntingQuery, ThreatHuntingResult,
    ForensicArtifactType, ForensicArtifact, edr_manager
)
from ..edr.integration import (
    EDRIntegrationManager, IntegrationType, IntegrationStatus,
    IntegrationConfig, edr_integration_manager
)

# Import ML components
# Optional streaming detector components; unused in minimal training script
try:
    from ..streaming.real_time_detector import (
        RealTimeThreatDetector, ThreatDetectionResult, StreamEvent,
        StreamEventType, ThreatLevel, StreamAnalytics, AdaptiveThreatScorer
    )
except ImportError:
    RealTimeThreatDetector = ThreatDetectionResult = StreamEvent = None
    StreamEventType = ThreatLevel = StreamAnalytics = AdaptiveThreatScorer = None


class DataSourceType(Enum):
    """Types of data sources for XDR."""
    SIEM = "siem"                  # Security Information and Event Management
    EDR = "edr"                    # Endpoint Detection and Response
    UEBA = "ueba"                  # User and Entity Behavior Analytics
    NETWORK = "network"            # Network security (firewalls, IDS/IPS, etc.)
    CLOUD = "cloud"                # Cloud security (AWS, Azure, GCP, etc.)
    EMAIL = "email"                # Email security
    IDENTITY = "identity"          # Identity and access management
    THREAT_INTEL = "threat_intel"  # Threat intelligence
    VULNERABILITY = "vulnerability" # Vulnerability management


class CorrelationRuleType(Enum):
    """Types of correlation rules for XDR."""
    SEQUENCE = "sequence"          # Sequence of events
    THRESHOLD = "threshold"        # Threshold-based correlation
    PATTERN = "pattern"            # Pattern-based correlation
    ANOMALY = "anomaly"            # Anomaly-based correlation
    BEHAVIOR = "behavior"          # Behavior-based correlation
    THREAT_INTEL = "threat_intel"  # Threat intelligence-based correlation


class XDREvent(BaseModel):
    """Unified XDR event model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_type: DataSourceType
    source_id: str
    source_name: str
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.now)
    severity: str = "medium"
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    processed: bool = False
    correlated: bool = False
    enriched: bool = False


class XDRAlert(BaseModel):
    """Unified XDR alert model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: str
    status: str = "new"
    source_type: DataSourceType
    source_id: str
    source_name: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    assigned_to: Optional[str] = None
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    user_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)


class CorrelationRule(BaseModel):
    """XDR correlation rule model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    rule_type: CorrelationRuleType
    enabled: bool = True
    severity: str = "medium"
    data_sources: List[DataSourceType] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    time_window: int = 3600  # seconds
    alert_template: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0


class ThreatHunt(BaseModel):
    """XDR threat hunt model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    query: str
    data_sources: List[DataSourceType] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    last_run: Optional[datetime] = None
    results: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "draft"  # draft, active, completed, failed


class XDRPlatform:
    """Extended Detection and Response (XDR) platform."""
    
    def __init__(self):
        self.events: Dict[str, XDREvent] = {}
        self.alerts: Dict[str, XDRAlert] = {}
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        self.threat_hunts: Dict[str, ThreatHunt] = {}
        
        self._event_queue = asyncio.Queue()
        self._correlation_queue = asyncio.Queue()
        self._alert_queue = asyncio.Queue()
        
        self._lock = threading.Lock()
        self._running = False
        self._tasks = []
        
        # Create default correlation rules
        self._create_default_correlation_rules()
        
        app_logger.info("XDR Platform initialized")
    
    def _create_default_correlation_rules(self):
        """Create default correlation rules."""
        # Lateral movement detection rule
        lateral_movement_rule = CorrelationRule(
            name="Lateral Movement Detection",
            description="Detects potential lateral movement by correlating authentication events across multiple systems",
            rule_type=CorrelationRuleType.SEQUENCE,
            severity="high",
            data_sources=[DataSourceType.SIEM, DataSourceType.EDR, DataSourceType.IDENTITY],
            conditions={
                "sequence": [
                    {"event_type": "authentication", "status": "success"},
                    {"event_type": "network_connection", "direction": "outbound"},
                    {"event_type": "authentication", "status": "success", "different_host": True}
                ],
                "timeframe": 1800  # 30 minutes
            },
            alert_template={
                "title": "Potential Lateral Movement Detected",
                "description": "Potential lateral movement detected from {source_host} to {destination_host} by user {username}",
                "mitre_techniques": ["T1021", "T1078"]
            }
        )
        
        # Privilege escalation rule
        privilege_escalation_rule = CorrelationRule(
            name="Privilege Escalation Detection",
            description="Detects potential privilege escalation by correlating process and user permission changes",
            rule_type=CorrelationRuleType.PATTERN,
            severity="high",
            data_sources=[DataSourceType.EDR, DataSourceType.SIEM],
            conditions={
                "patterns": [
                    {"event_type": "process_create", "process_name": ["whoami", "net.exe", "runas.exe"]},
                    {"event_type": "user_permission_change"},
                    {"event_type": "process_create", "elevated_privileges": True}
                ],
                "timeframe": 600  # 10 minutes
            },
            alert_template={
                "title": "Potential Privilege Escalation Detected",
                "description": "Potential privilege escalation detected on {hostname} by process {process_name}",
                "mitre_techniques": ["T1068", "T1548"]
            }
        )
        
        # Data exfiltration rule
        data_exfiltration_rule = CorrelationRule(
            name="Data Exfiltration Detection",
            description="Detects potential data exfiltration by correlating file access and network traffic",
            rule_type=CorrelationRuleType.THRESHOLD,
            severity="critical",
            data_sources=[DataSourceType.EDR, DataSourceType.NETWORK, DataSourceType.UEBA],
            conditions={
                "thresholds": [
                    {"event_type": "file_access", "file_type": ["document", "database", "archive"], "count": 10},
                    {"event_type": "network_connection", "direction": "outbound", "bytes_sent": 10000000}  # 10MB
                ],
                "timeframe": 3600  # 1 hour
            },
            alert_template={
                "title": "Potential Data Exfiltration Detected",
                "description": "Potential data exfiltration detected from {hostname} to {destination_address}",
                "mitre_techniques": ["T1048", "T1567"]
            }
        )
        
        # Multi-stage malware rule
        malware_rule = CorrelationRule(
            name="Multi-Stage Malware Detection",
            description="Detects multi-stage malware by correlating suspicious download, file creation, and process execution",
            rule_type=CorrelationRuleType.SEQUENCE,
            severity="critical",
            data_sources=[DataSourceType.EDR, DataSourceType.NETWORK, DataSourceType.SIEM],
            conditions={
                "sequence": [
                    {"event_type": "network_connection", "destination_reputation": "suspicious"},
                    {"event_type": "file_create", "file_type": "executable"},
                    {"event_type": "process_create", "process_reputation": "unknown"}
                ],
                "timeframe": 1800  # 30 minutes
            },
            alert_template={
                "title": "Multi-Stage Malware Detected",
                "description": "Multi-stage malware detected on {hostname} with suspicious download from {destination_address}",
                "mitre_techniques": ["T1105", "T1204"]
            }
        )
        
        # Anomalous user behavior rule
        user_anomaly_rule = CorrelationRule(
            name="Anomalous User Behavior Detection",
            description="Detects anomalous user behavior by correlating UEBA anomalies with EDR events",
            rule_type=CorrelationRuleType.ANOMALY,
            severity="high",
            data_sources=[DataSourceType.UEBA, DataSourceType.EDR, DataSourceType.IDENTITY],
            conditions={
                "anomalies": [
                    {"entity_type": "user", "risk_score": 0.7},
                    {"event_type": "authentication", "time_of_day": "unusual"},
                    {"event_type": "process_create", "process_name": "unusual"}
                ],
                "timeframe": 7200  # 2 hours
            },
            alert_template={
                "title": "Anomalous User Behavior Detected",
                "description": "Anomalous behavior detected for user {username} on {hostname}",
                "mitre_techniques": ["T1078", "T1204"]
            }
        )
        
        # Add rules to the platform
        self.correlation_rules[lateral_movement_rule.id] = lateral_movement_rule
        self.correlation_rules[privilege_escalation_rule.id] = privilege_escalation_rule
        self.correlation_rules[data_exfiltration_rule.id] = data_exfiltration_rule
        self.correlation_rules[malware_rule.id] = malware_rule
        self.correlation_rules[user_anomaly_rule.id] = user_anomaly_rule
    
    async def start(self):
        """Start the XDR platform."""
        if self._running:
            return
        
        self._running = True
        
        # Start event processing tasks
        self._tasks = [
            asyncio.create_task(self._process_events()),
            asyncio.create_task(self._correlate_events()),
            asyncio.create_task(self._process_alerts())
        ]
        
        app_logger.info("XDR Platform started")
    
    async def stop(self):
        """Stop the XDR platform."""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks = []
        
        app_logger.info("XDR Platform stopped")
    
    async def ingest_siem_alert(self, alert: Alert):
        """Ingest a SIEM alert."""
        # Convert SIEM alert to XDR event
        event = XDREvent(
            source_type=DataSourceType.SIEM,
            source_id=alert.id,
            source_name="siem",
            event_type="alert",
            timestamp=alert.timestamp,
            severity=alert.severity,
            hostname=alert.hostname,
            ip_address=alert.source_ip,
            user_id=alert.username,
            data={
                "title": alert.title,
                "description": alert.description,
                "source": alert.source,
                "event_type": alert.event_type,
                "details": alert.details
            }
        )
        
        # Add event to queue
        await self._event_queue.put(event)
        
        app_logger.debug(f"Ingested SIEM alert: {alert.id}")
    
    async def ingest_edr_event(self, event: EndpointEvent):
        """Ingest an EDR event."""
        # Convert EDR event to XDR event
        xdr_event = XDREvent(
            source_type=DataSourceType.EDR,
            source_id=event.id,
            source_name="edr",
            event_type=event.event_type.value,
            timestamp=event.timestamp,
            severity="medium",  # Default severity
            hostname=event.hostname,
            ip_address=event.ip_address,
            user_id=event.username,
            entity_id=event.endpoint_id,
            entity_type="endpoint",
            data={
                "process_name": event.process_name,
                "process_path": event.process_path,
                "process_id": event.process_id,
                "parent_process_id": event.parent_process_id,
                "file_path": event.file_path,
                "registry_key": event.registry_key,
                "destination_address": event.destination_address,
                "destination_port": event.destination_port,
                "command_line": event.command_line
            }
        )
        
        # Add event to queue
        await self._event_queue.put(xdr_event)
        
        app_logger.debug(f"Ingested EDR event: {event.id}")
    
    async def ingest_edr_detection(self, detection: EndpointThreatDetection):
        """Ingest an EDR threat detection."""
        # Map severity
        severity_mapping = {
            AlertSeverity.LOW: "low",
            AlertSeverity.MEDIUM: "medium",
            AlertSeverity.HIGH: "high",
            AlertSeverity.CRITICAL: "critical"
        }
        
        # Convert EDR detection to XDR event
        xdr_event = XDREvent(
            source_type=DataSourceType.EDR,
            source_id=detection.id,
            source_name="edr",
            event_type="threat_detection",
            timestamp=detection.timestamp,
            severity=severity_mapping.get(detection.severity, "medium"),
            hostname=detection.hostname,
            ip_address=detection.ip_address,
            user_id=detection.username,
            entity_id=detection.endpoint_id,
            entity_type="endpoint",
            data={
                "threat_name": detection.threat_name,
                "description": detection.description,
                "threat_category": detection.threat_category.value,
                "confidence": detection.confidence,
                "process_name": detection.process_name,
                "process_path": detection.process_path,
                "file_path": detection.file_path,
                "file_hash": detection.file_hash,
                "mitre_techniques": detection.mitre_techniques,
                "indicators": detection.indicators,
                "recommended_actions": detection.recommended_actions
            }
        )
        
        # Add event to queue
        await self._event_queue.put(xdr_event)
        
        # Also create an XDR alert directly
        alert = XDRAlert(
            title=f"EDR: {detection.threat_name}",
            description=detection.description,
            severity=severity_mapping.get(detection.severity, "medium"),
            source_type=DataSourceType.EDR,
            source_id=detection.id,
            source_name="edr",
            hostname=detection.hostname,
            ip_address=detection.ip_address,
            user_id=detection.username,
            entity_id=detection.endpoint_id,
            entity_type="endpoint",
            mitre_techniques=detection.mitre_techniques,
            related_events=[xdr_event.id],
            data={
                "threat_category": detection.threat_category.value,
                "confidence": detection.confidence,
                "process_name": detection.process_name,
                "process_path": detection.process_path,
                "file_path": detection.file_path,
                "file_hash": detection.file_hash,
                "indicators": detection.indicators,
                "recommended_actions": detection.recommended_actions
            }
        )
        
        # Add alert to queue
        await self._alert_queue.put(alert)
        
        app_logger.debug(f"Ingested EDR detection: {detection.id}")
    
    async def ingest_ueba_anomaly(self, anomaly: BehaviorAnomaly):
        """Ingest a UEBA anomaly."""
        # Map severity
        severity_mapping = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical"
        }
        
        # Convert UEBA anomaly to XDR event
        xdr_event = XDREvent(
            source_type=DataSourceType.UEBA,
            source_id=anomaly.id,
            source_name="ueba",
            event_type="behavior_anomaly",
            timestamp=anomaly.timestamp,
            severity=severity_mapping.get(anomaly.severity, "medium"),
            entity_id=anomaly.entity_id,
            entity_type=anomaly.entity_type.value,
            data={
                "description": anomaly.description,
                "category": anomaly.category.value,
                "activity_type": anomaly.activity_type,
                "risk_score": anomaly.risk_score,
                "anomaly_factors": anomaly.anomaly_factors,
                "baseline_deviation": anomaly.baseline_deviation,
                "related_events": [event.source_id for event in anomaly.related_events]
            }
        )
        
        # Add event to queue
        await self._event_queue.put(xdr_event)
        
        # For high and critical anomalies, also create an XDR alert directly
        if anomaly.severity in ["high", "critical"]:
            alert = XDRAlert(
                title=f"UEBA: {anomaly.description}",
                description=f"Behavioral anomaly detected: {anomaly.description}",
                severity=severity_mapping.get(anomaly.severity, "medium"),
                source_type=DataSourceType.UEBA,
                source_id=anomaly.id,
                source_name="ueba",
                entity_id=anomaly.entity_id,
                entity_type=anomaly.entity_type.value,
                related_events=[xdr_event.id],
                data={
                    "category": anomaly.category.value,
                    "activity_type": anomaly.activity_type,
                    "risk_score": anomaly.risk_score,
                    "anomaly_factors": anomaly.anomaly_factors,
                    "baseline_deviation": anomaly.baseline_deviation,
                    "related_events": [event.source_id for event in anomaly.related_events]
                }
            )
            
            # Add alert to queue
            await self._alert_queue.put(alert)
        
        app_logger.debug(f"Ingested UEBA anomaly: {anomaly.id}")
    
    async def ingest_threat_intel(self, intel_data: Dict[str, Any]):
        """Ingest threat intelligence data."""
        # Convert threat intel to XDR event
        event = XDREvent(
            source_type=DataSourceType.THREAT_INTEL,
            source_id=intel_data.get("id", str(uuid.uuid4())),
            source_name=intel_data.get("source", "threat_intel"),
            event_type="threat_intel",
            timestamp=datetime.now(),
            severity=intel_data.get("severity", "medium"),
            data=intel_data
        )
        
        # Add event to queue
        await self._event_queue.put(event)
        
        app_logger.debug(f"Ingested threat intelligence: {event.source_id}")
    
    async def _process_events(self):
        """Process events from the event queue."""
        while self._running:
            try:
                # Get event from queue
                event = await self._event_queue.get()
                
                # Store event
                with self._lock:
                    self.events[event.id] = event
                
                # Enrich event
                await self._enrich_event(event)
                
                # Add to correlation queue
                await self._correlation_queue.put(event)
                
                # Mark as processed
                event.processed = True
                
                # Mark task as done
                self._event_queue.task_done()
                
                app_logger.debug(f"Processed event: {event.id}")
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                app_logger.error(f"Error processing event: {e}", error=e)
    
    async def _enrich_event(self, event: XDREvent):
        """Enrich an event with additional data."""
        try:
            # Enrich with threat intelligence
            if event.source_type != DataSourceType.THREAT_INTEL:
                # In a real implementation, you would query threat intelligence platforms
                # For now, just mark as enriched
                pass
            
            # Enrich with asset information
            if event.hostname:
                # In a real implementation, you would query CMDB or asset database
                # For now, just mark as enriched
                pass
            
            # Enrich with user information
            if event.user_id:
                # In a real implementation, you would query IAM or user database
                # For now, just mark as enriched
                pass
            
            # Mark as enriched
            event.enriched = True
            
            app_logger.debug(f"Enriched event: {event.id}")
        
        except Exception as e:
            app_logger.error(f"Error enriching event: {e}", error=e)
    
    async def _correlate_events(self):
        """Correlate events from the correlation queue."""
        # Keep track of events for correlation
        event_buffer: Dict[str, List[XDREvent]] = {}
        
        while self._running:
            try:
                # Get event from queue
                event = await self._correlation_queue.get()
                
                # Add event to buffer for each data source type
                for rule_id, rule in self.correlation_rules.items():
                    if event.source_type in rule.data_sources:
                        if rule_id not in event_buffer:
                            event_buffer[rule_id] = []
                        
                        event_buffer[rule_id].append(event)
                        
                        # Clean up old events from buffer
                        cutoff_time = datetime.now() - timedelta(seconds=rule.time_window)
                        event_buffer[rule_id] = [e for e in event_buffer[rule_id] if e.timestamp >= cutoff_time]
                        
                        # Apply correlation rule
                        await self._apply_correlation_rule(rule, event_buffer[rule_id])
                
                # Mark as correlated
                event.correlated = True
                
                # Mark task as done
                self._correlation_queue.task_done()
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                app_logger.error(f"Error correlating events: {e}", error=e)
    
    async def _apply_correlation_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a correlation rule to a list of events."""
        try:
            # Check if rule is enabled
            if not rule.enabled:
                return
            
            # Apply rule based on type
            if rule.rule_type == CorrelationRuleType.SEQUENCE:
                await self._apply_sequence_rule(rule, events)
            
            elif rule.rule_type == CorrelationRuleType.THRESHOLD:
                await self._apply_threshold_rule(rule, events)
            
            elif rule.rule_type == CorrelationRuleType.PATTERN:
                await self._apply_pattern_rule(rule, events)
            
            elif rule.rule_type == CorrelationRuleType.ANOMALY:
                await self._apply_anomaly_rule(rule, events)
            
            elif rule.rule_type == CorrelationRuleType.BEHAVIOR:
                await self._apply_behavior_rule(rule, events)
            
            elif rule.rule_type == CorrelationRuleType.THREAT_INTEL:
                await self._apply_threat_intel_rule(rule, events)
        
        except Exception as e:
            app_logger.error(f"Error applying correlation rule {rule.name}: {e}", error=e)
    
    async def _apply_sequence_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a sequence correlation rule."""
        # Get sequence conditions
        sequence = rule.conditions.get("sequence", [])
        timeframe = rule.conditions.get("timeframe", 3600)  # Default 1 hour
        
        # Check if we have enough events
        if len(events) < len(sequence):
            return
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Check for sequence matches
        for i in range(len(sorted_events) - len(sequence) + 1):
            # Check if events match sequence
            match = True
            matched_events = []
            
            for j, condition in enumerate(sequence):
                event = sorted_events[i + j]
                
                # Check if event matches condition
                if not self._event_matches_condition(event, condition):
                    match = False
                    break
                
                matched_events.append(event)
            
            # Check timeframe
            if match and (matched_events[-1].timestamp - matched_events[0].timestamp).total_seconds() <= timeframe:
                # Create alert
                await self._create_correlation_alert(rule, matched_events)
                
                # Update rule stats
                rule.last_triggered = datetime.now()
                rule.trigger_count += 1
                
                # Only trigger once per rule application
                break
    
    async def _apply_threshold_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a threshold correlation rule."""
        # Get threshold conditions
        thresholds = rule.conditions.get("thresholds", [])
        timeframe = rule.conditions.get("timeframe", 3600)  # Default 1 hour
        
        # Check each threshold
        all_thresholds_met = True
        matched_events_by_threshold = {}
        
        for i, threshold in enumerate(thresholds):
            # Filter events by threshold condition
            matching_events = [e for e in events if self._event_matches_condition(e, threshold)]
            
            # Check if count threshold is met
            if len(matching_events) < threshold.get("count", 1):
                all_thresholds_met = False
                break
            
            matched_events_by_threshold[i] = matching_events
        
        # If all thresholds are met, create alert
        if all_thresholds_met:
            # Flatten matched events
            matched_events = []
            for events_list in matched_events_by_threshold.values():
                matched_events.extend(events_list)
            
            # Create alert
            await self._create_correlation_alert(rule, matched_events)
            
            # Update rule stats
            rule.last_triggered = datetime.now()
            rule.trigger_count += 1
    
    async def _apply_pattern_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a pattern correlation rule."""
        # Get pattern conditions
        patterns = rule.conditions.get("patterns", [])
        timeframe = rule.conditions.get("timeframe", 3600)  # Default 1 hour
        
        # Check each pattern
        matched_events_by_pattern = {}
        
        for i, pattern in enumerate(patterns):
            # Filter events by pattern condition
            matching_events = [e for e in events if self._event_matches_condition(e, pattern)]
            
            # If no matching events for this pattern, skip
            if not matching_events:
                continue
            
            matched_events_by_pattern[i] = matching_events
        
        # Check if all patterns have matches
        if len(matched_events_by_pattern) == len(patterns):
            # Flatten matched events
            matched_events = []
            for events_list in matched_events_by_pattern.values():
                matched_events.extend(events_list)
            
            # Sort by timestamp
            matched_events = sorted(matched_events, key=lambda e: e.timestamp)
            
            # Check timeframe
            if (matched_events[-1].timestamp - matched_events[0].timestamp).total_seconds() <= timeframe:
                # Create alert
                await self._create_correlation_alert(rule, matched_events)
                
                # Update rule stats
                rule.last_triggered = datetime.now()
                rule.trigger_count += 1
    
    async def _apply_anomaly_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply an anomaly correlation rule."""
        # Get anomaly conditions
        anomalies = rule.conditions.get("anomalies", [])
        timeframe = rule.conditions.get("timeframe", 3600)  # Default 1 hour
        
        # Check each anomaly
        matched_events_by_anomaly = {}
        
        for i, anomaly in enumerate(anomalies):
            # Filter events by anomaly condition
            matching_events = [e for e in events if self._event_matches_anomaly(e, anomaly)]
            
            # If no matching events for this anomaly, skip
            if not matching_events:
                continue
            
            matched_events_by_anomaly[i] = matching_events
        
        # Check if all anomalies have matches
        if len(matched_events_by_anomaly) == len(anomalies):
            # Flatten matched events
            matched_events = []
            for events_list in matched_events_by_anomaly.values():
                matched_events.extend(events_list)
            
            # Sort by timestamp
            matched_events = sorted(matched_events, key=lambda e: e.timestamp)
            
            # Check timeframe
            if (matched_events[-1].timestamp - matched_events[0].timestamp).total_seconds() <= timeframe:
                # Create alert
                await self._create_correlation_alert(rule, matched_events)
                
                # Update rule stats
                rule.last_triggered = datetime.now()
                rule.trigger_count += 1
    
    async def _apply_behavior_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a behavior correlation rule."""
        # Behavior rules are similar to anomaly rules but focus on specific behavior patterns
        # For now, implement as a simple pattern rule
        await self._apply_pattern_rule(rule, events)
    
    async def _apply_threat_intel_rule(self, rule: CorrelationRule, events: List[XDREvent]):
        """Apply a threat intelligence correlation rule."""
        # Get threat intel conditions
        indicators = rule.conditions.get("indicators", [])
        timeframe = rule.conditions.get("timeframe", 3600)  # Default 1 hour
        
        # Filter threat intel events
        threat_intel_events = [e for e in events if e.source_type == DataSourceType.THREAT_INTEL]
        
        # If no threat intel events, skip
        if not threat_intel_events:
            return
        
        # Filter other events
        other_events = [e for e in events if e.source_type != DataSourceType.THREAT_INTEL]
        
        # Check for matches between threat intel and other events
        matched_events = []
        
        for ti_event in threat_intel_events:
            for event in other_events:
                if self._event_matches_threat_intel(event, ti_event, indicators):
                    matched_events.extend([ti_event, event])
        
        # If matches found, create alert
        if matched_events:
            # Create alert
            await self._create_correlation_alert(rule, matched_events)
            
            # Update rule stats
            rule.last_triggered = datetime.now()
            rule.trigger_count += 1
    
    def _event_matches_condition(self, event: XDREvent, condition: Dict[str, Any]) -> bool:
        """Check if an event matches a condition."""
        # Check each condition field
        for key, value in condition.items():
            # Special case for different_host
            if key == "different_host" and value is True:
                # This requires context from other events, handled separately
                continue
            
            # Check event type
            if key == "event_type" and event.event_type != value:
                return False
            
            # Check data fields
            if key in event.data:
                # If value is a list, check if event value is in the list
                if isinstance(value, list):
                    if event.data[key] not in value:
                        return False
                # Otherwise, check for exact match
                elif event.data[key] != value:
                    return False
            
            # Check direct event fields
            elif hasattr(event, key):
                event_value = getattr(event, key)
                
                # If value is a list, check if event value is in the list
                if isinstance(value, list):
                    if event_value not in value:
                        return False
                # Otherwise, check for exact match
                elif event_value != value:
                    return False
            
            # If field not found, condition not met
            else:
                return False
        
        return True
    
    def _event_matches_anomaly(self, event: XDREvent, anomaly: Dict[str, Any]) -> bool:
        """Check if an event matches an anomaly condition."""
        # Check entity type
        if "entity_type" in anomaly and event.entity_type != anomaly["entity_type"]:
            return False
        
        # Check risk score
        if "risk_score" in anomaly:
            if event.source_type == DataSourceType.UEBA and "risk_score" in event.data:
                if event.data["risk_score"] < anomaly["risk_score"]:
                    return False
            else:
                return False
        
        # Check time of day
        if "time_of_day" in anomaly and anomaly["time_of_day"] == "unusual":
            # In a real implementation, you would check if the event time is unusual
            # For now, assume it's unusual if between midnight and 5am
            hour = event.timestamp.hour
            if not (0 <= hour < 5):
                return False
        
        # Check process name
        if "process_name" in anomaly and anomaly["process_name"] == "unusual":
            # In a real implementation, you would check if the process name is unusual
            # For now, assume it's unusual if it's not in a common list
            common_processes = ["explorer.exe", "chrome.exe", "firefox.exe", "svchost.exe", "winlogon.exe"]
            process_name = event.data.get("process_name")
            if process_name and process_name in common_processes:
                return False
        
        return True
    
    def _event_matches_threat_intel(self, event: XDREvent, ti_event: XDREvent, indicators: List[str]) -> bool:
        """Check if an event matches threat intelligence."""
        # Get indicators from threat intel event
        ti_indicators = ti_event.data.get("indicators", {})
        
        # Check each indicator type
        for indicator_type in indicators:
            if indicator_type not in ti_indicators:
                continue
            
            indicator_values = ti_indicators[indicator_type]
            
            # Check if event contains any of the indicator values
            if indicator_type == "ip":
                if event.ip_address in indicator_values or event.data.get("destination_address") in indicator_values:
                    return True
            
            elif indicator_type == "domain":
                if event.data.get("destination_address") in indicator_values:
                    return True
            
            elif indicator_type == "file_hash":
                if event.data.get("file_hash") in indicator_values:
                    return True
            
            elif indicator_type == "url":
                if event.data.get("url") in indicator_values:
                    return True
        
        return False
    
    async def _create_correlation_alert(self, rule: CorrelationRule, events: List[XDREvent]):
        """Create an alert from a correlation rule match."""
        # Get alert template
        template = rule.alert_template
        
        # Format title and description
        title = template.get("title", f"Correlation Rule: {rule.name}")
        description = template.get("description", f"Correlation rule {rule.name} triggered")
        
        # Replace placeholders in title and description
        for event in events:
            for key, value in event.data.items():
                title = title.replace(f"{{{key}}}", str(value))
                description = description.replace(f"{{{key}}}", str(value))
            
            # Replace direct event fields
            for key in ["hostname", "ip_address", "user_id", "entity_id", "entity_type"]:
                if hasattr(event, key):
                    value = getattr(event, key)
                    if value is not None:
                        title = title.replace(f"{{{key}}}", str(value))
                        description = description.replace(f"{{{key}}}", str(value))
        
        # Create alert
        alert = XDRAlert(
            title=title,
            description=description,
            severity=rule.severity,
            source_type=DataSourceType.XDR,
            source_id=rule.id,
            source_name=f"xdr:correlation:{rule.rule_type.value}",
            mitre_techniques=template.get("mitre_techniques", []),
            related_events=[event.id for event in events],
            data={
                "rule_name": rule.name,
                "rule_description": rule.description,
                "rule_type": rule.rule_type.value,
                "events": [{
                    "id": event.id,
                    "source_type": event.source_type.value,
                    "source_name": event.source_name,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp.isoformat(),
                    "data": event.data
                } for event in events]
            }
        )
        
        # Add alert to queue
        await self._alert_queue.put(alert)
        
        app_logger.info(f"Created correlation alert: {alert.id} from rule {rule.name}")
    
    async def _process_alerts(self):
        """Process alerts from the alert queue."""
        while self._running:
            try:
                # Get alert from queue
                alert = await self._alert_queue.get()
                
                # Store alert
                with self._lock:
                    self.alerts[alert.id] = alert
                
                # Create SOAR incident if enabled
                await self._create_soar_incident(alert)
                
                # Mark task as done
                self._alert_queue.task_done()
                
                app_logger.debug(f"Processed alert: {alert.id}")
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                app_logger.error(f"Error processing alert: {e}", error=e)
    
    async def _create_soar_incident(self, alert: XDRAlert):
        """Create a SOAR incident from an XDR alert."""
        try:
            # Map severity
            severity_mapping = {
                "low": IncidentSeverity.LOW,
                "medium": IncidentSeverity.MEDIUM,
                "high": IncidentSeverity.HIGH,
                "critical": IncidentSeverity.CRITICAL
            }
            
            # Create the incident
            incident = Incident(
                id=str(uuid.uuid4()),
                title=alert.title,
                description=alert.description,
                severity=severity_mapping.get(alert.severity, IncidentSeverity.MEDIUM),
                status=IncidentStatus.NEW,
                source="xdr",
                artifacts={
                    "alert_id": alert.id,
                    "source_type": alert.source_type.value,
                    "source_name": alert.source_name,
                    "hostname": alert.hostname,
                    "ip_address": alert.ip_address,
                    "user_id": getattr(alert, "user_id", None),
                    "entity_id": getattr(alert, "entity_id", None),
                    "entity_type": getattr(alert, "entity_type", None),
                    "mitre_techniques": getattr(alert, "mitre_techniques", []),
                    "related_events": getattr(alert, "related_events", []),
                    "related_alerts": getattr(alert, "related_alerts", []),
                    "data": getattr(alert, "data", {})
                },
                tags=["xdr", "auto-created"]
            )
            
            # Add the incident to the workflow engine
            workflow_engine.add_incident(incident)
            
            # Trigger appropriate workflows
            await self._trigger_soar_workflows(incident, alert)
            
            app_logger.info(f"Created SOAR incident {incident.id} for XDR alert {alert.id}")
            
            # Update alert with action taken
            alert.actions_taken.append({
                "action": "create_incident",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "incident_id": incident.id
                }
            })
        
        except Exception as e:
            app_logger.error(f"Error creating SOAR incident for alert {alert.id}: {e}", error=e)
    
    async def _trigger_soar_workflows(self, incident: Incident, alert: XDRAlert):
        """Trigger SOAR workflows for an incident."""
        try:
            # Determine workflow types based on alert source and severity
            workflow_types = ["generic_alert_response"]
            
            # Add source-specific workflow types
            if alert.source_type == DataSourceType.EDR:
                workflow_types.append("edr_alert_response")
            
            elif alert.source_type == DataSourceType.UEBA:
                workflow_types.append("ueba_anomaly_response")
            
            elif alert.source_type == DataSourceType.SIEM:
                workflow_types.append("siem_alert_response")
            
            # Add severity-specific workflow types
            if alert.severity in ["high", "critical"]:
                workflow_types.append("high_severity_response")
            
            # Add MITRE technique-specific workflow types
            for technique in alert.mitre_techniques:
                workflow_types.append(f"mitre_{technique.lower()}_response")
            
            # Find applicable workflows
            applicable_workflows = []
            for workflow in workflow_engine.get_workflows():
                if workflow.workflow_type in workflow_types:
                    applicable_workflows.append(workflow)
            
            # Trigger each applicable workflow
            for workflow in applicable_workflows:
                await workflow_engine.trigger_workflow(workflow.id, incident.id)
                app_logger.info(f"Triggered workflow {workflow.name} for incident {incident.id}")
            
            # Update alert with action taken
            alert.actions_taken.append({
                "action": "trigger_workflows",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "workflow_count": len(applicable_workflows),
                    "workflow_types": workflow_types
                }
            })
        
        except Exception as e:
            app_logger.error(f"Error triggering SOAR workflows for incident {incident.id}: {e}", error=e)
    
    async def create_threat_hunt(self, name: str, description: str, query: str, data_sources: List[DataSourceType], parameters: Dict[str, Any] = None) -> ThreatHunt:
        """Create a new threat hunt."""
        # Create threat hunt
        hunt = ThreatHunt(
            name=name,
            description=description,
            query=query,
            data_sources=data_sources,
            parameters=parameters or {}
        )
        
        # Store threat hunt
        with self._lock:
            self.threat_hunts[hunt.id] = hunt
        
        app_logger.info(f"Created threat hunt: {hunt.name} ({hunt.id})")
        
        return hunt
    
    async def run_threat_hunt(self, hunt_id: str) -> ThreatHunt:
        """Run a threat hunt."""
        # Get threat hunt
        hunt = self.threat_hunts.get(hunt_id)
        if not hunt:
            raise SecurityAIException(f"Threat hunt {hunt_id} not found")
        
        try:
            # Update status
            hunt.status = "active"
            hunt.last_run = datetime.now()
            
            app_logger.info(f"Running threat hunt: {hunt.name} ({hunt.id})")
            
            # In a real implementation, you would execute the hunt query against data sources
            # For now, just simulate results
            hunt.results = []
            
            # Update status
            hunt.status = "completed"
            
            app_logger.info(f"Completed threat hunt: {hunt.name} ({hunt.id})")
        
        except Exception as e:
            hunt.status = "failed"
            app_logger.error(f"Error running threat hunt {hunt.name}: {e}", error=e)
        
        return hunt
    
    def get_alerts(self, start_time: datetime = None, end_time: datetime = None, severity: str = None, source_type: DataSourceType = None, limit: int = 100) -> List[XDRAlert]:
        """Get alerts with optional filtering."""
        # Start with all alerts
        alerts = list(self.alerts.values())
        
        # Apply filters
        if start_time:
            alerts = [a for a in alerts if a.created_at >= start_time]
        
        if end_time:
            alerts = [a for a in alerts if a.created_at <= end_time]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if source_type:
            alerts = [a for a in alerts if a.source_type == source_type]
        
        # Sort by created_at (newest first)
        alerts = sorted(alerts, key=lambda a: a.created_at, reverse=True)
        
        # Apply limit
        if limit:
            alerts = alerts[:limit]
        
        return alerts
    
    def get_events(self, start_time: datetime = None, end_time: datetime = None, source_type: DataSourceType = None, event_type: str = None, limit: int = 100) -> List[XDREvent]:
        """Get events with optional filtering."""
        # Start with all events
        events = list(self.events.values())
        
        # Apply filters
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        if source_type:
            events = [e for e in events if e.source_type == source_type]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        # Sort by timestamp (newest first)
        events = sorted(events, key=lambda e: e.timestamp, reverse=True)
        
        # Apply limit
        if limit:
            events = events[:limit]
        
        return events


# Create singleton instance
xdr_platform = XDRPlatform()


# Initialize XDR platform
async def initialize_xdr_platform():
    """Initialize the XDR platform."""
    app_logger.info("Initializing XDR platform")
    
    # Start the platform
    await xdr_platform.start()
    
    app_logger.info("XDR platform initialized")


# Shutdown XDR platform
async def shutdown_xdr_platform():
    """Shutdown the XDR platform."""
    app_logger.info("Shutting down XDR platform")
    
    # Stop the platform
    await xdr_platform.stop()
    
    app_logger.info("XDR platform shutdown complete")