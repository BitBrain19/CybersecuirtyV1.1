#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Security Orchestration, Automation and Response (SOAR) workflow engine.

This module provides:
- Workflow definition and execution
- Playbook management
- Automated response actions
- Integration with security tools
- Case management
- Incident response coordination
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Callable, Union, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import importlib
import inspect
import logging
import os
import yaml

from pydantic import BaseModel, Field

from ..core.config import settings
from ..core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from ..core.monitoring import metrics_collector
from ..core.exceptions import SecurityAIException


class WorkflowStatus(Enum):
    """Status of a workflow execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(Enum):
    """Status of an action execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TriggerType(Enum):
    """Types of workflow triggers."""
    ALERT = "alert"
    SCHEDULE = "schedule"
    MANUAL = "manual"
    EVENT = "event"
    CONDITION = "condition"


class IncidentSeverity(Enum):
    """Severity levels for security incidents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    """Status of a security incident."""
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class WorkflowContext:
    """Context for workflow execution."""
    workflow_id: str
    trigger_type: TriggerType
    trigger_data: Dict[str, Any]
    variables: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: WorkflowStatus = WorkflowStatus.PENDING
    actions_history: List[Dict[str, Any]] = field(default_factory=list)
    incident_id: Optional[str] = None


@dataclass
class ActionResult:
    """Result of an action execution."""
    success: bool
    status: ActionStatus
    output: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    execution_time: float = 0.0


class Action:
    """Base class for all workflow actions."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
    
    async def execute(self, context: WorkflowContext, params: Dict[str, Any]) -> ActionResult:
        """Execute the action."""
        raise NotImplementedError("Subclasses must implement execute()")


class Condition:
    """Base class for workflow conditions."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate the condition."""
        raise NotImplementedError("Subclasses must implement evaluate()")


class WorkflowStep:
    """A step in a workflow."""
    
    def __init__(self, action: Action, params: Dict[str, Any] = None, 
                 conditions: List[Condition] = None, next_steps: List[str] = None,
                 on_failure: List[str] = None, id: str = None):
        self.id = id or str(uuid.uuid4())
        self.action = action
        self.params = params or {}
        self.conditions = conditions or []
        self.next_steps = next_steps or []
        self.on_failure = on_failure or []


class Workflow:
    """A security automation workflow."""
    
    def __init__(self, id: str, name: str, description: str = "", 
                 steps: Dict[str, WorkflowStep] = None, 
                 triggers: List[Dict[str, Any]] = None,
                 initial_step_id: str = None):
        self.id = id
        self.name = name
        self.description = description
        self.steps = steps or {}
        self.triggers = triggers or []
        self.initial_step_id = initial_step_id
    
    def add_step(self, step: WorkflowStep):
        """Add a step to the workflow."""
        self.steps[step.id] = step
        if not self.initial_step_id:
            self.initial_step_id = step.id
    
    def add_trigger(self, trigger_type: TriggerType, trigger_config: Dict[str, Any]):
        """Add a trigger to the workflow."""
        self.triggers.append({
            "type": trigger_type,
            "config": trigger_config
        })


class Incident:
    """A security incident."""
    
    def __init__(self, id: str, title: str, description: str, 
                 severity: IncidentSeverity, status: IncidentStatus = IncidentStatus.NEW,
                 created_at: datetime = None, updated_at: datetime = None,
                 assigned_to: str = None, source: str = None,
                 artifacts: Dict[str, Any] = None, tags: List[str] = None):
        self.id = id
        self.title = title
        self.description = description
        self.severity = severity
        self.status = status
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.assigned_to = assigned_to
        self.source = source
        self.artifacts = artifacts or {}
        self.tags = tags or []
        self.timeline = [{
            "timestamp": self.created_at,
            "event": "Incident created",
            "details": {"status": status.value}
        }]
    
    def update_status(self, status: IncidentStatus, details: Dict[str, Any] = None):
        """Update incident status."""
        self.status = status
        self.updated_at = datetime.now()
        
        self.timeline.append({
            "timestamp": self.updated_at,
            "event": f"Status changed to {status.value}",
            "details": details or {}
        })
    
    def add_comment(self, comment: str, author: str = "system"):
        """Add a comment to the incident timeline."""
        self.updated_at = datetime.now()
        
        self.timeline.append({
            "timestamp": self.updated_at,
            "event": "Comment added",
            "details": {"comment": comment, "author": author}
        })
    
    def add_artifact(self, name: str, value: Any, artifact_type: str = "other"):
        """Add an artifact to the incident."""
        self.updated_at = datetime.now()
        
        self.artifacts[name] = {
            "value": value,
            "type": artifact_type,
            "added_at": self.updated_at
        }
        
        self.timeline.append({
            "timestamp": self.updated_at,
            "event": f"Artifact added: {name}",
            "details": {"type": artifact_type}
        })


class WorkflowEngine:
    """SOAR workflow execution engine."""
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self.actions: Dict[str, Action] = {}
        self.conditions: Dict[str, Condition] = {}
        self.incidents: Dict[str, Incident] = {}
        self.active_workflows: Dict[str, WorkflowContext] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()
    
    def register_workflow(self, workflow: Workflow):
        """Register a workflow with the engine."""
        with self._lock:
            self.workflows[workflow.id] = workflow
            app_logger.info(f"Registered workflow: {workflow.name} ({workflow.id})")
    
    def register_action(self, action: Action):
        """Register an action with the engine."""
        with self._lock:
            self.actions[action.name] = action
            app_logger.info(f"Registered action: {action.name}")
    
    def register_condition(self, condition: Condition):
        """Register a condition with the engine."""
        with self._lock:
            self.conditions[condition.name] = condition
            app_logger.info(f"Registered condition: {condition.name}")
    
    def load_workflows_from_directory(self, directory: str):
        """Load workflows from YAML files in a directory."""
        if not os.path.exists(directory):
            app_logger.warning(f"Workflow directory does not exist: {directory}")
            return
        
        for filename in os.listdir(directory):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                try:
                    filepath = os.path.join(directory, filename)
                    with open(filepath, "r") as f:
                        workflow_def = yaml.safe_load(f)
                    
                    workflow = self._parse_workflow_definition(workflow_def)
                    self.register_workflow(workflow)
                
                except Exception as e:
                    app_logger.error(f"Error loading workflow from {filename}: {e}", error=e)
    
    def _parse_workflow_definition(self, workflow_def: Dict[str, Any]) -> Workflow:
        """Parse a workflow definition from a dictionary."""
        workflow_id = workflow_def.get("id", str(uuid.uuid4()))
        name = workflow_def.get("name", f"Workflow {workflow_id}")
        description = workflow_def.get("description", "")
        
        workflow = Workflow(id=workflow_id, name=name, description=description)
        
        # Parse triggers
        for trigger_def in workflow_def.get("triggers", []):
            trigger_type = TriggerType(trigger_def.get("type", "event"))
            trigger_config = trigger_def.get("config", {})
            workflow.add_trigger(trigger_type, trigger_config)
        
        # Parse steps
        steps_def = workflow_def.get("steps", {})
        initial_step_id = workflow_def.get("initial_step")
        
        for step_id, step_def in steps_def.items():
            action_name = step_def.get("action")
            if action_name not in self.actions:
                raise ValueError(f"Unknown action: {action_name}")
            
            action = self.actions[action_name]
            params = step_def.get("params", {})
            
            # Parse conditions
            conditions = []
            for condition_def in step_def.get("conditions", []):
                condition_name = condition_def.get("name")
                if condition_name not in self.conditions:
                    raise ValueError(f"Unknown condition: {condition_name}")
                conditions.append(self.conditions[condition_name])
            
            next_steps = step_def.get("next_steps", [])
            on_failure = step_def.get("on_failure", [])
            
            step = WorkflowStep(
                id=step_id,
                action=action,
                params=params,
                conditions=conditions,
                next_steps=next_steps,
                on_failure=on_failure
            )
            
            workflow.add_step(step)
        
        if initial_step_id:
            workflow.initial_step_id = initial_step_id
        
        return workflow
    
    async def execute_workflow(self, workflow_id: str, trigger_type: TriggerType, 
                             trigger_data: Dict[str, Any]) -> str:
        """Execute a workflow."""
        if workflow_id not in self.workflows:
            raise ValueError(f"Unknown workflow: {workflow_id}")
        
        workflow = self.workflows[workflow_id]
        
        # Create workflow context
        context_id = str(uuid.uuid4())
        context = WorkflowContext(
            workflow_id=context_id,
            trigger_type=trigger_type,
            trigger_data=trigger_data
        )
        
        # Store active workflow
        with self._lock:
            self.active_workflows[context_id] = context
        
        # Start workflow execution
        asyncio.create_task(self._execute_workflow_steps(workflow, context))
        
        return context_id
    
    async def _execute_workflow_steps(self, workflow: Workflow, context: WorkflowContext):
        """Execute workflow steps."""
        try:
            # Update status
            context.status = WorkflowStatus.RUNNING
            app_logger.info(f"Starting workflow execution: {workflow.name} ({context.workflow_id})")
            
            # Get initial step
            current_step_id = workflow.initial_step_id
            if not current_step_id or current_step_id not in workflow.steps:
                raise ValueError(f"Invalid initial step for workflow: {workflow.id}")
            
            # Execute steps
            while current_step_id:
                step = workflow.steps[current_step_id]
                
                # Check conditions
                conditions_met = all(condition.evaluate(context) for condition in step.conditions)
                
                if conditions_met:
                    # Execute action
                    action_result = await self._execute_action(step.action, step.params, context)
                    
                    # Record action execution
                    context.actions_history.append({
                        "step_id": step.id,
                        "action": step.action.name,
                        "status": action_result.status.value,
                        "success": action_result.success,
                        "execution_time": action_result.execution_time,
                        "timestamp": datetime.now().isoformat(),
                        "output": action_result.output,
                        "error": action_result.error_message
                    })
                    
                    # Determine next step
                    if action_result.success and step.next_steps:
                        current_step_id = step.next_steps[0]  # For now, just take the first next step
                    elif not action_result.success and step.on_failure:
                        current_step_id = step.on_failure[0]  # For now, just take the first failure step
                    else:
                        current_step_id = None  # End of workflow
                else:
                    # Skip step if conditions not met
                    context.actions_history.append({
                        "step_id": step.id,
                        "action": step.action.name,
                        "status": ActionStatus.SKIPPED.value,
                        "success": True,
                        "execution_time": 0.0,
                        "timestamp": datetime.now().isoformat(),
                        "output": {},
                        "error": "Conditions not met"
                    })
                    
                    # End workflow if no next step
                    current_step_id = None
            
            # Update workflow status
            context.status = WorkflowStatus.COMPLETED
            context.end_time = datetime.now()
            app_logger.info(f"Workflow completed: {workflow.name} ({context.workflow_id})")
        
        except Exception as e:
            # Handle workflow execution error
            context.status = WorkflowStatus.FAILED
            context.end_time = datetime.now()
            app_logger.error(f"Workflow execution failed: {workflow.name} ({context.workflow_id}): {e}", error=e)
        
        finally:
            # Clean up after some time
            await asyncio.sleep(3600)  # Keep workflow context for 1 hour
            with self._lock:
                if context.workflow_id in self.active_workflows:
                    del self.active_workflows[context.workflow_id]
    
    async def _execute_action(self, action: Action, params: Dict[str, Any], 
                            context: WorkflowContext) -> ActionResult:
        """Execute an action."""
        start_time = time.time()
        
        try:
            # Execute action
            result = await action.execute(context, params)
            execution_time = time.time() - start_time
            result.execution_time = execution_time
            
            return result
        
        except Exception as e:
            # Handle action execution error
            execution_time = time.time() - start_time
            app_logger.error(f"Action execution failed: {action.name}: {e}", error=e)
            
            return ActionResult(
                success=False,
                status=ActionStatus.FAILED,
                error_message=str(e),
                execution_time=execution_time
            )
    
    def create_incident(self, title: str, description: str, severity: IncidentSeverity,
                       source: str = None, artifacts: Dict[str, Any] = None,
                       tags: List[str] = None) -> str:
        """Create a new security incident."""
        incident_id = str(uuid.uuid4())
        
        incident = Incident(
            id=incident_id,
            title=title,
            description=description,
            severity=severity,
            source=source,
            artifacts=artifacts,
            tags=tags
        )
        
        with self._lock:
            self.incidents[incident_id] = incident
        
        app_logger.info(f"Created incident: {title} ({incident_id}), severity: {severity.value}")
        
        # Create alert for high/critical incidents
        if severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            alert_severity = AlertSeverity.HIGH if severity == IncidentSeverity.HIGH else AlertSeverity.CRITICAL
            
            create_alert(
                title=f"SOAR: {title}",
                description=description,
                severity=alert_severity,
                source=f"soar:incident:{incident_id}",
                tags={"type": "security_incident"},
                metadata={
                    "incident_id": incident_id,
                    "severity": severity.value,
                    "source": source,
                    "tags": tags
                }
            )
        
        return incident_id
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self.incidents.get(incident_id)
    
    def update_incident(self, incident_id: str, status: Optional[IncidentStatus] = None,
                       assigned_to: Optional[str] = None, comment: Optional[str] = None,
                       artifacts: Optional[Dict[str, Any]] = None) -> bool:
        """Update an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            return False
        
        if status:
            incident.update_status(status)
        
        if assigned_to:
            incident.assigned_to = assigned_to
            incident.timeline.append({
                "timestamp": datetime.now(),
                "event": "Incident assigned",
                "details": {"assigned_to": assigned_to}
            })
        
        if comment:
            incident.add_comment(comment)
        
        if artifacts:
            for name, artifact in artifacts.items():
                artifact_type = artifact.get("type", "other")
                artifact_value = artifact.get("value")
                incident.add_artifact(name, artifact_value, artifact_type)
        
        incident.updated_at = datetime.now()
        return True
    
    def get_incidents_by_status(self, status: IncidentStatus) -> List[Incident]:
        """Get incidents by status."""
        return [i for i in self.incidents.values() if i.status == status]
    
    def get_incidents_by_severity(self, severity: IncidentSeverity) -> List[Incident]:
        """Get incidents by severity."""
        return [i for i in self.incidents.values() if i.severity == severity]


# Create singleton instance
workflow_engine = WorkflowEngine()