#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SOAR conditions for security automation workflows.

This module provides a collection of conditions that can be used in SOAR workflows:
- Threat intelligence conditions
- Alert severity conditions
- Time-based conditions
- Event count conditions
- Entity risk score conditions
- Indicator match conditions
"""

import re
import time
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta

from core.logging_system import app_logger
from .workflow_engine import Condition, WorkflowContext


class ThreatIntelligenceCondition(Condition):
    """Condition based on threat intelligence data."""
    
    def __init__(self, indicator_type: str = None, min_score: float = 0.5):
        name = f"threat_intel_{indicator_type or 'any'}_score_{min_score}"
        description = f"Check if threat intelligence score for {indicator_type or 'any'} indicator is >= {min_score}"
        super().__init__(name=name, description=description)
        
        self.indicator_type = indicator_type
        self.min_score = min_score
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if threat intelligence score meets the threshold."""
        # Check if threat intelligence data exists in context
        if "threat_intel" not in context.artifacts:
            return False
        
        threat_intel = context.artifacts["threat_intel"]
        
        # If no indicators found, condition is not met
        if not threat_intel:
            return False
        
        # Check all indicators
        for indicator, data in threat_intel.items():
            # Filter by indicator type if specified
            if self.indicator_type and data.get("type") != self.indicator_type:
                continue
            
            # Check if malicious score meets the threshold
            if data.get("malicious_score", 0) >= self.min_score:
                return True
        
        return False


class AlertSeverityCondition(Condition):
    """Condition based on alert severity."""
    
    def __init__(self, min_severity: str):
        name = f"alert_severity_{min_severity}"
        description = f"Check if alert severity is at least {min_severity}"
        super().__init__(name=name, description=description)
        
        self.min_severity = min_severity
        self.severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if alert severity meets the threshold."""
        # Check if alert data exists in trigger data
        if "alert" not in context.trigger_data:
            return False
        
        alert = context.trigger_data["alert"]
        alert_severity = alert.get("severity", "low").lower()
        
        # Get numeric severity levels
        alert_level = self.severity_levels.get(alert_severity, 0)
        min_level = self.severity_levels.get(self.min_severity.lower(), 0)
        
        # Check if alert severity meets the threshold
        return alert_level >= min_level


class TimeWindowCondition(Condition):
    """Condition based on time window."""
    
    def __init__(self, start_time: str = None, end_time: str = None, 
                days: List[int] = None, hours: List[int] = None):
        name = "time_window"
        description = "Check if current time is within specified window"
        super().__init__(name=name, description=description)
        
        self.start_time = start_time  # Format: "HH:MM"
        self.end_time = end_time      # Format: "HH:MM"
        self.days = days              # 0=Monday, 6=Sunday
        self.hours = hours            # 0-23
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if current time is within the specified window."""
        now = datetime.now()
        
        # Check day of week
        if self.days is not None:
            # Convert to 0=Monday, 6=Sunday
            current_day = now.weekday()
            if current_day not in self.days:
                return False
        
        # Check hour
        if self.hours is not None:
            current_hour = now.hour
            if current_hour not in self.hours:
                return False
        
        # Check time range
        if self.start_time and self.end_time:
            start_hour, start_minute = map(int, self.start_time.split(":"))
            end_hour, end_minute = map(int, self.end_time.split(":"))
            
            start_time = now.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
            end_time = now.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)
            
            # Handle overnight ranges
            if end_time < start_time:
                # Check if current time is after start_time or before end_time
                return now >= start_time or now <= end_time
            else:
                # Check if current time is between start_time and end_time
                return start_time <= now <= end_time
        
        # If no time range specified, other conditions were met
        return True


class EventCountCondition(Condition):
    """Condition based on event count within a time window."""
    
    def __init__(self, event_type: str, threshold: int, time_window: int, 
                field_filter: Dict[str, Any] = None):
        name = f"event_count_{event_type}_{threshold}_{time_window}"
        description = f"Check if {event_type} event count is >= {threshold} in the last {time_window} seconds"
        super().__init__(name=name, description=description)
        
        self.event_type = event_type
        self.threshold = threshold
        self.time_window = time_window  # in seconds
        self.field_filter = field_filter or {}
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if event count meets the threshold within the time window."""
        # This is a simplified implementation
        # In a real implementation, you would query a database or event store
        
        # Check if events exist in context
        if "events" not in context.artifacts:
            return False
        
        events = context.artifacts["events"]
        
        # Filter events by type and time window
        now = datetime.now()
        window_start = now - timedelta(seconds=self.time_window)
        
        matching_events = []
        
        for event in events:
            # Skip if event type doesn't match
            if event.get("type") != self.event_type:
                continue
            
            # Skip if event is outside time window
            event_time = datetime.fromisoformat(event.get("timestamp"))
            if event_time < window_start:
                continue
            
            # Check field filters
            match = True
            for field, value in self.field_filter.items():
                if event.get(field) != value:
                    match = False
                    break
            
            if match:
                matching_events.append(event)
        
        # Check if count meets threshold
        return len(matching_events) >= self.threshold


class EntityRiskScoreCondition(Condition):
    """Condition based on entity risk score."""
    
    def __init__(self, entity_type: str, min_score: float):
        name = f"entity_risk_{entity_type}_{min_score}"
        description = f"Check if {entity_type} entity risk score is >= {min_score}"
        super().__init__(name=name, description=description)
        
        self.entity_type = entity_type
        self.min_score = min_score
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if entity risk score meets the threshold."""
        # Check if entity data exists in context
        if "entities" not in context.artifacts:
            return False
        
        entities = context.artifacts["entities"]
        
        # Check if entity exists in trigger data
        entity_id = None
        if "entity" in context.trigger_data:
            entity_id = context.trigger_data["entity"].get("id")
        
        # If entity ID is provided, check only that entity
        if entity_id and entity_id in entities:
            entity = entities[entity_id]
            if entity.get("type") == self.entity_type and entity.get("risk_score", 0) >= self.min_score:
                return True
        
        # Otherwise, check all entities of the specified type
        for entity_id, entity in entities.items():
            if entity.get("type") == self.entity_type and entity.get("risk_score", 0) >= self.min_score:
                return True
        
        return False


class IndicatorMatchCondition(Condition):
    """Condition based on indicator match."""
    
    def __init__(self, indicator_type: str, pattern: str, field: str = None):
        name = f"indicator_match_{indicator_type}_{field or 'any'}"
        description = f"Check if {indicator_type} indicator matches pattern in {field or 'any'} field"
        super().__init__(name=name, description=description)
        
        self.indicator_type = indicator_type
        self.pattern = pattern
        self.field = field
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate if indicator matches the pattern."""
        # Check trigger data for indicators
        if "indicators" not in context.trigger_data:
            return False
        
        indicators = context.trigger_data["indicators"]
        
        # Filter indicators by type
        matching_indicators = [i for i in indicators if i.get("type") == self.indicator_type]
        
        # If no matching indicators, check is not met
        if not matching_indicators:
            return False
        
        # Check if any indicator matches the pattern
        for indicator in matching_indicators:
            # If field is specified, check only that field
            if self.field:
                if self.field not in indicator:
                    continue
                
                value = indicator[self.field]
                if isinstance(value, str) and re.search(self.pattern, value):
                    return True
            
            # Otherwise, check all string fields
            else:
                for field, value in indicator.items():
                    if isinstance(value, str) and re.search(self.pattern, value):
                        return True
        
        return False


class CompoundCondition(Condition):
    """Compound condition that combines multiple conditions with AND/OR logic."""
    
    def __init__(self, conditions: List[Condition], operator: str = "and"):
        name = f"{operator}_condition"
        description = f"Compound condition with {operator} logic"
        super().__init__(name=name, description=description)
        
        self.conditions = conditions
        self.operator = operator.lower()
    
    def evaluate(self, context: WorkflowContext) -> bool:
        """Evaluate all conditions with AND/OR logic."""
        if not self.conditions:
            return True
        
        if self.operator == "and":
            return all(condition.evaluate(context) for condition in self.conditions)
        elif self.operator == "or":
            return any(condition.evaluate(context) for condition in self.conditions)
        else:
            app_logger.warning(f"Unknown operator: {self.operator}, defaulting to AND")
            return all(condition.evaluate(context) for condition in self.conditions)


# Register conditions with the workflow engine
def register_conditions():
    """Register all conditions with the workflow engine."""
    from .workflow_engine import workflow_engine
    
    # Create and register common conditions
    conditions = [
        # Alert severity conditions
        AlertSeverityCondition("medium"),
        AlertSeverityCondition("high"),
        AlertSeverityCondition("critical"),
        
        # Threat intelligence conditions
        ThreatIntelligenceCondition(indicator_type="ip", min_score=0.7),
        ThreatIntelligenceCondition(indicator_type="domain", min_score=0.7),
        ThreatIntelligenceCondition(indicator_type="hash", min_score=0.7),
        ThreatIntelligenceCondition(min_score=0.8),  # Any indicator type
        
        # Time window conditions
        TimeWindowCondition(hours=list(range(8, 18))),  # Business hours (8 AM - 6 PM)
        TimeWindowCondition(days=[0, 1, 2, 3, 4]),      # Weekdays
        
        # Entity risk score conditions
        EntityRiskScoreCondition("user", 0.7),
        EntityRiskScoreCondition("host", 0.7),
        EntityRiskScoreCondition("application", 0.7),
    ]
    
    for condition in conditions:
        workflow_engine.register_condition(condition)
    
    app_logger.info(f"Registered {len(conditions)} SOAR conditions")