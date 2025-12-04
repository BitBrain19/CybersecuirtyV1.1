"""
Adapters for integrating production ML modules with the ModelManager.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

from app.core.config import ModelType
from app.core.exceptions import PredictionError

# Import production modules
# Note: These imports will be resolved at runtime by the ModelManager using importlib
# to avoid circular dependencies and startup errors if modules are missing

logger = logging.getLogger(__name__)

class BaseAdapter:
    """Base adapter for all ML modules."""
    
    def __init__(self, model_instance: Any):
        self.model = model_instance
        
    async def predict(self, features: Dict[str, Any]) -> Any:
        """Standard prediction interface."""
        raise NotImplementedError

class ThreatDetectionAdapter(BaseAdapter):
    """Adapter for Threat Classifier."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.threat_classification.threat_classifier_prod import SecurityEvent, ThreatCategory
        
        # Convert features to SecurityEvent
        event = SecurityEvent(
            event_type=features.get("event_type", "unknown"),
            source_type=features.get("source_type", "unknown"),
            event_data=features,
            context=features.get("context", {})
        )
        
        # Call model
        result = await self.model.classify_event(event)
        
        return {
            "threat_category": result.threat_category.value,
            "severity": result.severity.value,
            "confidence": result.confidence,
            "is_threat": result.is_threat,
            "reasoning": result.reasoning
        }

class MalwareDetectionAdapter(BaseAdapter):
    """Adapter for Malware Detector."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.malware_detection.malware_detector_prod import ProcessEvent
        
        # Convert features to ProcessEvent
        event = ProcessEvent(
            process_name=features.get("process_name", ""),
            process_id=features.get("process_id", 0),
            command_line=features.get("command_line", ""),
            file_path=features.get("file_path", ""),
            parent_process_id=features.get("parent_process_id", 0)
        )
        
        # Call model
        result = await self.model.analyze_process(event)
        
        return {
            "is_malware": result.is_malware,
            "severity": result.severity.value,
            "malware_type": result.malware_type.value,
            "confidence": result.confidence,
            "indicators": result.indicators
        }

class AttackPathAdapter(BaseAdapter):
    """Adapter for Attack Path Predictor."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        # Expects source and target nodes
        source = features.get("source_node")
        target = features.get("target_node")
        
        if not source or not target:
            raise PredictionError("attack_path", "Missing source or target node")
            
        result = await self.model.find_attack_paths(source, target)
        
        return {
            "paths_found": len(result),
            "paths": [
                {
                    "steps": [n.id for n in path.nodes],
                    "risk_score": path.risk_score,
                    "probability": path.probability
                }
                for path in result
            ]
        }

class MitreMappingAdapter(BaseAdapter):
    """Adapter for MITRE Technique Mapper."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.mitre_mapping.mitre_technique_mapper_prod import SecurityEvent
        
        event = SecurityEvent(
            event_type=features.get("event_type", ""),
            description=features.get("description", ""),
            data=features
        )
        
        result = await self.model.map_event(event)
        
        return {
            "techniques": [t.id for t in result.techniques],
            "tactics": [t.value for t in result.tactics],
            "confidence": result.confidence
        }

class UEBAAdapter(BaseAdapter):
    """Adapter for UEBA Graph Detector."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.ueba.ueba_graph_detector_prod import UserActivity
        
        activity = UserActivity(
            user_id=features.get("user_id", ""),
            action=features.get("action", ""),
            resource=features.get("resource", ""),
            timestamp=datetime.now(),
            metadata=features
        )
        
        result = await self.model.analyze_activity(activity)
        
        return {
            "is_anomalous": result.is_anomalous,
            "risk_score": result.risk_score,
            "anomaly_types": [t.value for t in result.anomaly_types]
        }

class FederatedLearningAdapter(BaseAdapter):
    """Adapter for Federated Learning."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        # Federated learning is mostly for training, but we can expose model status
        status = await self.model.get_status()
        return status

class EDRTelemetryAdapter(BaseAdapter):
    """Adapter for EDR Telemetry Processor."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.edr_telemetry.edr_telemetry_processor_prod import TelemetryEvent
        
        event = TelemetryEvent(
            source_id=features.get("source_id", ""),
            event_type=features.get("event_type", ""),
            data=features
        )
        
        result = await self.model.process_event(event)
        
        return {
            "processed": True,
            "risk_level": result.risk_level,
            "tags": result.tags
        }

class XDRCorrelationAdapter(BaseAdapter):
    """Adapter for XDR Correlation Engine."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.xdr_correlation.xdr_correlation_engine_prod import AlertEvent
        
        alert = AlertEvent(
            alert_id=features.get("alert_id", ""),
            source=features.get("source", ""),
            severity=features.get("severity", ""),
            description=features.get("description", ""),
            timestamp=datetime.now()
        )
        
        result = await self.model.correlate_alert(alert)
        
        return {
            "correlated": result.is_correlated,
            "incident_id": result.incident_id,
            "related_alerts": result.related_alert_ids
        }

class SOAREngineAdapter(BaseAdapter):
    """Adapter for SOAR Engine."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        from app.soar_engine.soar_orchestrator_prod import IncidentContext
        
        # Map features to IncidentContext fields
        incident = IncidentContext(
            incident_id=features.get("incident_id", ""),
            severity=features.get("severity", "medium"),
            incident_type=features.get("alert_type", "security_incident"),
            affected_hosts=features.get("assets", [])
        )
        
        result = await self.model.process_incident(incident)
        
        return {
            "playbook_actions": [a.action_type.value for a in result.suggested_actions],
            "executed_actions": [a.action_type.value for a in result.executed_actions],
            "triage_level": result.triage_level.value,
            "root_cause": result.root_cause_hypothesis
        }

class VulnerabilityAssessmentAdapter(BaseAdapter):
    """Adapter for existing Vulnerability Assessment Model."""
    
    async def predict(self, features: Dict[str, Any]) -> Any:
        # Existing model has a predict method returning (score, severity)
        score, severity = self.model.predict(features)
        return {
            "severity": severity,
            "risk_score": score,
            "confidence": score / 10.0
        }

# Factory map
ADAPTER_MAP = {
    ModelType.THREAT_DETECTION: ThreatDetectionAdapter,
    ModelType.MALWARE_DETECTION: MalwareDetectionAdapter,
    ModelType.ATTACK_PATH: AttackPathAdapter,
    ModelType.MITRE_MAPPING: MitreMappingAdapter,
    ModelType.UEBA: UEBAAdapter,
    ModelType.FEDERATED_LEARNING: FederatedLearningAdapter,
    ModelType.EDR_TELEMETRY: EDRTelemetryAdapter,
    ModelType.XDR_CORRELATION: XDRCorrelationAdapter,
    ModelType.SOAR_ENGINE: SOAREngineAdapter,
    ModelType.VULNERABILITY_ASSESSMENT: VulnerabilityAssessmentAdapter,
}
