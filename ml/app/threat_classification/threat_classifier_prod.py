"""
ML-Based Threat Classifier - Production System
Classifies security events/logs into threat categories in real-time
Uses feature extraction, ML models, and confidence scoring
"""

import asyncio
import json
import logging
import pickle
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
import threading

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    """Threat categories"""
    MALWARE = "malware"
    EXPLOIT = "exploit"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_CONTROL = "command_control"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    IMPACT = "impact"
    COLLECTION = "collection"


@dataclass
class SecurityEvent:
    """Represents a security event/log"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Event source
    source_type: str = ""  # process, network, file, auth, etc.
    source_id: str = ""
    
    # Event details
    event_type: str = ""
    event_data: Dict[str, Any] = field(default_factory=dict)
    raw_log: str = ""
    
    # Classification labels (for training)
    threat_category: Optional[ThreatCategory] = None
    is_threat: bool = False
    confidence: float = 0.0
    
    # Context
    host_id: str = ""
    user_id: str = ""
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatClassification:
    """Result of threat classification"""
    event_id: str
    threat_category: ThreatCategory
    severity: ThreatSeverity
    confidence: float  # 0-1.0
    is_threat: bool
    
    # Reasoning
    top_features: Dict[str, float]  # Feature importance
    reasoning: str
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    model_version: str = ""
    
    # MITRE ATT&CK mapping
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    auc_roc: float = 0.0
    
    # Per-category metrics
    category_metrics: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    # Date
    evaluated_at: datetime = field(default_factory=datetime.now)
    dataset_size: int = 0


class FeatureExtractor:
    """Extract features from security events"""
    
    def __init__(self):
        self.label_encoders = {}
        self.feature_names = []
        
    def extract_features(self, event: SecurityEvent) -> np.ndarray:
        """Extract numeric features from event"""
        features = []
        
        # Time-based features
        hour_of_day = event.timestamp.hour
        day_of_week = event.timestamp.weekday()
        features.extend([hour_of_day, day_of_week])
        
        # Event type features
        event_type_encoded = hash(event.event_type) % 100
        features.append(event_type_encoded)
        
        # Source type features
        source_type_map = {
            "process": 0, "network": 1, "file": 2, 
            "auth": 3, "registry": 4, "system": 5
        }
        features.append(source_type_map.get(event.source_type, 6))
        
        # Event data features
        event_data_features = self._extract_event_data_features(event.event_data)
        features.extend(event_data_features)
        
        # Context features
        context_features = self._extract_context_features(event.context)
        features.extend(context_features)
        
        return np.array(features[:20], dtype=np.float32)  # Fixed feature length
    
    def _extract_event_data_features(self, event_data: Dict[str, Any]) -> List[float]:
        """Extract numeric features from event data"""
        features = []
        
        # Command line complexity
        cmd_line = event_data.get("command_line", "")
        features.append(len(cmd_line))  # Command line length
        features.append(cmd_line.count(" "))  # Number of arguments
        features.append(1.0 if any(x in cmd_line.lower() for x in ["powershell", "cmd", "bash"]) else 0.0)
        
        # File activity
        file_path = event_data.get("file_path", "")
        features.append(1.0 if any(x in file_path.lower() for x in ["system32", "windows", "temp"]) else 0.0)
        features.append(1.0 if "." in file_path else 0.0)
        
        # Network activity
        port = event_data.get("port", 0)
        features.append(float(port))
        features.append(1.0 if port in [445, 135, 139, 22, 3389] else 0.0)  # Known malicious ports
        
        # Registry activity
        registry_path = event_data.get("registry_path", "")
        features.append(1.0 if "Run" in registry_path else 0.0)
        features.append(1.0 if "Services" in registry_path else 0.0)
        
        while len(features) < 12:
            features.append(0.0)
        
        return features[:12]
    
    def _extract_context_features(self, context: Dict[str, Any]) -> List[float]:
        """Extract context features"""
        features = []
        
        # User context
        is_admin = context.get("is_admin", False)
        features.append(1.0 if is_admin else 0.0)
        
        # Host context
        has_av = context.get("has_av", True)
        features.append(1.0 if has_av else 0.0)
        
        # Previous incidents on host/user
        incidents_count = context.get("previous_incidents", 0)
        features.append(float(min(incidents_count, 10)))  # Cap at 10
        
        # Reputation score
        reputation = context.get("reputation_score", 0.5)
        features.append(float(reputation))
        
        while len(features) < 8:
            features.append(0.0)
        
        return features[:8]


class ThreatClassifierModel:
    """ML model for threat classification"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.label_encoder = LabelEncoder()
        self.metrics = ModelMetrics()
        self.version = "1.0.0"
        self.trained = False
        
    def train(self, events: List[SecurityEvent]) -> ModelMetrics:
        """Train the classifier"""
        logger.info(f"Training threat classifier on {len(events)} events")
        
        # Filter only threat events (those with a threat_category)
        threat_events = [e for e in events if e.threat_category]
        
        if len(threat_events) < 10:
            logger.warning(f"Not enough threat events for training: {len(threat_events)}")
            return self.metrics
        
        # Extract features and labels from threat events only
        X = np.array([self.feature_extractor.extract_features(e) for e in threat_events])
        y = np.array([e.threat_category.value for e in threat_events])
        
        if len(np.unique(y)) < 2:
            logger.warning("Not enough threat categories for training")
            return self.metrics
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train ensemble model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        
        self.metrics.accuracy = accuracy_score(y_test, y_pred)
        self.metrics.precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        self.metrics.recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        self.metrics.f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        self.metrics.dataset_size = len(threat_events)
        
        self.trained = True
        logger.info(f"Training complete - Accuracy: {self.metrics.accuracy:.2%}")
        
        return self.metrics
    
    def classify(self, event: SecurityEvent) -> ThreatClassification:
        """Classify a single event"""
        if not self.trained or self.model is None:
            logger.warning("Model not trained yet")
            return ThreatClassification(
                event_id=event.event_id,
                threat_category=ThreatCategory.RECONNAISSANCE,
                severity=ThreatSeverity.LOW,
                confidence=0.0,
                is_threat=False,
                top_features={},
                reasoning="Model not trained"
            )
        
        # Extract and scale features
        X = self.feature_extractor.extract_features(event).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # Predict
        y_pred = self.model.predict(X_scaled)[0]
        y_proba = self.model.predict_proba(X_scaled)[0]
        
        # Get confidence
        confidence = float(np.max(y_proba))
        
        # Decode prediction
        category_name = self.label_encoder.inverse_transform([y_pred])[0]
        threat_category = ThreatCategory(category_name)
        
        # Determine severity
        severity = self._determine_severity(threat_category, confidence)
        
        # Get feature importance
        top_features = self._get_feature_importance()
        
        return ThreatClassification(
            event_id=event.event_id,
            threat_category=threat_category,
            severity=severity,
            confidence=confidence,
            is_threat=confidence > 0.6,
            top_features=top_features,
            reasoning=f"Classified as {threat_category.value} with {confidence:.0%} confidence",
            model_version=self.version
        )
    
    def _determine_severity(self, category: ThreatCategory, confidence: float) -> ThreatSeverity:
        """Determine threat severity"""
        critical_categories = [
            ThreatCategory.MALWARE,
            ThreatCategory.PRIVILEGE_ESCALATION,
            ThreatCategory.DATA_EXFILTRATION
        ]
        
        if category in critical_categories and confidence > 0.8:
            return ThreatSeverity.CRITICAL
        elif category in critical_categories and confidence > 0.6:
            return ThreatSeverity.HIGH
        elif confidence > 0.7:
            return ThreatSeverity.MEDIUM
        elif confidence > 0.5:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO
    
    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from model"""
        if self.model is None:
            return {}
        
        importances = self.model.feature_importances_
        feature_names = [f"feature_{i}" for i in range(len(importances))]
        
        return {name: float(imp) for name, imp in zip(feature_names, importances)}
    
    def save_model(self, path: str) -> None:
        """Save model to disk"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'version': self.version,
                'metrics': asdict(self.metrics)
            }, f)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str) -> None:
        """Load model from disk"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.label_encoder = data['label_encoder']
            self.version = data['version']
            self.trained = True
        logger.info(f"Model loaded from {path}")


class ThreatClassifier:
    """Main threat classifier system"""
    
    def __init__(self):
        self.model = ThreatClassifierModel()
        self.event_history = deque(maxlen=10000)
        self.classification_history = deque(maxlen=10000)
        self.lock = threading.RLock()
        self.models_dir = Path("ml/models/threat_classifier")
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
    async def classify_event(self, event: SecurityEvent) -> ThreatClassification:
        """Classify a security event"""
        classification = self.model.classify(event)
        
        with self.lock:
            self.event_history.append(event)
            self.classification_history.append(classification)
        
        logger.info(f"Event {event.event_id} classified as {classification.threat_category.value}")
        return classification
    
    async def classify_batch(self, events: List[SecurityEvent]) -> List[ThreatClassification]:
        """Classify multiple events"""
        classifications = []
        for event in events:
            classification = await self.classify_event(event)
            classifications.append(classification)
        return classifications
    
    async def train_model(self, events: List[SecurityEvent]) -> ModelMetrics:
        """Train the classifier model"""
        with self.lock:
            metrics = self.model.train(events)
        
        # Save model
        model_path = self.models_dir / f"classifier_v{self.model.version}.pkl"
        self.model.save_model(str(model_path))
        
        return metrics
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get classifier statistics"""
        with self.lock:
            total_classified = len(self.classification_history)
            threat_count = sum(1 for c in self.classification_history if c.is_threat)
            
            category_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for classification in self.classification_history:
                category_counts[classification.threat_category.value] += 1
                severity_counts[classification.severity.value] += 1
        
        return {
            "total_classified": total_classified,
            "total_threats": threat_count,
            "threat_percentage": threat_count / total_classified if total_classified > 0 else 0,
            "by_category": dict(category_counts),
            "by_severity": dict(severity_counts),
            "model_version": self.model.version,
            "model_accuracy": self.model.metrics.accuracy
        }


# Global instance
_classifier_instance = None


def get_threat_classifier() -> ThreatClassifier:
    """Get or create threat classifier instance"""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = ThreatClassifier()
    return _classifier_instance
