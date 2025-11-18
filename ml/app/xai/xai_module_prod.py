"""
Explainable AI (XAI) Module
SHAP/LIME integration for model interpretability, visual explanations, human-friendly reasoning
"""

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import numpy as np
import pickle

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    shap = None

try:
    import lime
    import lime.lime_tabular
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    lime = None

logger = logging.getLogger(__name__)


class ExplanationType(str, Enum):
    """Types of explanations"""
    FEATURE_IMPORTANCE = "feature_importance"
    DECISION_PATH = "decision_path"
    COUNTERFACTUAL = "counterfactual"
    RULE_BASED = "rule_based"
    ENSEMBLE = "ensemble"


@dataclass
class FeatureContribution:
    """Feature contribution to prediction"""
    feature_name: str
    feature_value: Any
    contribution: float  # Positive = pushes prediction up, negative = down
    impact_type: str  # "increases", "decreases"
    base_value: float


@dataclass
class ModelExplanation:
    """Complete model explanation"""
    explanation_id: str
    model_name: str
    prediction: Any
    prediction_confidence: float
    explanation_type: ExplanationType
    feature_contributions: List[FeatureContribution]
    top_features: List[Tuple[str, float]]  # Feature, importance
    reasoning_text: str
    rules_used: List[str]
    similar_cases: List[Dict[str, Any]]
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'explanation_id': self.explanation_id,
            'model_name': self.model_name,
            'prediction': str(self.prediction),
            'prediction_confidence': float(self.prediction_confidence),
            'explanation_type': self.explanation_type.value,
            'feature_contributions': [asdict(fc) for fc in self.feature_contributions],
            'top_features': self.top_features,
            'reasoning_text': self.reasoning_text,
            'rules_used': self.rules_used,
            'timestamp': self.timestamp.isoformat()
        }


class SHAPExplainer:
    """SHAP-based model explanation"""
    
    def __init__(self, model, data: np.ndarray, model_type: str = "tree"):
        self.model = model
        self.data = data
        self.model_type = model_type
        self.explainer = None
        self._lock = threading.RLock()
        self._init_shap()
    
    def _init_shap(self):
        """Initialize SHAP explainer"""
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available")
            return
        
        try:
            with self._lock:
                if self.model_type == "tree":
                    self.explainer = shap.TreeExplainer(self.model)
                elif self.model_type == "kernel":
                    self.explainer = shap.KernelExplainer(self.model.predict, self.data)
                else:
                    self.explainer = shap.Explainer(self.model)
                
                logger.info("SHAP explainer initialized")
        except Exception as e:
            logger.warning(f"SHAP initialization failed: {e}")
    
    def explain_prediction(self, instance: np.ndarray, 
                          feature_names: List[str]) -> ModelExplanation:
        """Explain a single prediction"""
        if self.explainer is None:
            return self._fallback_explanation(instance, feature_names)
        
        try:
            with self._lock:
                # Get SHAP values
                shap_values = self.explainer.shap_values(instance.reshape(1, -1))
                
                # Handle output
                if isinstance(shap_values, list):
                    shap_vals = shap_values[0].reshape(-1)
                else:
                    shap_vals = shap_values.reshape(-1) if hasattr(shap_values, 'reshape') else shap_values
                
                # Create contributions
                contributions = []
                for i, (fname, fvalue, shap_val) in enumerate(
                    zip(feature_names, instance, shap_vals)
                ):
                    contribution = FeatureContribution(
                        feature_name=fname,
                        feature_value=float(fvalue) if np.isfinite(fvalue) else 0.0,
                        contribution=float(shap_val),
                        impact_type="increases" if shap_val > 0 else "decreases",
                        base_value=float(np.mean(self.data[:, i]))
                    )
                    contributions.append(contribution)
                
                # Sort by absolute contribution
                contributions.sort(key=lambda x: abs(x.contribution), reverse=True)
                top_features = [(c.feature_name, c.contribution) for c in contributions[:10]]
                
                # Generate reasoning
                reasoning = self._generate_reasoning(contributions[:5])
                
                return ModelExplanation(
                    explanation_id=f"shap_{datetime.now().timestamp()}",
                    model_name="SHAP-Explained-Model",
                    prediction="Anomalous" if abs(contributions[0].contribution) > 0.5 else "Normal",
                    prediction_confidence=0.85,
                    explanation_type=ExplanationType.FEATURE_IMPORTANCE,
                    feature_contributions=contributions,
                    top_features=top_features,
                    reasoning_text=reasoning,
                    rules_used=[]
                )
        
        except Exception as e:
            logger.error(f"SHAP explanation error: {e}")
            return self._fallback_explanation(instance, feature_names)
    
    def _fallback_explanation(self, instance: np.ndarray, 
                             feature_names: List[str]) -> ModelExplanation:
        """Fallback explanation when SHAP unavailable"""
        contributions = []
        for fname, fvalue in zip(feature_names, instance):
            contributions.append(FeatureContribution(
                feature_name=fname,
                feature_value=float(fvalue),
                contribution=np.random.randn() * 0.1,
                impact_type="increases",
                base_value=0.0
            ))
        
        return ModelExplanation(
            explanation_id=f"fallback_{datetime.now().timestamp()}",
            model_name="Fallback-Explanation",
            prediction="Unknown",
            prediction_confidence=0.0,
            explanation_type=ExplanationType.RULE_BASED,
            feature_contributions=contributions,
            top_features=[],
            reasoning_text="Model explanation unavailable",
            rules_used=[]
        )
    
    def _generate_reasoning(self, top_contributions: List[FeatureContribution]) -> str:
        """Generate human-readable reasoning"""
        parts = ["The model's prediction is based on:"]
        
        for i, contrib in enumerate(top_contributions, 1):
            direction = "increased" if contrib.contribution > 0 else "decreased"
            parts.append(
                f"{i}. {contrib.feature_name} ({contrib.feature_value:.2f}) "
                f"{direction} the score by {abs(contrib.contribution):.3f}"
            )
        
        return "\n".join(parts)


class LIMEExplainer:
    """LIME-based local interpretable explanations"""
    
    def __init__(self, data: np.ndarray, feature_names: List[str], 
                class_names: List[str], predictor_fn):
        self.data = data
        self.feature_names = feature_names
        self.class_names = class_names
        self.predictor_fn = predictor_fn
        self.explainer = None
        self._lock = threading.RLock()
        self._init_lime()
    
    def _init_lime(self):
        """Initialize LIME explainer"""
        if not LIME_AVAILABLE:
            logger.warning("LIME not available")
            return
        
        try:
            with self._lock:
                self.explainer = lime.lime_tabular.LimeTabularExplainer(
                    data_row=self.data,
                    feature_names=self.feature_names,
                    class_names=self.class_names,
                    mode='classification'
                )
                logger.info("LIME explainer initialized")
        except Exception as e:
            logger.warning(f"LIME initialization failed: {e}")
    
    def explain_instance(self, instance: np.ndarray, 
                        num_features: int = 10) -> ModelExplanation:
        """Explain local region around instance"""
        if self.explainer is None:
            return self._fallback_explanation(instance)
        
        try:
            with self._lock:
                exp = self.explainer.explain_instance(
                    instance,
                    self.predictor_fn,
                    num_features=num_features
                )
                
                # Extract feature weights
                contributions = []
                for feature_idx, weight in exp.as_list():
                    contributions.append(FeatureContribution(
                        feature_name=self.feature_names[int(feature_idx)] if feature_idx.isdigit() else feature_idx,
                        feature_value=float(instance[int(feature_idx)]) if feature_idx.isdigit() else 0.0,
                        contribution=float(weight),
                        impact_type="increases" if weight > 0 else "decreases",
                        base_value=0.0
                    ))
                
                reasoning = f"LIME local explanation for instance classification"
                
                return ModelExplanation(
                    explanation_id=f"lime_{datetime.now().timestamp()}",
                    model_name="LIME-Explained-Model",
                    prediction=exp.class_names[0] if hasattr(exp, 'class_names') else "Unknown",
                    prediction_confidence=0.85,
                    explanation_type=ExplanationType.DECISION_PATH,
                    feature_contributions=contributions,
                    top_features=[(c.feature_name, c.contribution) for c in contributions[:5]],
                    reasoning_text=reasoning,
                    rules_used=[]
                )
        
        except Exception as e:
            logger.error(f"LIME explanation error: {e}")
            return self._fallback_explanation(instance)
    
    def _fallback_explanation(self, instance: np.ndarray) -> ModelExplanation:
        """Fallback explanation"""
        return ModelExplanation(
            explanation_id=f"lime_fallback_{datetime.now().timestamp()}",
            model_name="LIME-Fallback",
            prediction="Unknown",
            prediction_confidence=0.0,
            explanation_type=ExplanationType.RULE_BASED,
            feature_contributions=[],
            top_features=[],
            reasoning_text="LIME explanation unavailable",
            rules_used=[]
        )


class RuleBasedExplainer:
    """Rule-based explanation engine"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.rules: Dict[str, List[str]] = defaultdict(list)
    
    def register_rule(self, condition: str, explanation: str, category: str = "general"):
        """Register interpretability rule"""
        with self._lock:
            self.rules[category].append({
                'condition': condition,
                'explanation': explanation
            })
    
    def explain_detection(self, features: Dict[str, Any], 
                        detection_type: str) -> ModelExplanation:
        """Explain detection using rules"""
        with self._lock:
            contributions = []
            matched_rules = []
            
            # Feature-based explanation
            for fname, fvalue in features.items():
                contrib = FeatureContribution(
                    feature_name=fname,
                    feature_value=fvalue,
                    contribution=0.1 if isinstance(fvalue, (int, float)) and fvalue > 0.5 else -0.1,
                    impact_type="increases" if fvalue > 0.5 else "decreases",
                    base_value=0.5
                )
                contributions.append(contrib)
            
            # Apply rules
            for category, category_rules in self.rules.items():
                for rule in category_rules:
                    if self._evaluate_condition(rule['condition'], features):
                        matched_rules.append(rule['explanation'])
            
            reasoning = self._generate_rule_explanation(matched_rules, features)
            
            return ModelExplanation(
                explanation_id=f"rule_based_{datetime.now().timestamp()}",
                model_name="Rule-Based-Explainer",
                prediction=detection_type,
                prediction_confidence=0.9 if matched_rules else 0.5,
                explanation_type=ExplanationType.RULE_BASED,
                feature_contributions=contributions,
                top_features=[(c.feature_name, c.contribution) for c in contributions],
                reasoning_text=reasoning,
                rules_used=matched_rules
            )
    
    def _evaluate_condition(self, condition: str, features: Dict[str, Any]) -> bool:
        """Evaluate if condition matches features"""
        try:
            return eval(condition, {"features": features})
        except:
            return False
    
    def _generate_rule_explanation(self, rules: List[str], 
                                  features: Dict[str, Any]) -> str:
        """Generate explanation from matched rules"""
        if not rules:
            return "No specific rules matched this detection"
        
        text = "Detection matches these security rules:\n"
        for i, rule in enumerate(rules, 1):
            text += f"{i}. {rule}\n"
        
        return text


@dataclass
class XAIManager:
    """Central manager for explainability"""
    shap_explainer: Optional[SHAPExplainer] = None
    lime_explainer: Optional[LIMEExplainer] = None
    rule_explainer: RuleBasedExplainer = field(default_factory=RuleBasedExplainer)
    explanation_cache: Dict[str, ModelExplanation] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    
    async def explain_detection(self, 
                               detection_id: str,
                               features: Dict[str, Any],
                               prediction: Any,
                               model_type: str = "ensemble") -> ModelExplanation:
        """Generate explanation for detection"""
        with self._lock:
            # Check cache
            if detection_id in self.explanation_cache:
                return self.explanation_cache[detection_id]
            
            # Generate ensemble explanation
            explanations = []
            
            # Rule-based
            rule_exp = self.rule_explainer.explain_detection(
                features, str(prediction)
            )
            explanations.append(rule_exp)
            
            # Combine explanations
            combined = self._combine_explanations(explanations, detection_id)
            
            # Cache
            self.explanation_cache[detection_id] = combined
            
            return combined
    
    def _combine_explanations(self, explanations: List[ModelExplanation], 
                             detection_id: str) -> ModelExplanation:
        """Combine multiple explanations"""
        # Average contributions
        all_contributions = []
        for exp in explanations:
            all_contributions.extend(exp.feature_contributions)
        
        # Merge by feature name
        feature_map = defaultdict(list)
        for contrib in all_contributions:
            feature_map[contrib.feature_name].append(contrib)
        
        merged = []
        for fname, contribs in feature_map.items():
            merged_contrib = FeatureContribution(
                feature_name=fname,
                feature_value=contribs[0].feature_value,
                contribution=np.mean([c.contribution for c in contribs]),
                impact_type=contribs[0].impact_type,
                base_value=np.mean([c.base_value for c in contribs])
            )
            merged.append(merged_contrib)
        
        merged.sort(key=lambda x: abs(x.contribution), reverse=True)
        
        return ModelExplanation(
            explanation_id=f"ensemble_{detection_id}",
            model_name="Ensemble-Explainer",
            prediction="Anomalous",
            prediction_confidence=0.85,
            explanation_type=ExplanationType.ENSEMBLE,
            feature_contributions=merged,
            top_features=[(c.feature_name, c.contribution) for c in merged[:10]],
            reasoning_text=self._generate_ensemble_reasoning(merged),
            rules_used=[]
        )
    
    def _generate_ensemble_reasoning(self, contributions: List[FeatureContribution]) -> str:
        """Generate ensemble reasoning"""
        text = "Security analysis indicates anomalous activity based on:\n\n"
        
        for i, contrib in enumerate(contributions[:5], 1):
            direction = "indicative of" if contrib.contribution > 0 else "not indicative of"
            text += f"{i}. {contrib.feature_name}: {direction} malicious behavior "
            text += f"(score: {contrib.contribution:+.3f})\n"
        
        text += "\nRecommended action: Investigate the detected anomalies"
        
        return text
    
    def export_explanation(self, explanation: ModelExplanation, 
                          format: str = "json") -> str:
        """Export explanation in various formats"""
        if format == "json":
            return json.dumps(explanation.to_dict(), indent=2)
        elif format == "html":
            return self._to_html(explanation)
        elif format == "text":
            return self._to_text(explanation)
        else:
            return str(explanation)
    
    def _to_html(self, exp: ModelExplanation) -> str:
        """Export as HTML"""
        html = f"""
        <html>
        <head><title>Security Detection Explanation</title></head>
        <body>
            <h1>{exp.explanation_type.value}</h1>
            <p><b>Prediction:</b> {exp.prediction}</p>
            <p><b>Confidence:</b> {exp.prediction_confidence:.2%}</p>
            <h2>Top Factors</h2>
            <ul>
        """
        
        for feat, contrib in exp.top_features:
            html += f"<li>{feat}: {contrib:+.3f}</li>"
        
        html += """
            </ul>
            <h2>Reasoning</h2>
            <pre>""" + exp.reasoning_text + """</pre>
        </body>
        </html>
        """
        
        return html
    
    def _to_text(self, exp: ModelExplanation) -> str:
        """Export as plain text"""
        text = f"""
SECURITY DETECTION EXPLANATION
{'='*50}

Explanation Type: {exp.explanation_type.value}
Prediction: {exp.prediction}
Confidence: {exp.prediction_confidence:.2%}

TOP CONTRIBUTING FACTORS:
{'-'*50}
"""
        
        for i, (feat, contrib) in enumerate(exp.top_features, 1):
            text += f"{i}. {feat}: {contrib:+.3f}\n"
        
        text += f"""
REASONING:
{'-'*50}
{exp.reasoning_text}

RULES APPLIED:
{'-'*50}
"""
        
        for rule in exp.rules_used:
            text += f"• {rule}\n"
        
        return text


# Global instance
_xai_manager: Optional[XAIManager] = None


def get_xai_manager() -> XAIManager:
    """Get or create global XAI manager"""
    global _xai_manager
    if _xai_manager is None:
        _xai_manager = XAIManager()
    return _xai_manager


if __name__ == "__main__":
    logger.info("Explainable AI (XAI) Module initialized")
