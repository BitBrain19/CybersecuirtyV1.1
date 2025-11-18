"""
Compliance Mapping Engine
Maps security detections to NIST 800-53, ISO 27001, SOC2, GDPR controls
"""

import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    """Compliance frameworks"""
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    GDPR = "gdpr"


@dataclass
class ComplianceControl:
    """Compliance control"""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    objectives: List[str]
    implementation_required: bool


@dataclass
class ComplianceMapping:
    """Maps detection to compliance control"""
    detection_id: str
    detection_type: str
    mapped_controls: List[Tuple[str, float]]  # control_id, confidence
    frameworks_covered: Set[ComplianceFramework]
    timestamp: datetime = field(default_factory=datetime.now)


class ComplianceMappingEngine:
    """Maps security detections to compliance controls"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.nist_controls = self._load_nist_800_53()
        self.iso_controls = self._load_iso_27001()
        self.soc2_controls = self._load_soc2()
        self.gdpr_controls = self._load_gdpr()
    
    def _load_nist_800_53(self) -> Dict[str, ComplianceControl]:
        """Load NIST 800-53 controls"""
        return {
            'AC-2': ComplianceControl(
                'AC-2', ComplianceFramework.NIST_800_53,
                'Account Management',
                'Manage user accounts across the system',
                ['Account creation', 'Account removal', 'Privilege assignments'],
                True
            ),
            'AC-3': ComplianceControl(
                'AC-3', ComplianceFramework.NIST_800_53,
                'Access Enforcement',
                'Enforce approved access',
                ['Authorization', 'Access control', 'Policy enforcement'],
                True
            ),
            'AU-2': ComplianceControl(
                'AU-2', ComplianceFramework.NIST_800_53,
                'Audit Events',
                'Audit and accountability',
                ['Event logging', 'Activity recording', 'Trail generation'],
                True
            ),
            'SC-7': ComplianceControl(
                'SC-7', ComplianceFramework.NIST_800_53,
                'Boundary Protection',
                'Monitor communications at external boundaries',
                ['Firewall rules', 'IDS/IPS', 'Traffic filtering'],
                True
            ),
            'IA-2': ComplianceControl(
                'IA-2', ComplianceFramework.NIST_800_53,
                'Authentication',
                'Authenticate users and resources',
                ['MFA', 'Credential verification', 'Session management'],
                True
            ),
        }
    
    def _load_iso_27001(self) -> Dict[str, ComplianceControl]:
        """Load ISO 27001 controls"""
        return {
            'A.9.1.1': ComplianceControl(
                'A.9.1.1', ComplianceFramework.ISO_27001,
                'Access control policy',
                'Access control policy document',
                ['Policy creation', 'Access rules'],
                True
            ),
            'A.9.2.1': ComplianceControl(
                'A.9.2.1', ComplianceFramework.ISO_27001,
                'User registration',
                'User registration and de-registration',
                ['Account provisioning', 'Account deprovisioning'],
                True
            ),
            'A.12.4.1': ComplianceControl(
                'A.12.4.1', ComplianceFramework.ISO_27001,
                'Event logging',
                'Event logging',
                ['Logging', 'Monitoring', 'Audit trails'],
                True
            ),
        }
    
    def _load_soc2(self) -> Dict[str, ComplianceControl]:
        """Load SOC2 controls"""
        return {
            'CC6.1': ComplianceControl(
                'CC6.1', ComplianceFramework.SOC2,
                'Logical access controls',
                'Implement logical access controls',
                ['Authentication', 'Authorization', 'Access management'],
                True
            ),
            'CC7.2': ComplianceControl(
                'CC7.2', ComplianceFramework.SOC2,
                'System monitoring',
                'Monitor systems and network',
                ['Logging', 'Monitoring', 'Alerting'],
                True
            ),
        }
    
    def _load_gdpr(self) -> Dict[str, ComplianceControl]:
        """Load GDPR controls"""
        return {
            'Article 32': ComplianceControl(
                'Article 32', ComplianceFramework.GDPR,
                'Security of processing',
                'Implement appropriate technical and organizational measures',
                ['Encryption', 'Integrity', 'Confidentiality', 'Availability'],
                True
            ),
            'Article 33': ComplianceControl(
                'Article 33', ComplianceFramework.GDPR,
                'Notification of breach',
                'Notify supervisory authority without undue delay',
                ['Breach notification', 'Incident response', 'Forensics'],
                True
            ),
        }
    
    def map_detection_to_controls(self, detection_type: str) -> ComplianceMapping:
        """Map detection to compliance controls"""
        with self._lock:
            mapped_controls = []
            
            # Rule-based mapping
            mapping_rules = {
                'unauthorized_access': [
                    ('AC-2', 0.9), ('AC-3', 0.9),
                    ('A.9.1.1', 0.8), ('CC6.1', 0.9)
                ],
                'privilege_escalation': [
                    ('AC-2', 0.95), ('IA-2', 0.8),
                    ('A.9.2.1', 0.7), ('CC6.1', 0.85)
                ],
                'data_exfiltration': [
                    ('SC-7', 0.9), ('Article 32', 0.95),
                    ('Article 33', 0.9), ('CC7.2', 0.8)
                ],
                'malware_detected': [
                    ('SC-7', 0.95), ('AU-2', 0.9),
                    ('Article 32', 0.85), ('CC7.2', 0.95)
                ],
                'policy_violation': [
                    ('AC-2', 0.7), ('A.9.1.1', 0.8),
                    ('CC6.1', 0.75)
                ],
                'audit_log_tampering': [
                    ('AU-2', 0.99), ('A.12.4.1', 0.95),
                    ('CC7.2', 0.95), ('Article 32', 0.85)
                ]
            }
            
            detection_lower = detection_type.lower()
            
            for rule_type, controls in mapping_rules.items():
                if rule_type in detection_lower:
                    mapped_controls.extend(controls)
            
            # Collect frameworks
            frameworks = set()
            for control_id, _ in mapped_controls:
                for control in [*self.nist_controls.values(), *self.iso_controls.values(),
                              *self.soc2_controls.values(), *self.gdpr_controls.values()]:
                    if control.control_id == control_id:
                        frameworks.add(control.framework)
            
            return ComplianceMapping(
                detection_id=f"detection_{datetime.now().timestamp()}",
                detection_type=detection_type,
                mapped_controls=mapped_controls,
                frameworks_covered=frameworks
            )
    
    def get_remediation_checklist(self, detection_type: str) -> Dict[str, List[str]]:
        """Get compliance remediation checklist"""
        mapping = self.map_detection_to_controls(detection_type)
        
        checklist = defaultdict(list)
        
        # Add remediation items per framework
        for framework in mapping.frameworks_covered:
            if framework == ComplianceFramework.NIST_800_53:
                checklist[framework.value].extend([
                    'Review and update access control policies',
                    'Audit user accounts and permissions',
                    'Enable comprehensive logging',
                    'Implement network monitoring',
                    'Verify authentication mechanisms'
                ])
            elif framework == ComplianceFramework.ISO_27001:
                checklist[framework.value].extend([
                    'Review access control procedures',
                    'Update user registration processes',
                    'Enable audit logging',
                    'Conduct risk assessment',
                    'Document control implementation'
                ])
            elif framework == ComplianceFramework.SOC2:
                checklist[framework.value].extend([
                    'Validate logical access controls',
                    'Review system monitoring',
                    'Test incident response',
                    'Verify user provisioning',
                    'Review monitoring logs'
                ])
            elif framework == ComplianceFramework.GDPR:
                checklist[framework.value].extend([
                    'Implement encryption',
                    'Establish incident response plan',
                    'Notify supervisory authority if required',
                    'Document data processing',
                    'Review data retention policies'
                ])
        
        return dict(checklist)
    
    def get_compliance_report(self, detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance report from detections"""
        with self._lock:
            framework_coverage = defaultdict(set)
            control_hits = defaultdict(int)
            
            for detection in detections:
                mapping = self.map_detection_to_controls(detection.get('type', 'unknown'))
                
                for framework in mapping.frameworks_covered:
                    framework_coverage[framework.value].add(mapping.detection_id)
                
                for control_id, confidence in mapping.mapped_controls:
                    control_hits[control_id] += 1
            
            report = {
                'report_date': datetime.now().isoformat(),
                'total_detections': len(detections),
                'frameworks_covered': {
                    fw: len(dets) for fw, dets in framework_coverage.items()
                },
                'top_controls_triggered': sorted(
                    control_hits.items(), key=lambda x: x[1], reverse=True
                )[:10],
                'compliance_status': 'NEEDS_ATTENTION' if len(detections) > 5 else 'COMPLIANT'
            }
            
            return report


# Global instance
_compliance_engine: Optional[ComplianceMappingEngine] = None


def get_compliance_engine() -> ComplianceMappingEngine:
    """Get or create global compliance engine"""
    global _compliance_engine
    if _compliance_engine is None:
        _compliance_engine = ComplianceMappingEngine()
    return _compliance_engine


if __name__ == "__main__":
    logger.info("Compliance Mapping Engine initialized")
