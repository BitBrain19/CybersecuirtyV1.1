"""
Compliance Assessment Model
===========================

A rule-based model for assessing system compliance against various standards.
"""

from typing import Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ComplianceResult:
    score: float
    status: str
    issues: List[str]
    compliant: bool
    framework: str

class ComplianceModel:
    """
    Assesses system compliance based on provided configuration and state.
    """
    
    def __init__(self):
        self.frameworks = {
            "PCI-DSS": self._check_pci_dss,
            "HIPAA": self._check_hipaa,
            "GDPR": self._check_gdpr,
            "NIST": self._check_nist
        }
        
    async def assess_compliance(self, features: Dict[str, Any]) -> ComplianceResult:
        """
        Assess compliance for a given framework.
        """
        framework = features.get("framework", "NIST")
        check_func = self.frameworks.get(framework, self._check_nist)
        
        return await check_func(features)
        
    async def _check_pci_dss(self, features: Dict[str, Any]) -> ComplianceResult:
        issues = []
        score = 100.0
        
        # Simulated checks
        if not features.get("encryption_enabled", False):
            issues.append("Encryption not enabled for data at rest")
            score -= 30
            
        if not features.get("firewall_enabled", False):
            issues.append("Firewall not active")
            score -= 20
            
        if features.get("password_policy_weak", False):
            issues.append("Weak password policy detected")
            score -= 15
            
        return ComplianceResult(
            score=max(0.0, score),
            status="compliant" if score >= 80 else "non_compliant",
            issues=issues,
            compliant=score == 100,
            framework="PCI-DSS"
        )

    async def _check_hipaa(self, features: Dict[str, Any]) -> ComplianceResult:
        issues = []
        score = 100.0
        
        if not features.get("audit_logging_enabled", False):
            issues.append("Audit logging disabled")
            score -= 40
            
        if not features.get("access_control_strict", False):
            issues.append("Access control not strict enough")
            score -= 30
            
        return ComplianceResult(
            score=max(0.0, score),
            status="compliant" if score >= 90 else "non_compliant",
            issues=issues,
            compliant=score == 100,
            framework="HIPAA"
        )

    async def _check_gdpr(self, features: Dict[str, Any]) -> ComplianceResult:
        issues = []
        score = 100.0
        
        if not features.get("data_consent_recorded", False):
            issues.append("User consent not recorded")
            score -= 50
            
        if not features.get("data_retention_policy", False):
            issues.append("Data retention policy missing")
            score -= 20
            
        return ComplianceResult(
            score=max(0.0, score),
            status="compliant" if score >= 85 else "non_compliant",
            issues=issues,
            compliant=score == 100,
            framework="GDPR"
        )
        
    async def _check_nist(self, features: Dict[str, Any]) -> ComplianceResult:
        issues = []
        score = 100.0
        
        # Generic checks
        if features.get("vulnerabilities_count", 0) > 5:
            issues.append("Too many active vulnerabilities")
            score -= 25
            
        if not features.get("mfa_enabled", False):
            issues.append("MFA not enabled for admins")
            score -= 25
            
        return ComplianceResult(
            score=max(0.0, score),
            status="compliant" if score >= 70 else "non_compliant",
            issues=issues,
            compliant=score >= 90,
            framework="NIST"
        )

# Factory function for dynamic loading
def get_compliance_model():
    return ComplianceModel()
