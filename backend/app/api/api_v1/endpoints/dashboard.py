from typing import Any, List

from fastapi import APIRouter, Depends, Query

from app.core.auth import get_current_user
from app.models.user import User

router = APIRouter()


@router.get("/", response_model=dict)
async def get_dashboard(
    current_user: User = Depends(get_current_user),
) -> Any:
    return {
        "securityScore": 82,
        "securityScoreTrend": 3,
        "vulnerabilitiesCount": 127,
        "vulnerabilitiesTrend": -4,
        "attackPathsCount": 12,
        "attackPathsTrend": 1,
        "alertsCount": 56,
        "alertsTrend": 8,
        "criticalVulnerabilities": 9,
        "vulnerabilitiesByType": [
            {"category": "Network", "count": 38},
            {"category": "Application", "count": 54},
            {"category": "Configuration", "count": 35},
        ],
        "vulnerabilityDistribution": [
            {"name": "Critical", "value": 9},
            {"name": "High", "value": 31},
            {"name": "Medium", "value": 58},
            {"name": "Low", "value": 29},
        ],
        "alertsOverTime": [
            {"date": "2025-11-01", "count": 5},
            {"date": "2025-11-02", "count": 7},
            {"date": "2025-11-03", "count": 8},
            {"date": "2025-11-04", "count": 6},
            {"date": "2025-11-05", "count": 10},
        ],
        "recentAlerts": [
            {
                "id": "A-1001",
                "title": "Unauthorized access attempt detected",
                "description": "Multiple failed login attempts from external IP",
                "severity": "high",
                "timestamp": "2025-11-13T10:05:00Z",
                "status": "new",
            },
            {
                "id": "A-1002",
                "title": "Suspicious process behavior",
                "description": "Process spawned network connections unexpectedly",
                "severity": "medium",
                "timestamp": "2025-11-13T09:42:00Z",
                "status": "acknowledged",
            },
        ],
        "topVulnerabilities": [
            {
                "id": "V-2001",
                "name": "Outdated OpenSSL library",
                "severity": "high",
                "affectedAssets": 14,
                "discoveredAt": "2025-11-10T12:00:00Z",
            },
            {
                "id": "V-2002",
                "name": "Weak admin credentials",
                "severity": "critical",
                "affectedAssets": 3,
                "discoveredAt": "2025-11-09T08:30:00Z",
            },
        ],
        "systemHealth": {
            "cpu": 37,
            "memory": 62,
            "storage": 71,
            "lastUpdated": "2025-11-13T10:10:00Z",
        },
    }


@router.get("/summary", response_model=dict)
async def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
) -> Any:
    return {
        "total_alerts": 56,
        "critical_alerts": 7,
        "high_alerts": 15,
        "medium_alerts": 22,
        "low_alerts": 12,
        "total_vulnerabilities": 127,
        "total_assets": 342,
        "compliance_score": 86,
        "risk_score": 64,
        "attack_paths": 12,
    }


@router.get("/trends", response_model=List[dict])
async def get_trends(
    timeframe: str = Query("week", regex="^(day|week|month)$"),
    current_user: User = Depends(get_current_user),
) -> Any:
    # Stub trend data by timeframe
    data = {
        "day": [
            {"date": "2025-11-13", "alerts": 10, "vulnerabilities": 3, "risk_score": 64},
        ],
        "week": [
            {"date": "2025-11-07", "alerts": 6, "vulnerabilities": 2, "risk_score": 60},
            {"date": "2025-11-09", "alerts": 8, "vulnerabilities": 4, "risk_score": 62},
            {"date": "2025-11-11", "alerts": 7, "vulnerabilities": 3, "risk_score": 63},
            {"date": "2025-11-13", "alerts": 10, "vulnerabilities": 3, "risk_score": 64},
        ],
        "month": [
            {"date": "2025-10-15", "alerts": 120, "vulnerabilities": 45, "risk_score": 58},
            {"date": "2025-11-13", "alerts": 220, "vulnerabilities": 82, "risk_score": 64},
        ],
    }
    return data.get(timeframe, data["week"])


@router.get("/severity-distribution", response_model=List[dict])
async def get_severity_distribution(
    current_user: User = Depends(get_current_user),
) -> Any:
    return [
        {"severity": "critical", "count": 9},
        {"severity": "high", "count": 31},
        {"severity": "medium", "count": 58},
        {"severity": "low", "count": 29},
    ]


@router.get("/compliance-status", response_model=List[dict])
async def get_compliance_status(
    current_user: User = Depends(get_current_user),
) -> Any:
    return [
        {"framework": "ISO 27001", "score": 86, "total_controls": 114, "passed_controls": 98, "failed_controls": 16},
        {"framework": "NIST CSF", "score": 79, "total_controls": 108, "passed_controls": 85, "failed_controls": 23},
    ]


@router.get("/top-vulnerabilities", response_model=List[dict])
async def get_top_vulnerabilities(
    limit: int = Query(5, ge=1, le=50),
    current_user: User = Depends(get_current_user),
) -> Any:
    items = [
        {"id": "V-2001", "name": "Outdated OpenSSL library", "severity": "high", "cvss_score": 7.8, "affected_assets_count": 14, "exploit_available": True},
        {"id": "V-2002", "name": "Weak admin credentials", "severity": "critical", "cvss_score": 9.2, "affected_assets_count": 3, "exploit_available": True},
        {"id": "V-2003", "name": "Unpatched kernel", "severity": "medium", "cvss_score": 6.5, "affected_assets_count": 22, "exploit_available": False},
        {"id": "V-2004", "name": "Exposed S3 bucket", "severity": "high", "cvss_score": 8.1, "affected_assets_count": 5, "exploit_available": False},
        {"id": "V-2005", "name": "Outdated nginx", "severity": "low", "cvss_score": 3.5, "affected_assets_count": 18, "exploit_available": False},
    ]
    return items[:limit]


@router.get("/recent-alerts", response_model=List[dict])
async def get_recent_alerts(
    limit: int = Query(5, ge=1, le=50),
    current_user: User = Depends(get_current_user),
) -> Any:
    items = [
        {"id": "A-1001", "title": "Unauthorized access attempt detected", "severity": "high", "timestamp": "2025-11-13T10:05:00Z", "status": "new"},
        {"id": "A-1002", "title": "Suspicious process behavior", "severity": "medium", "timestamp": "2025-11-13T09:42:00Z", "status": "acknowledged"},
        {"id": "A-1003", "title": "Multiple failed logins", "severity": "low", "timestamp": "2025-11-13T09:01:00Z", "status": "resolved"},
    ]
    return items[:limit]


@router.get("/asset-risk-distribution", response_model=List[dict])
async def get_asset_risk_distribution(
    current_user: User = Depends(get_current_user),
) -> Any:
    return [
        {"risk": "low", "count": 120},
        {"risk": "medium", "count": 180},
        {"risk": "high", "count": 42},
    ]


@router.get("/attack-surface-metrics", response_model=dict)
async def get_attack_surface_metrics(
    current_user: User = Depends(get_current_user),
) -> Any:
    return {
        "open_ports": 245,
        "public_endpoints": 34,
        "exposed_services": 12,
        "weak_ciphers": 5,
    }