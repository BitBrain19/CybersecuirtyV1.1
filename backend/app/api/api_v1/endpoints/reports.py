from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from datetime import datetime
import uuid

from app.core.auth import get_current_user

router = APIRouter()

# In-memory store for demo purposes
_reports_store: Dict[str, Dict[str, Any]] = {}

# Seed a few placeholder reports for the frontend
def _seed_reports():
    if _reports_store:
        return
    now = datetime.utcnow().isoformat()
    samples = [
        {
            "id": str(uuid.uuid4()),
            "name": "Executive Summary",
            "description": "High-level overview of security posture",
            "type": "executive",
            "status": "completed",
            "created_at": now,
            "completed_at": now,
            "created_by": "admin@example.com",
            "file_url": "/files/reports/executive-summary.txt",
            "parameters": {},
            "progress": 100,
            "generatedAt": now,
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Threat Intelligence",
            "description": "Recent threats and activity",
            "type": "threat",
            "status": "completed",
            "created_at": now,
            "completed_at": now,
            "created_by": "admin@example.com",
            "file_url": "/files/reports/threat-intel.txt",
            "parameters": {},
            "progress": 100,
            "generatedAt": now,
        },
    ]
    for r in samples:
        _reports_store[r["id"]] = r


@router.get("/", response_model=Dict[str, Any])
def list_reports(
    page: int = 1,
    limit: int = 10,
    type: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """List reports with optional filters."""
    _seed_reports()
    items = list(_reports_store.values())

    # Filtering
    if type:
        items = [i for i in items if i.get("type") in set(type)]
    if status:
        items = [i for i in items if i.get("status") in set(status)]
    if search:
        s = search.lower()
        items = [
            i for i in items
            if s in i.get("name", "").lower() or s in i.get("description", "").lower()
        ]
    # Date range filter (created_at)
    def _parse_dt(v: Optional[str]) -> Optional[datetime]:
        if not v:
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None

    start_dt = _parse_dt(start_date)
    end_dt = _parse_dt(end_date)
    if start_dt or end_dt:
        filtered = []
        for i in items:
            try:
                created = datetime.fromisoformat(i.get("created_at", "").replace("Z", "+00:00"))
            except Exception:
                continue
            if start_dt and created < start_dt:
                continue
            if end_dt and created > end_dt:
                continue
            filtered.append(i)
        items = filtered

    total = len(items)
    start = max(0, (page - 1) * limit)
    end = start + limit
    return {
        "reports": items[start:end],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/templates", response_model=List[Dict[str, Any]])
def get_templates(current_user: Dict[str, Any] = Depends(get_current_user)) -> List[Dict[str, Any]]:
    return [
        {
            "id": "exec-summary",
            "name": "Executive Summary Report",
            "description": "Overview of security posture and key indicators",
            "type": "executive",
            "parameters_schema": {},
        },
        {
            "id": "threat-intel",
            "name": "Threat Intelligence Report",
            "description": "Emerging threats and actor activity",
            "type": "threat",
            "parameters_schema": {},
        },
        {
            "id": "vuln-mgmt",
            "name": "Vulnerability Management Report",
            "description": "Vulnerability trends and remediation progress",
            "type": "vulnerability",
            "parameters_schema": {},
        },
    ]


@router.get("/{report_id}", response_model=Dict[str, Any])
def get_report(report_id: str, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    _seed_reports()
    report = _reports_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post("/generate", response_model=Dict[str, Any])
def generate_report(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    now = datetime.utcnow().isoformat()
    report_id = str(uuid.uuid4())
    name = payload.get("name") or f"Generated {payload.get('type', 'report').title()} Report"
    description = payload.get("description") or "Generated report"
    creator_email = getattr(current_user, "email", "admin@example.com")
    r = {
        "id": report_id,
        "name": name,
        "description": description,
        "type": payload.get("type") or "custom",
        "status": "completed",
        "created_at": now,
        "completed_at": now,
        "created_by": creator_email,
        "file_url": f"/files/reports/{report_id}.txt",
        "parameters": payload.get("parameters", {}),
        "progress": 100,
        "generatedAt": now,
    }
    _reports_store[report_id] = r
    return r


@router.get("/{report_id}/download")
def download_report(report_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    report = _reports_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    content = f"Report: {report.get('name')}\nType: {report.get('type')}\nGenerated: {report.get('completed_at')}\nDescription: {report.get('description')}\n"
    headers = {"Content-Disposition": f"attachment; filename=report-{report_id}.txt"}
    return PlainTextResponse(content=content, headers=headers, media_type="text/plain")


@router.delete("/{report_id}", status_code=204)
def delete_report(report_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    if report_id not in _reports_store:
        raise HTTPException(status_code=404, detail="Report not found")
    del _reports_store[report_id]
    return


@router.get("/{report_id}/status", response_model=Dict[str, Any])
def report_status(report_id: str, current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    report = _reports_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post("/schedule", response_model=Dict[str, Any])
def schedule_report(payload: Dict[str, Any], current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    schedule_id = str(uuid.uuid4())
    creator_email = getattr(current_user, "email", "admin@example.com")
    return {
        "id": schedule_id,
        "template_id": payload.get("template_id"),
        "name": payload.get("name"),
        "description": payload.get("description"),
        "parameters": payload.get("parameters", {}),
        "schedule": payload.get("schedule", {}),
        "status": "scheduled",
        "created_at": datetime.utcnow().isoformat(),
        "created_by": creator_email,
    }