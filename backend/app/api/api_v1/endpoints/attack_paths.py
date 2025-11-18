from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import get_current_user


router = APIRouter()


# Simple placeholder schemas (dicts) to avoid adding Pydantic models yet
def sample_attack_paths() -> List[dict]:
    return [
        {
            "id": 1,
            "name": "Workstation → DB via App Server",
            "severity": "high",
            "nodeCount": 5,
            "edgeCount": 4,
            "status": "open",
            "discoveredAt": "2024-11-01T10:30:00Z",
        },
        {
            "id": 2,
            "name": "Phishing → Priv Esc → Domain Admin",
            "severity": "critical",
            "nodeCount": 7,
            "edgeCount": 6,
            "status": "open",
            "discoveredAt": "2024-11-03T08:12:00Z",
        },
        {
            "id": 3,
            "name": "Public Service → Misconfig → Internal API",
            "severity": "medium",
            "nodeCount": 4,
            "edgeCount": 3,
            "status": "acknowledged",
            "discoveredAt": "2024-11-05T14:50:00Z",
        },
    ]


@router.get("/", response_model=List[dict])
def get_attack_paths(current_user: dict = Depends(get_current_user)):
    """Return a list of attack paths. Placeholder implementation."""
    return sample_attack_paths()


@router.get("/{attack_path_id}", response_model=dict)
def get_attack_path_by_id(attack_path_id: int, current_user: dict = Depends(get_current_user)):
    """Return a single attack path by id. Placeholder implementation."""
    paths = sample_attack_paths()
    for p in paths:
        if p["id"] == attack_path_id:
            return p
    raise HTTPException(status_code=404, detail="Attack path not found")


@router.get("/statistics", response_model=dict)
def get_attack_path_statistics(current_user: dict = Depends(get_current_user)):
    """Return basic statistics for attack paths. Placeholder implementation."""
    paths = sample_attack_paths()
    total = len(paths)
    severities = {}
    for p in paths:
        severities[p["severity"]] = severities.get(p["severity"], 0) + 1
    return {"total": total, "bySeverity": severities}


@router.get("/mitre-techniques", response_model=List[dict])
def get_mitre_techniques(current_user: dict = Depends(get_current_user)):
    """Return a placeholder list of MITRE ATT&CK techniques involved."""
    return [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
        {"id": "T1078", "name": "Valid Accounts"},
    ]


@router.post("/simulate", response_model=dict)
def simulate_attack_path(current_user: dict = Depends(get_current_user)):
    """Simulate an attack path. Placeholder implementation."""
    return {"status": "ok", "message": "Simulation queued"}


@router.patch("/{attack_path_id}/status", response_model=dict)
def update_attack_path_status(
    attack_path_id: int,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Update an attack path status. Placeholder implementation."""
    if status not in {None, "open", "acknowledged", "dismissed", "resolved"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    return {"id": attack_path_id, "status": status or "open"}