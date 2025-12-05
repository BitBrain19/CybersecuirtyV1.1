from typing import List, Optional, Dict, Any
import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel

from app.core.auth import get_current_user
from app.models.user import User
from app.services.ml_client import ml_client

logger = logging.getLogger(__name__)
router = APIRouter()

# ==================== Pydantic Models ====================

class AttackPathRequest(BaseModel):
    source_node: str
    target_node: str
    context: Optional[Dict[str, Any]] = None

class AttackPathStep(BaseModel):
    step_id: str
    description: str
    technique: Optional[str] = None

class AttackPath(BaseModel):
    id: str
    name: str
    source: str
    target: str
    steps: List[str]
    risk_score: float
    probability: float
    status: str = "open"
    discovered_at: datetime = datetime.now()

class SimulationResponse(BaseModel):
    simulation_id: str
    paths_found: int
    top_path: Optional[AttackPath] = None
    message: str

# ==================== Endpoints ====================

@router.get("/", response_model=List[AttackPath])
async def get_attack_paths(
    current_user: User = Depends(get_current_user)
):
    """
    Get a list of potential attack paths.
    
    Currently triggers a real-time analysis for critical assets.
    """
    # In a real system, this would fetch from a DB of previously discovered paths.
    # For this remediation, we will query the ML model for a default critical path
    # to demonstrate connectivity.
    
    try:
        # Example: Check path from Internet to Database
        result = await ml_client.predict(
            model_name="attack_path",
            features={
                "source_node": "internet_gateway",
                "target_node": "production_database",
                "scan_mode": "quick"
            }
        )
        
        paths = []
        if result and result.get("paths"):
            for idx, p in enumerate(result["paths"]):
                paths.append(AttackPath(
                    id=f"path-{idx}",
                    name=f"Internet to DB Path {idx+1}",
                    source="internet_gateway",
                    target="production_database",
                    steps=p.get("steps", []),
                    risk_score=p.get("risk_score", 0.0),
                    probability=p.get("probability", 0.0),
                    status="open",
                    discovered_at=datetime.now()
                ))
        
        return paths

    except Exception as e:
        logger.error(f"Failed to fetch attack paths: {e}")
        # Return empty list instead of erroring out completely if ML is down, 
        # but log the error.
        return []


@router.post("/simulate", response_model=SimulationResponse)
async def simulate_attack_path(
    request: AttackPathRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Simulate an attack path between two nodes using the ML model.
    """
    simulation_id = str(uuid.uuid4())
    
    try:
        logger.info(f"Starting attack path simulation {simulation_id}: {request.source_node} -> {request.target_node}")
        
        result = await ml_client.predict(
            model_name="attack_path",
            features={
                "source_node": request.source_node,
                "target_node": request.target_node,
                "context": request.context or {}
            },
            request_id=simulation_id
        )
        
        paths_found = result.get("paths_found", 0)
        top_path = None
        
        if paths_found > 0 and result.get("paths"):
            first_path = result["paths"][0]
            top_path = AttackPath(
                id=f"sim-{simulation_id}",
                name=f"Simulated: {request.source_node} to {request.target_node}",
                source=request.source_node,
                target=request.target_node,
                steps=first_path.get("steps", []),
                risk_score=first_path.get("risk_score", 0.0),
                probability=first_path.get("probability", 0.0)
            )
            
        return SimulationResponse(
            simulation_id=simulation_id,
            paths_found=paths_found,
            top_path=top_path,
            message="Simulation completed successfully"
        )

    except Exception as e:
        logger.error(f"Simulation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Simulation failed: {str(e)}"
        )


@router.get("/mitre-techniques", response_model=List[dict])
async def get_mitre_techniques(current_user: User = Depends(get_current_user)):
    """
    Get MITRE techniques from the ML model (MITRE Mapper).
    """
    try:
        # Use the MITRE Mapping model to get a list of relevant techniques
        # We pass a dummy event to get general techniques or a specific query if supported
        result = await ml_client.predict(
            model_name="mitre_mapping",
            features={
                "event_type": "discovery",
                "description": "list_all_techniques" 
            }
        )
        
        # Transform result to list
        techniques = []
        if result and result.get("techniques"):
            for t_id in result["techniques"]:
                techniques.append({"id": t_id, "name": "Technique " + t_id}) # Name might need lookup
                
        return techniques or [{"id": "T0000", "name": "No techniques found"}]

    except Exception as e:
        logger.error(f"Failed to get MITRE techniques: {e}")
        return []