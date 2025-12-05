import httpx
import logging
from typing import Dict, Any, List, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class MLClient:
    """Client for communicating with the ML Service."""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or settings.ML_SERVICE_URL
        self.timeout = 30.0

    async def _request(self, method: str, endpoint: str, data: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Any:
        """Make an HTTP request to the ML service."""
        url = f"{self.base_url}{endpoint}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.request(method, url, json=data, params=params)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"ML Service HTTP error: {e.response.status_code} - {e.response.text}")
                raise
            except httpx.RequestError as e:
                logger.error(f"ML Service connection error: {e}")
                raise

    async def predict(self, model_name: str, features: Dict[str, Any], request_id: str = None) -> Dict[str, Any]:
        """Make a prediction using the ML service."""
        payload = {
            "model_name": model_name,
            "features": features,
            "request_id": request_id
        }
        return await self._request("POST", "/predict", data=payload)

    async def submit_stream_event(self, event_data: Dict[str, Any], event_type: str = "network_traffic", source: str = "unknown") -> Dict[str, Any]:
        """Submit a stream event for real-time analysis."""
        payload = {
            "event_type": event_type,
            "source": source,
            "data": event_data
        }
        return await self._request("POST", "/stream/events", data=payload)

    # SOAR Methods
    async def get_soar_workflows(self) -> List[Dict[str, Any]]:
        """Get available SOAR workflows."""
        # Note: The ML service might not expose this directly yet, 
        # but we'll implement the client method anticipating the endpoint or use a workaround.
        # For now, we might need to mock this if the ML service doesn't have a direct endpoint for listing workflows
        # distinct from the backend's database. 
        # Checking ml/app/main.py, there isn't a direct /workflows endpoint.
        # However, the backend was trying to import `get_workflow_engine`.
        # We might need to add endpoints to ML service or assume the backend manages workflows and just asks ML for decisions.
        # Let's assume for now we just need health check to confirm connectivity.
        return []

    async def get_alerts(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Get alerts from the ML service."""
        return await self._request("GET", "/alerts", params={"active_only": active_only})

    async def check_health(self) -> Dict[str, Any]:
        """Check ML service health."""
        return await self._request("GET", "/health")

# Global instance
ml_client = MLClient()
