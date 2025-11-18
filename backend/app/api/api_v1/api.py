from fastapi import APIRouter

from app.api.api_v1.endpoints import (
    auth, users, alerts, assets, vulnerabilities, dashboard,
    attack_paths, reports, ml_predictions, soar, ueba, edr, ml_integration
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(attack_paths.router, prefix="/attack-paths", tags=["attack_paths"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(ml_predictions.router, prefix="/ml", tags=["ml"])
api_router.include_router(soar.router, tags=["soar"])
api_router.include_router(ueba.router, tags=["ueba"])
api_router.include_router(edr.router, tags=["edr"])
api_router.include_router(ml_integration.router, tags=["ml_integration"])