import logging
from datetime import datetime

from app.worker import celery_app
from app.db.session import async_session_maker
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.alert import Alert
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset

logger = logging.getLogger(__name__)

@celery_app.task
async def scan_asset(asset_id: int):
    """Scan an asset for vulnerabilities"""
    logger.info(f"Scanning asset with ID: {asset_id}")
    
    try:
        # Get asset information
        async with async_session_maker() as session:
            asset = await session.get(Asset, asset_id)
            if not asset:
                logger.error(f"Asset with ID {asset_id} not found")
                return {"status": "error", "message": f"Asset with ID {asset_id} not found"}
            
            # Simulate vulnerability scanning
            # In a real implementation, this would call the ML service or external scanners
            vulnerabilities = await _simulate_vulnerability_scan(asset, session)
            
            return {
                "status": "success", 
                "message": f"Scan completed for asset {asset.name}",
                "vulnerabilities_found": len(vulnerabilities)
            }
    except Exception as e:
        logger.exception(f"Error scanning asset {asset_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

@celery_app.task
async def generate_security_report():
    """Generate a security report for all assets"""
    logger.info("Generating security report")
    
    try:
        async with async_session_maker() as session:
            # Get all assets
            assets = await session.query(Asset).all()
            
            # Get all vulnerabilities
            vulnerabilities = await session.query(Vulnerability).all()
            
            # Get all alerts
            alerts = await session.query(Alert).all()
            
            return {
                "status": "success",
                "report": {
                    "generated_at": datetime.now().isoformat(),
                    "total_assets": len(assets),
                    "total_vulnerabilities": len(vulnerabilities),
                    "total_alerts": len(alerts),
                    "critical_vulnerabilities": sum(1 for v in vulnerabilities if v.severity == "critical"),
                    "high_vulnerabilities": sum(1 for v in vulnerabilities if v.severity == "high"),
                    "medium_vulnerabilities": sum(1 for v in vulnerabilities if v.severity == "medium"),
                    "low_vulnerabilities": sum(1 for v in vulnerabilities if v.severity == "low")
                }
            }
    except Exception as e:
        logger.exception(f"Error generating security report: {str(e)}")
        return {"status": "error", "message": str(e)}

async def _simulate_vulnerability_scan(asset, session: AsyncSession):
    """Simulate a vulnerability scan for an asset"""
    # This is a placeholder for actual vulnerability scanning logic
    # In a real implementation, this would call the ML service or external scanners
    
    # Simulate finding 0-3 vulnerabilities
    import random
    from app.schemas.vulnerability import VulnerabilityCreate
    
    vulnerabilities = []
    severity_levels = ["low", "medium", "high", "critical"]
    vulnerability_types = ["SQL Injection", "XSS", "CSRF", "Insecure Direct Object Reference", 
                          "Security Misconfiguration", "Sensitive Data Exposure"]
    
    # Simulate 0-3 vulnerabilities
    for _ in range(random.randint(0, 3)):
        vuln = Vulnerability(
            asset_id=asset.id,
            name=f"{random.choice(vulnerability_types)} Vulnerability",
            description=f"Simulated vulnerability for testing purposes",
            severity=random.choice(severity_levels),
            status="open",
            discovered_at=datetime.now(),
            last_updated=datetime.now()
        )
        session.add(vuln)
        await session.commit()
        await session.refresh(vuln)
        vulnerabilities.append(vuln)
        
        # Create an alert for critical and high vulnerabilities
        if vuln.severity in ["critical", "high"]:
            alert = Alert(
                title=f"New {vuln.severity} vulnerability detected",
                description=f"{vuln.name} was detected on {asset.name}",
                severity=vuln.severity,
                status="new",
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                created_at=datetime.now()
            )
            session.add(alert)
            await session.commit()
    
    return vulnerabilities