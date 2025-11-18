import asyncio
from datetime import datetime, timedelta
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.security import get_password_hash
from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.alert import Alert
from app.models.user_settings import UserSettings
from app.models.soar import SOARPlaybook, SOARExecution, PlaybookStatus, ExecutionStatus
from app.models.ueba import UEBAUser, UEBAAnomaly, RiskLevel, AnomalyType
from app.models.edr import EDREndpoint, EDRAlert, EndpointStatus, AlertSeverity, AlertStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_db() -> None:
    async with AsyncSessionLocal() as db:
        await create_initial_data(db)


async def create_initial_data(db: AsyncSession) -> None:
    # Check if we already have users (SQLAlchemy 2.0 / AsyncSession)
    result = await db.execute(select(func.count()).select_from(User))
    user_count = result.scalar() or 0
    if user_count > 0:
        logger.info("Database already initialized, skipping")
        return

    logger.info("Creating initial data")
    
    # Create admin user
    admin_user = User(
        email="admin@example.com",
        full_name="Admin User",
        hashed_password=get_password_hash("adminpassword"),
        is_admin=True
    )
    db.add(admin_user)
    await db.commit()
    await db.refresh(admin_user)
    
    # Create regular user
    regular_user = User(
        email="user@example.com",
        full_name="Regular User",
        hashed_password=get_password_hash("userpassword"),
        is_admin=False
    )
    db.add(regular_user)
    await db.commit()
    await db.refresh(regular_user)
    
    # Create user settings
    admin_settings = UserSettings(
        user_id=admin_user.id,
        theme="dark"
    )
    db.add(admin_settings)
    
    regular_settings = UserSettings(
        user_id=regular_user.id,
        theme="light"
    )
    db.add(regular_settings)
    await db.commit()
    
    # Create sample assets
    assets = [
        Asset(
            name="Web Server",
            description="Main production web server",
            asset_type="server",
            ip_address="192.168.1.10",
            hostname="webserver01",
            operating_system="Ubuntu 22.04 LTS",
            criticality=5,
            last_seen=datetime.now()
        ),
        Asset(
            name="Database Server",
            description="PostgreSQL database server",
            asset_type="database",
            ip_address="192.168.1.11",
            hostname="dbserver01",
            operating_system="Ubuntu 22.04 LTS",
            criticality=5,
            last_seen=datetime.now()
        ),
        Asset(
            name="Developer Workstation",
            description="Developer workstation for John",
            asset_type="workstation",
            ip_address="192.168.1.50",
            hostname="dev-john",
            operating_system="Windows 11",
            criticality=3,
            last_seen=datetime.now() - timedelta(hours=2)
        ),
    ]
    
    for asset in assets:
        db.add(asset)
    
    await db.commit()
    
    # Refresh assets to get their IDs
    for i, asset in enumerate(assets):
        await db.refresh(asset)
    
    # Create sample vulnerabilities
    vulnerabilities = [
        Vulnerability(
            title="Outdated OpenSSL Version",
            description="The server is running an outdated version of OpenSSL with known vulnerabilities",
            severity="high",
            status="open",
            cvss_score=7.5,
            cve_id="CVE-2023-1234",
            asset_id=assets[0].id
        ),
        Vulnerability(
            title="Default PostgreSQL Password",
            description="The PostgreSQL instance is using default credentials",
            severity="critical",
            status="open",
            cvss_score=9.1,
            cve_id=None,
            asset_id=assets[1].id
        ),
        Vulnerability(
            title="Outdated Browser",
            description="Chrome browser is outdated and has security vulnerabilities",
            severity="medium",
            status="open",
            cvss_score=5.5,
            cve_id="CVE-2023-5678",
            asset_id=assets[2].id
        ),
    ]
    
    for vuln in vulnerabilities:
        db.add(vuln)
    
    await db.commit()
    
    # Refresh vulnerabilities to get their IDs
    for i, vuln in enumerate(vulnerabilities):
        await db.refresh(vuln)
    
    # Create sample alerts
    alerts = [
        Alert(
            title="Critical Database Vulnerability Detected",
            description="Default credentials detected on PostgreSQL server",
            severity="critical",
            status="new",
            source="vulnerability_scan",
            asset_id=assets[1].id,
            user_id=None,
            is_read=False
        ),
        Alert(
            title="High Severity Web Server Vulnerability",
            description="OpenSSL vulnerability detected on web server",
            severity="high",
            status="investigating",
            source="vulnerability_scan",
            asset_id=assets[0].id,
            user_id=admin_user.id,
            is_read=True
        ),
    ]
    
    for alert in alerts:
        db.add(alert)
    
    await db.commit()
    
    # Create sample SOAR playbooks
    soar_playbooks = [
        SOARPlaybook(
            name="Incident Response - Malware",
            description="Automated response playbook for malware detection",
            status=PlaybookStatus.active,
            actions=5,
            execution_count=12,
            success_rate=92,
            last_executed=datetime.now() - timedelta(hours=2)
        ),
        SOARPlaybook(
            name="Data Exfiltration Response",
            description="Playbook for detecting and responding to data exfiltration attempts",
            status=PlaybookStatus.active,
            actions=8,
            execution_count=5,
            success_rate=85,
            last_executed=datetime.now() - timedelta(days=1)
        ),
        SOARPlaybook(
            name="Phishing Email Containment",
            description="Automated containment and isolation for phishing emails",
            status=PlaybookStatus.active,
            actions=6,
            execution_count=28,
            success_rate=95,
            last_executed=datetime.now() - timedelta(hours=4)
        ),
    ]
    
    for playbook in soar_playbooks:
        db.add(playbook)
    
    await db.commit()
    
    for i, playbook in enumerate(soar_playbooks):
        await db.refresh(playbook)
    
    # Create sample SOAR executions
    soar_executions = [
        SOARExecution(
            playbook_id=soar_playbooks[0].id,
            status=ExecutionStatus.succeeded,
            started_at=datetime.now() - timedelta(hours=2),
            completed_at=datetime.now() - timedelta(hours=1, minutes=55),
            duration_seconds=300,
            actions_executed=5
        ),
        SOARExecution(
            playbook_id=soar_playbooks[2].id,
            status=ExecutionStatus.succeeded,
            started_at=datetime.now() - timedelta(hours=4),
            completed_at=datetime.now() - timedelta(hours=3, minutes=58),
            duration_seconds=120,
            actions_executed=6
        ),
    ]
    
    for execution in soar_executions:
        db.add(execution)
    
    await db.commit()
    
    # Create sample UEBA users
    ueba_users = [
        UEBAUser(
            username="john.doe",
            email="john.doe@example.com",
            full_name="John Doe",
            department="Engineering",
            risk_score=15.5,
            risk_level=RiskLevel.low,
            is_active=1,
            last_activity=datetime.now() - timedelta(minutes=30),
            anomaly_count=0
        ),
        UEBAUser(
            username="jane.smith",
            email="jane.smith@example.com",
            full_name="Jane Smith",
            department="Finance",
            risk_score=42.3,
            risk_level=RiskLevel.medium,
            is_active=1,
            last_activity=datetime.now() - timedelta(hours=2),
            anomaly_count=3
        ),
        UEBAUser(
            username="admin.user",
            email="admin@example.com",
            full_name="Admin User",
            department="IT",
            risk_score=8.2,
            risk_level=RiskLevel.low,
            is_active=1,
            last_activity=datetime.now() - timedelta(minutes=5),
            anomaly_count=0
        ),
        UEBAUser(
            username="contractor.temp",
            email="contractor@example.com",
            full_name="Temporary Contractor",
            department="Consulting",
            risk_score=68.9,
            risk_level=RiskLevel.high,
            is_active=1,
            last_activity=datetime.now() - timedelta(days=2),
            anomaly_count=7
        ),
    ]
    
    for user in ueba_users:
        db.add(user)
    
    await db.commit()
    
    for user in ueba_users:
        await db.refresh(user)
    
    # Create sample UEBA anomalies
    ueba_anomalies = [
        UEBAAnomaly(
            user_id=ueba_users[1].id,
            anomaly_type=AnomalyType.failed_login,
            risk_level=RiskLevel.medium,
            title="Multiple Failed Login Attempts",
            description="User experienced 5 failed login attempts in 15 minutes",
            source_ip="203.0.113.45",
            location="Outside United States",
            confidence=0.92,
            is_acknowledged=0,
            detection_time=datetime.now() - timedelta(hours=1)
        ),
        UEBAAnomaly(
            user_id=ueba_users[1].id,
            anomaly_type=AnomalyType.unusual_time,
            risk_level=RiskLevel.low,
            title="Unusual Activity Time",
            description="User accessed system at 3 AM, outside normal working hours",
            source_ip="192.168.1.100",
            location="Office Network",
            confidence=0.78,
            is_acknowledged=1,
            detection_time=datetime.now() - timedelta(hours=6)
        ),
        UEBAAnomaly(
            user_id=ueba_users[3].id,
            anomaly_type=AnomalyType.data_exfiltration,
            risk_level=RiskLevel.high,
            title="Unusual Data Download",
            description="User downloaded 500GB of data outside normal pattern",
            source_ip="203.0.113.78",
            location="Unknown Location",
            confidence=0.95,
            is_acknowledged=0,
            detection_time=datetime.now() - timedelta(hours=12)
        ),
    ]
    
    for anomaly in ueba_anomalies:
        db.add(anomaly)
    
    await db.commit()
    
    # Create sample EDR endpoints
    edr_endpoints = [
        EDREndpoint(
            hostname="workstation-001",
            ip_address="192.168.1.100",
            os="Windows",
            os_version="11 Pro",
            agent_version="7.8.2",
            status=EndpointStatus.online,
            last_seen=datetime.now() - timedelta(minutes=5),
            risk_score=12,
            total_alerts=3,
            active_threats=0
        ),
        EDREndpoint(
            hostname="server-web-01",
            ip_address="192.168.1.50",
            os="Linux",
            os_version="Ubuntu 22.04 LTS",
            agent_version="7.8.1",
            status=EndpointStatus.at_risk,
            last_seen=datetime.now() - timedelta(minutes=15),
            risk_score=45,
            total_alerts=8,
            active_threats=2
        ),
        EDREndpoint(
            hostname="laptop-john",
            ip_address="192.168.1.105",
            os="MacOS",
            os_version="13.4",
            agent_version="7.8.2",
            status=EndpointStatus.online,
            last_seen=datetime.now() - timedelta(minutes=2),
            risk_score=5,
            total_alerts=0,
            active_threats=0
        ),
        EDREndpoint(
            hostname="server-db-01",
            ip_address="192.168.1.60",
            os="Linux",
            os_version="CentOS 7",
            agent_version="7.7.0",
            status=EndpointStatus.offline,
            last_seen=datetime.now() - timedelta(hours=8),
            risk_score=0,
            total_alerts=0,
            active_threats=0
        ),
    ]
    
    for endpoint in edr_endpoints:
        db.add(endpoint)
    
    await db.commit()
    
    for endpoint in edr_endpoints:
        await db.refresh(endpoint)
    
    # Create sample EDR alerts
    edr_alerts = [
        EDRAlert(
            endpoint_id=edr_endpoints[1].id,
            title="Suspicious Process Detected",
            description="Process 'svchost.exe' spawned unusual child processes",
            severity=AlertSeverity.high,
            status=AlertStatus.new,
            alert_type="suspicious_process",
            process_name="svchost.exe",
            process_id=2456,
            file_hash="a" * 64,
            detection_time=datetime.now() - timedelta(hours=1),
            is_acknowledged=0
        ),
        EDRAlert(
            endpoint_id=edr_endpoints[1].id,
            title="Privilege Escalation Attempt",
            description="Process attempted to escalate privileges without authorization",
            severity=AlertSeverity.critical,
            status=AlertStatus.investigated,
            alert_type="privilege_escalation",
            process_name="powershell.exe",
            process_id=3456,
            file_hash="b" * 64,
            detection_time=datetime.now() - timedelta(hours=3),
            remediation_action="Process terminated",
            is_acknowledged=1
        ),
        EDRAlert(
            endpoint_id=edr_endpoints[0].id,
            title="Malware Signature Match",
            description="File matches known malware signature database",
            severity=AlertSeverity.critical,
            status=AlertStatus.new,
            alert_type="malware",
            process_name="winrar.exe",
            process_id=1234,
            file_hash="c" * 64,
            detection_time=datetime.now() - timedelta(hours=6),
            is_acknowledged=0
        ),
    ]
    
    for alert in edr_alerts:
        db.add(alert)
    
    await db.commit()
    
    logger.info("Initial data created successfully with SOAR, UEBA, and EDR sample data")


if __name__ == "__main__":
    asyncio.run(init_db())