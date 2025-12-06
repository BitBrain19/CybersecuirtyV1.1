
import sys
import os
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import get_current_user
from app.models.user import User
from app.services.ml_client import ml_client

# Mock user for authentication bypass
def mock_get_current_user():
    return User(id=1, email="test@example.com", is_active=True, is_admin=True)

# Override dependency
app.dependency_overrides[get_current_user] = mock_get_current_user

client = TestClient(app)

def test_endpoints():
    print("=== Starting Integration Verification ===\n")

    # 1. Test Threat Detection (Core ML)
    print("[1] Verify Threat Detection (ML Connectivity)...")
    try:
        response = client.post(
            "/api/v1/ml/threat-detection",
            json={
                "features": {
                    "source_ip": "1.1.1.1",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "packet_count": 50,
                    "byte_count": 1000,
                    "duration": 10
                }
            }
        )
        if response.status_code == 200:
            print(f"✅ Threat Detection Success: {response.json()['prediction']} (Confidence: {response.json()['confidence']})")
        else:
            print(f"❌ Threat Detection Failed ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Threat Detection Error: {e}")
    print()

    # 2. Verify Attack Paths
    print("[2] Verify Attack Path Integration...")
    try:
        response = client.get("/api/v1/attack-paths/")
        if response.status_code == 200:
            paths = response.json()
            print(f"✅ Attack Paths Fetched: {len(paths)} paths found")
            if len(paths) > 0:
                print(f"   Sample: {paths[0]['name']}")
        else:
            print(f"❌ Attack Paths Failed ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Attack Paths Error: {e}")
    print()

    # 3. Verify SOAR Integration
    print("[3] Verify SOAR Playbooks (Sync check)...")
    try:
        # Trigger Sync first
        sync_resp = client.post("/api/v1/soar/sync")
        if sync_resp.status_code == 200:
            print(f"✅ SOAR Sync Success: {sync_resp.json()['message']}")
        else:
            print(f"⚠️ SOAR Sync Warning ({sync_resp.status_code}): {sync_resp.text}")

        # Get Playbooks
        response = client.get("/api/v1/soar/playbooks")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SOAR Playbooks Fetched: {data['total']} playbooks available")
        else:
            print(f"❌ SOAR Playbooks Failed ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ SOAR Error: {e}")
    print()

    # 4. Verify Alerts Integration
    print("[4] Verify Unified Alerting...")
    try:
        response = client.get("/api/v1/alerts/")
        if response.status_code == 200:
            alerts = response.json()
            print(f"✅ Alerts Fetched: {len(alerts)} alerts found")
            if len(alerts) > 0:
                print(f"   Sample: {alerts[0]['title']} (Source: {alerts[0]['source']})")
        else:
            print(f"❌ Alerts Failed ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Alerts Error: {e}")
    print()
    
    print("=== Verification Complete ===")

if __name__ == "__main__":
    test_endpoints()
