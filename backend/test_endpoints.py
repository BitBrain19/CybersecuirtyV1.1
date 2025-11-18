#!/usr/bin/env python3
"""
Test Script for SOAR, UEBA, and EDR Endpoints
Tests all newly implemented backend endpoints
"""

import requests
import json
from datetime import datetime
import sys

BASE_URL = "http://localhost:8000/api/v1"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "adminpassword"

def get_token():
    """Get authentication token"""
    print("\n📝 Getting authentication token...")
    data = {
        "username": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            data=data,
            timeout=5
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        print(f"✅ Token obtained: {token[:20]}...")
        return token
    except Exception as e:
        print(f"❌ Failed to get token: {e}")
        return None

def get_headers(token):
    """Get request headers with auth"""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

def test_soar_endpoints(token):
    """Test SOAR endpoints"""
    print("\n" + "="*60)
    print("🎯 TESTING SOAR ENDPOINTS")
    print("="*60)
    
    headers = get_headers(token)
    
    # Get playbooks
    print("\n1️⃣  GET /soar/playbooks")
    try:
        response = requests.get(f"{BASE_URL}/soar/playbooks", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} playbooks")
        if data['data']:
            print(f"   First playbook: {data['data'][0]['name']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get specific playbook
    print("\n2️⃣  GET /soar/playbooks/1")
    try:
        response = requests.get(f"{BASE_URL}/soar/playbooks/1", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"   Playbook: {data['data']['name']}")
        print(f"   Success Rate: {data['data']['success_rate']}%")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Run playbook
    print("\n3️⃣  POST /soar/playbooks/1/run")
    try:
        response = requests.post(f"{BASE_URL}/soar/playbooks/1/run", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"   Execution ID: {data['data']['execution_id']}")
        print(f"   Status: {data['data']['status']}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_ueba_endpoints(token):
    """Test UEBA endpoints"""
    print("\n" + "="*60)
    print("👥 TESTING UEBA ENDPOINTS")
    print("="*60)
    
    headers = get_headers(token)
    
    # Get users
    print("\n1️⃣  GET /ueba/users")
    try:
        response = requests.get(f"{BASE_URL}/ueba/users", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} users")
        if data['data']:
            for user in data['data'][:3]:
                print(f"   - {user['full_name']} ({user['risk_level']}): {user['risk_score']:.1f}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get user anomalies
    print("\n2️⃣  GET /ueba/users/1/anomalies")
    try:
        response = requests.get(f"{BASE_URL}/ueba/users/1/anomalies", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} anomalies")
        if data['data']:
            for anomaly in data['data']:
                print(f"   - {anomaly['title']} ({anomaly['risk_level']})")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get all anomalies
    print("\n3️⃣  GET /ueba/anomalies")
    try:
        response = requests.get(f"{BASE_URL}/ueba/anomalies", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} anomalies across all users")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_edr_endpoints(token):
    """Test EDR endpoints"""
    print("\n" + "="*60)
    print("🔒 TESTING EDR ENDPOINTS")
    print("="*60)
    
    headers = get_headers(token)
    
    # Get endpoints
    print("\n1️⃣  GET /edr/endpoints")
    try:
        response = requests.get(f"{BASE_URL}/edr/endpoints", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} endpoints")
        if data['data']:
            for endpoint in data['data'][:3]:
                print(f"   - {endpoint['hostname']} ({endpoint['status']}): Risk {endpoint['risk_score']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get endpoint details
    print("\n2️⃣  GET /edr/endpoints/1")
    try:
        response = requests.get(f"{BASE_URL}/edr/endpoints/1", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"   Hostname: {data['data']['hostname']}")
        print(f"   IP: {data['data']['ip_address']}")
        print(f"   OS: {data['data']['os']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get alerts
    print("\n3️⃣  GET /edr/alerts")
    try:
        response = requests.get(f"{BASE_URL}/edr/alerts", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} alerts")
        if data['data']:
            for alert in data['data'][:3]:
                print(f"   - {alert['title']} ({alert['severity']})")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Get alerts for specific endpoint
    print("\n4️⃣  GET /edr/alerts?endpoint_id=1")
    try:
        response = requests.get(f"{BASE_URL}/edr/alerts?endpoint_id=1", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Found {data['total']} alerts for endpoint 1")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🚀 BACKEND ENDPOINT TESTING")
    print("="*60)
    print(f"Backend URL: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get token
    token = get_token()
    if not token:
        print("\n❌ Cannot proceed without authentication token")
        sys.exit(1)
    
    # Test endpoints
    test_soar_endpoints(token)
    test_ueba_endpoints(token)
    test_edr_endpoints(token)
    
    print("\n" + "="*60)
    print("✅ TESTING COMPLETE")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
