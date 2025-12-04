
import sys
import os
import asyncio
import logging
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ml.app.soar_engine.soar_orchestrator_prod import (
    get_soar_orchestrator, 
    IncidentContext, 
    TriageLevel
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("soar_simulation")

async def simulate_phishing_attack():
    orchestrator = get_soar_orchestrator()
    
    print("\n--- STARTING SOAR SIMULATION: PHISHING ATTACK ---")
    
    # 1. Create a Mock Incident (Phishing)
    # Simulating an alert that came from the Threat Classifier or SIEM
    incident = IncidentContext(
        incident_id="INC-2025-001",
        incident_type="phishing",  # Triggers the "Phishing Response" playbook
        severity="high",
        affected_hosts=["WORKSTATION-01"],
        affected_users=["jdoe@company.com"],
        affected_resources=["O365_Mailbox"],
        indicators=["Suspicious Login from IP 192.168.1.50", "Mass Email Deletion"],
        mitre_techniques=["T1566", "T1078"], # Phishing, Valid Accounts
        evidence_count=5,
        correlation_score=0.85
    )
    
    print(f"Incoming Incident: {incident.incident_type.upper()} (Severity: {incident.severity})")
    print(f"Affected User: {incident.affected_users[0]}")
    
    # 2. Process the Incident
    print("\nSOAR Engine Processing...")
    response = await orchestrator.process_incident(incident)
    
    # 3. Display Results
    print("\n--- RESPONSE GENERATED ---")
    print(f"Triage Level: {response.triage_level.value.upper()}")
    print(f"Root Cause Hypothesis: {response.root_cause_hypothesis} (Confidence: {response.root_cause_confidence:.0%})")
    
    print("\n--- AUTOMATED ACTIONS EXECUTED ---")
    if response.executed_actions:
        for action in response.executed_actions:
            print(f"  [EXECUTED] {action.action_type.value.upper()} (Confidence: {action.confidence:.0%})")
            print(f"     Status: {action.status}")
    else:
        print("  [!] No actions executed (Confidence threshold not met?)")

    print("\n--- SUGGESTED ACTIONS (Human Review Needed) ---")
    executed_ids = [a.action_id for a in response.executed_actions]
    for action in response.suggested_actions:
        if action.action_id not in executed_ids:
            print(f"  [SUGGESTED] {action.action_type.value.upper()} (Confidence: {action.confidence:.0%})")

    print("\n--- SIMULATION COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(simulate_phishing_attack())
