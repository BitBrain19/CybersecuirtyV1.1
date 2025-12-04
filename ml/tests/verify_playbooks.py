
import sys
import os
import asyncio
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ml.app.soar_engine.soar_orchestrator_prod import get_soar_orchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("playbook_verification")

def verify_playbooks():
    orchestrator = get_soar_orchestrator()
    library = orchestrator.playbook_library
    
    expected_playbooks = [
        "ransomware", "privesc", "lateral",  # Original
        "phishing", "exfiltration", "c2", "brute_force", "insider_threat" # New
    ]
    
    logger.info(f"Checking for {len(expected_playbooks)} playbooks...")
    
    missing = []
    for pb_id in expected_playbooks:
        if pb_id in library.playbooks:
            pb = library.playbooks[pb_id]
            logger.info(f"✅ Found playbook: {pb.name} (Trigger: {pb.trigger_type})")
            logger.info(f"   Actions: {[a.action_type.value for a in pb.actions]}")
        else:
            logger.error(f"❌ Missing playbook: {pb_id}")
            missing.append(pb_id)
            
    if missing:
        logger.error(f"Verification FAILED. Missing: {missing}")
        sys.exit(1)
    else:
        logger.info("Verification PASSED. All playbooks loaded.")
        sys.exit(0)

if __name__ == "__main__":
    verify_playbooks()
