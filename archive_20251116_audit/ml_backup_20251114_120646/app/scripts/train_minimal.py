#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Minimal training script to warm baselines across EDR, XDR, UEBA, and SOAR,
and export a concise JSON summary to `artifacts/saved/`.

This script:
- Generates synthetic EDR endpoint events and a detection
- Starts the XDR platform and ingests EDR events/detections
- Builds a UEBA behavior profile and detects a few anomalies
- Executes a simple SOAR workflow step
- Persists a summary JSON artifact for quick validation
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Dict, Any, List

# Core utilities
from ..core.logging_system import app_logger, AlertSeverity

# EDR components
from ..edr.agent import (
    EndpointAgent,
    EndpointEvent,
    EndpointEventType,
    EndpointThreatDetection,
    ThreatCategory,
)

# XDR platform
from ..xdr.xdr_platform import XDRPlatform, xdr_platform

# UEBA components
from ..ueba.behavior_analytics import (
    BehaviorProfiler,
    BehaviorAnomalyDetector,
    BehaviorEvent,
    BehaviorCategory,
    EntityType,
)

# SOAR components
from ..soar.workflow_engine import (
    Workflow,
    WorkflowStep,
    TriggerType,
    WorkflowStatus,
    workflow_engine,
)
from ..soar.actions import TicketCreationAction


async def _warm_edr_and_xdr(agent: EndpointAgent, xdr: XDRPlatform) -> Dict[str, Any]:
    """Generate synthetic EDR events and a detection; ingest into XDR."""
    events: List[EndpointEvent] = []
    detections: List[EndpointThreatDetection] = []

    # Create a few benign and suspicious events
    base_host = agent.hostname
    base_ip = agent.endpoint_info.ip_address
    endpoint_id = agent.endpoint_id

    # Benign process creation
    events.append(
        EndpointEvent(
            event_type=EndpointEventType.PROCESS_CREATE,
            endpoint_id=endpoint_id,
            hostname=base_host,
            ip_address=base_ip,
            username="Administrator",
            process_id=1234,
            process_name="explorer.exe",
            process_path="C\\Windows\\explorer.exe",
            command_line="explorer.exe",
        )
    )

    # Suspicious network connection
    events.append(
        EndpointEvent(
            event_type=EndpointEventType.NETWORK_CONNECTION,
            endpoint_id=endpoint_id,
            hostname=base_host,
            ip_address=base_ip,
            username="Administrator",
            process_id=4321,
            process_name="powershell.exe",
            process_path="C\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            network_protocol="TCP",
            source_address=base_ip,
            source_port=55555,
            destination_address="203.0.113.10",
            destination_port=4444,
            command_line="powershell -enc SQBuc3VzcGljaW91cw==",
        )
    )

    # System file modification
    events.append(
        EndpointEvent(
            event_type=EndpointEventType.FILE_MODIFY,
            endpoint_id=endpoint_id,
            hostname=base_host,
            ip_address=base_ip,
            username="Administrator",
            process_id=2456,
            process_name="cmd.exe",
            process_path="C\\Windows\\System32\\cmd.exe",
            file_path="C\\Windows\\System32\\drivers\\etc\\hosts",
            command_line="cmd /c echo 203.0.113.10 bad.com >> %SystemRoot%\\System32\\drivers\\etc\\hosts",
        )
    )

    # Ingest events into XDR and analyze via EDR
    for ev in events:
        try:
            await agent._analyze_event(ev)
        except Exception:
            # _analyze_event is best-effort for warming; continue on errors
            pass
        await xdr.ingest_edr_event(ev)

    # Create and ingest one synthetic detection to guarantee at least one alert
    detections.append(
        EndpointThreatDetection(
            endpoint_id=endpoint_id,
            hostname=base_host,
            ip_address=base_ip,
            username="Administrator",
            threat_name="Suspicious PowerShell Activity",
            threat_category=ThreatCategory.BEHAVIORAL,
            severity=AlertSeverity.MEDIUM,
            confidence=0.85,
            description="Encoded command observed with external callback",
            process_id=4321,
            process_name="powershell.exe",
            process_path="C\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            network_connection={
                "destination_address": "203.0.113.10",
                "destination_port": 4444,
                "protocol": "TCP",
            },
            mitre_techniques=["T1059", "T1071"],
            indicators={"encoded": True, "external_ip": "203.0.113.10"},
            recommended_actions=["Investigate process tree", "Block IP", "Quarantine endpoint"],
        )
    )

    for det in detections:
        await xdr.ingest_edr_detection(det)

    # Allow background tasks to process
    await asyncio.sleep(1.0)

    return {
        "events_generated": len(events),
        "detections_ingested": len(detections),
    }


async def _warm_ueba() -> Dict[str, Any]:
    """Build a UEBA profile and produce a few anomalies."""
    profiler = BehaviorProfiler()
    detector = BehaviorAnomalyDetector(profiler)

    entity_id = "user-123"
    entity_type = EntityType.USER

    # Baseline authentication events during business hours from a stable IP
    for hour in [9, 10, 11, 12, 13, 14, 15, 16]:
        evt = BehaviorEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            category=BehaviorCategory.AUTHENTICATION,
            action="login",
            context={
                "method": "password",
                "success": True,
                "ip_address": "192.168.1.50",
            },
        )
        # Override timestamp hour
        evt.timestamp = evt.timestamp.replace(hour=hour)
        profiler.update_profile(evt)

    # Baseline access pattern events
    for _ in range(5):
        evt = BehaviorEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            category=BehaviorCategory.ACCESS_PATTERN,
            action="read",
            context={"resource_id": "doc-42", "resource_type": "document", "access_type": "read"},
        )
        profiler.update_profile(evt)

    # Anomalous authentication from a new IP at unusual hour
    anomalies_total = 0
    anomaly_events: List[BehaviorEvent] = []

    anomalous = BehaviorEvent(
        entity_id=entity_id,
        entity_type=entity_type,
        category=BehaviorCategory.AUTHENTICATION,
        action="login",
        context={
            "method": "password",
            "success": True,
            "ip_address": "203.0.113.50",
        },
    )
    anomalous.timestamp = anomalous.timestamp.replace(hour=3)
    anomaly_events.append(anomalous)

    for evt in anomaly_events:
        # Run detection; profiler already warmed above
        anomalies = detector.detect_anomalies(evt)
        anomalies_total += len(anomalies)
        # Record anomalies into profile (detector updates risk when anomalies exist)
        for a in anomalies:
            profile = profiler.get_profile(entity_id, entity_type)
            profile.anomalies.append({
                "id": a.id,
                "category": a.category.value,
                "severity": a.severity,
                "description": a.description,
            })

    profile = profiler.get_profile(entity_id, entity_type)
    return {
        "entity_id": entity_id,
        "risk_score": profile.risk_score,
        "anomalies_detected": anomalies_total,
    }


async def _run_soar_workflow() -> Dict[str, Any]:
    """Register and execute a simple SOAR workflow with a single ticket action."""
    # Define a one-step workflow
    ticket_action = TicketCreationAction()
    step = WorkflowStep(
        action=ticket_action,
        params={
            "system": "demo",
            "project": "SEC",
            "title": "Baseline Training Ticket",
            "description": "Automatically created during baseline training.",
            "priority": "medium",
        },
    )

    wf = Workflow(id="wf-baseline-training", name="Baseline Training Workflow")
    wf.add_step(step)
    workflow_engine.register_workflow(wf)

    # Execute and wait briefly for completion
    context_id = await workflow_engine.execute_workflow(wf.id, TriggerType.MANUAL, {"reason": "baseline_training"})
    await asyncio.sleep(1.0)

    ctx = workflow_engine.active_workflows.get(context_id)
    status = ctx.status.value if ctx else "unknown"
    actions_count = len(ctx.actions_history) if ctx else 0

    return {
        "workflow_id": wf.id,
        "context_id": context_id,
        "status": status,
        "actions_executed": actions_count,
    }


async def main() -> Dict[str, Any]:
    # Ensure artifact storage exists
    os.makedirs(os.path.join("artifacts", "saved"), exist_ok=True)

    # Start XDR platform
    await xdr_platform.start()

    # EDR/XDR warming
    agent = EndpointAgent()
    edr_xdr_summary = await _warm_edr_and_xdr(agent, xdr_platform)

    # UEBA warming
    ueba_summary = await _warm_ueba()

    # SOAR workflow execution
    soar_summary = await _run_soar_workflow()

    # Gather XDR counts
    xdr_counts = {
        "events_processed": len(getattr(xdr_platform, "events", {})),
        "alerts_processed": len(getattr(xdr_platform, "alerts", {})),
    }

    summary: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "edr": edr_xdr_summary,
        "xdr": xdr_counts,
        "ueba": ueba_summary,
        "soar": soar_summary,
    }

    out_path = os.path.join("artifacts", "saved", "security_training_summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    app_logger.info(f"Training summary written to {out_path}")
    return summary


if __name__ == "__main__":
    # Run the async main and print summary
    summary_result = asyncio.run(main())
    print(json.dumps(summary_result, indent=2))
import sys
import numpy as np
import pandas as pd

# Ensure internal app modules import correctly when running as module
CURRENT_DIR = os.path.dirname(__file__)
APP_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from ..models.threat_detection import ThreatDetectionModel
from ..models.vulnerability_assessment import VulnerabilityAssessmentModel
from ..core.config import settings


def main():
    storage_dir = os.path.abspath(settings.model_storage_path)
    os.makedirs(storage_dir, exist_ok=True)

    # Minimal ThreatDetection training
    td = ThreatDetectionModel()
    # Create tiny synthetic data aligned with expected numeric shape
    X_td = np.random.rand(50, 15)  # approximate feature count after preprocess
    y_td = np.array(["benign", "malicious", "suspicious"] * (50 // 3 + 1))[:50]
    td.train(X_td, y_td, validation_split=0.2, optimize_hyperparameters=False, cross_validate=False)
    td_path = os.path.join(storage_dir, "threat_detection_latest.joblib")
    td.save(td_path)
    print(f"Saved: {td_path}")
    print(f"Exists after save (TD): {os.path.exists(td_path)}")

    # Minimal VulnerabilityAssessment training
    va = VulnerabilityAssessmentModel()
    df = pd.DataFrame({
        "age": np.random.randint(0, 365, 60),
        "version": np.random.randint(1, 10, 60),
        "patch_level": np.random.randint(0, 10, 60),
        "complexity_score": np.random.uniform(0.0, 10.0, 60),
        "os_type": np.random.choice(["Windows","Linux","macOS","NetworkOS"], 60),
        "service_type": np.random.choice(["web","database","ssh","smtp","fileserver"], 60),
        "access_vector": np.random.choice(["NETWORK","ADJACENT","LOCAL"], 60),
        "authentication_required": np.random.choice(["NONE","SINGLE","MULTIPLE"], 60),
        "confidentiality_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 60),
        "integrity_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 60),
        "availability_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 60),
    })
    y = np.random.uniform(0.0, 10.0, 60)
    va.train(df, y, validation_split=0.2, optimize_hyperparameters=False)
    # Assign primary for saving
    va.model = va.models.get("primary")
    va_path = os.path.join(storage_dir, "vulnerability_assessment_latest.joblib")
    va.save(va_path)
    print(f"Saved: {va_path}")
    print(f"Exists after save (VA): {os.path.exists(va_path)}")
    # Write a simple results JSON next to this script for verification
    import json
    results = {
        "td_path": td_path,
        "td_exists": os.path.exists(td_path),
        "va_path": va_path,
        "va_exists": os.path.exists(va_path),
        "storage_dir": storage_dir,
    }
    out_path = os.path.join(os.path.dirname(__file__), "training_results_minimal.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Wrote results: {out_path}")


if __name__ == "__main__":
    main()