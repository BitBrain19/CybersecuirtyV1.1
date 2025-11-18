#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate a human-readable Markdown report from artifacts/saved/security_training_summary.json.
"""

import json
from pathlib import Path


def generate_markdown(summary: dict) -> str:
    ts = summary.get("timestamp", "unknown")
    edr = summary.get("edr", {})
    xdr = summary.get("xdr", {})
    ueba = summary.get("ueba", {})
    soar = summary.get("soar", {})

    lines = []
    lines.append(f"# SecurityAI Minimal Training Summary\n")
    lines.append(f"Generated: {ts}\n")

    # EDR
    lines.append("## EDR\n")
    lines.append(f"- events_generated: {edr.get('events_generated', 0)}")
    lines.append(f"- detections_ingested: {edr.get('detections_ingested', 0)}\n")

    # XDR
    lines.append("## XDR\n")
    lines.append(f"- events_processed: {xdr.get('events_processed', 0)}")
    lines.append(f"- alerts_processed: {xdr.get('alerts_processed', 0)}\n")

    # UEBA
    lines.append("## UEBA\n")
    lines.append(f"- entity_id: {ueba.get('entity_id', 'unknown')}")
    lines.append(f"- risk_score: {ueba.get('risk_score', 0)}")
    lines.append(f"- anomalies_detected: {ueba.get('anomalies_detected', 0)}\n")

    # SOAR
    lines.append("## SOAR\n")
    lines.append(f"- workflow_id: {soar.get('workflow_id', 'unknown')}")
    lines.append(f"- context_id: {soar.get('context_id', 'unknown')}")
    lines.append(f"- status: {soar.get('status', 'unknown')}")
    lines.append(f"- actions_executed: {soar.get('actions_executed', 0)}\n")

    return "\n".join(lines) + "\n"


def main():
    root = Path(__file__).resolve().parents[3]
    json_path = root / "artifacts" / "saved" / "security_training_summary.json"
    md_path = root / "artifacts" / "saved" / "security_training_summary.md"

    if not json_path.exists():
        print(f"Summary JSON not found at {json_path}")
        return 1

    data = json.loads(json_path.read_text(encoding="utf-8"))
    md = generate_markdown(data)
    md_path.write_text(md, encoding="utf-8")
    print(f"Markdown report written to {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())