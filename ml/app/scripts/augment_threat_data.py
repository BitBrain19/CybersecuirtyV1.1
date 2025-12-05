"""
Augment Real Data with Synthetic Threat Events
Adds synthetic threat events to existing benign network events
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_threat_event(base_timestamp: datetime) -> dict:
    """Generate a synthetic threat event"""
    
    threat_types = [
        {
            "event_type": "port_scan",
            "severity": "high",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "dest_port": random.choice([22, 23, 3389, 445, 135]),
            "packet_count": random.randint(100, 1000),
            "description": "Port scanning activity detected"
        },
        {
            "event_type": "brute_force",
            "severity": "critical",
            "protocol": random.choice(["TCP", "UDP"]),
            "dest_port": random.choice([22, 3389, 21]),
            "failed_attempts": random.randint(10, 100),
            "description": "Brute force login attempts"
        },
        {
            "event_type": "malware_callback",
            "severity": "critical",
            "protocol": random.choice(["TCP", "UDP"]),
            "dest_port": random.choice([4444, 8080, 443]),
            "bytes_sent": random.randint(1000, 100000),
            "description": "Suspected C2 communication"
        },
        {
            "event_type": "data_exfiltration",
            "severity": "critical",
            "protocol": random.choice(["TCP", "UDP"]),
            "dest_port": random.choice([443, 80, 21]),
            "bytes_sent": random.randint(1000000, 10000000),
            "description": "Large data transfer to external IP"
        },
        {
            "event_type": "ddos",
            "severity": "high",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "packet_count": random.randint(10000, 100000),
            "description": "DDoS attack pattern detected"
        },
        {
            "event_type": "sql_injection",
            "severity": "high",
            "protocol": "TCP",
            "dest_port": 80,
            "payload_pattern": "' OR '1'='1",
            "description": "SQL injection attempt"
        }
    ]
    
    threat = random.choice(threat_types)
    
    event = {
        "protocol": threat["protocol"],
        "source_port": random.randint(1024, 65535),
        "dest_port": threat.get("dest_port", random.randint(1, 1024)),
        "bytes_sent": threat.get("bytes_sent", random.randint(100, 10000)),
        "packet_count": threat.get("packet_count", random.randint(1, 100)),
        "duration_seconds": random.randint(1, 600),
        "is_encrypted": random.choice([True, False]),
        "is_threat": True
    }
    
    return event


def augment_data(input_file: str, output_file: str, threat_ratio: float = 0.3):
    """
    Augment benign data with synthetic threat events
    
    Args:
        input_file: Path to existing benign events
        output_file: Path to save augmented data
        threat_ratio: Ratio of threat events to add (0.3 = 30% threats)
    """
    
    print(f"Reading benign events from: {input_file}")
    
    # Read existing benign events
    benign_events = []
    with open(input_file, 'r') as f:
        for line in f:
            event = json.loads(line)
            # Ensure is_threat is set to False for benign events
            event['is_threat'] = False
            benign_events.append(event)
    
    benign_count = len(benign_events)
    print(f"Found {benign_count} benign events")
    
    # Calculate how many threat events to add
    threat_count = int(benign_count * threat_ratio / (1 - threat_ratio))
    print(f"Generating {threat_count} synthetic threat events ({threat_ratio*100:.0f}% of total)")
    
    # Generate threat events
    base_timestamp = datetime.now()
    threat_events = [generate_threat_event(base_timestamp) for _ in range(threat_count)]
    
    # Combine and shuffle
    all_events = benign_events + threat_events
    random.shuffle(all_events)
    
    # Write to output file
    print(f"Writing {len(all_events)} total events to: {output_file}")
    with open(output_file, 'w') as f:
        for event in all_events:
            f.write(json.dumps(event) + '\n')
    
    print(f"\n✅ Augmentation complete!")
    print(f"   Total events: {len(all_events)}")
    print(f"   Benign: {benign_count} ({benign_count/len(all_events)*100:.1f}%)")
    print(f"   Threats: {threat_count} ({threat_count/len(all_events)*100:.1f}%)")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Augment benign data with synthetic threats")
    parser.add_argument("--input", type=str, required=True, help="Input file with benign events")
    parser.add_argument("--output", type=str, help="Output file (default: overwrites input)")
    parser.add_argument("--threat-ratio", type=float, default=0.3, help="Ratio of threats (default: 0.3)")
    
    args = parser.parse_args()
    
    output_file = args.output or args.input
    augment_data(args.input, output_file, args.threat_ratio)
