# 🚀 Quick ML Model Training Guide

## TL;DR - Train Your Models in 5 Minutes

### Step 1: Start the Backend

```bash
cd d:\Cybergardproject_V1.1\backend
python -m uvicorn app.main:app --reload --port 8000
```

### Step 2: Generate Sample Training Data

```bash
cd d:\Cybergardproject_V1.1\ml
python -c "
import json
from datetime import datetime, timedelta
import random

# Generate UEBA training data (1000 events)
events = []
for i in range(1000):
    event = {
        'entity_id': f'user_{i % 10:03d}',
        'entity_type': 'user',
        'timestamp': (datetime.now() - timedelta(hours=i)).isoformat(),
        'event_type': random.choice(['login', 'file_access', 'privilege_escalation']),
        'source_ip': f'192.168.1.{random.randint(1, 254)}',
        'location': random.choice(['New York', 'London', 'Tokyo', 'Sydney']),
        'resource': f'resource_{random.randint(1, 50)}',
        'success': random.choice([True, True, True, False]),
        'bytes_transferred': random.randint(0, 5000000)
    }
    events.append(event)

with open('training_data_ueba.jsonl', 'w') as f:
    for event in events:
        f.write(json.dumps(event) + '\n')

print(f'✅ Generated {len(events)} UEBA training events')
print(f'   Saved to: training_data_ueba.jsonl')
"
```

### Step 3: Train UEBA Model

```bash
python -c "
from ml.app.ueba.ueba_prod import get_ueba_system
from datetime import datetime, timedelta
import json
import asyncio

async def train():
    ueba = get_ueba_system()

    # Load training data
    with open('training_data_ueba.jsonl', 'r') as f:
        for line in f:
            event_data = json.loads(line)
            # Process each event to build baselines
            await ueba.process_event(event_data)

    # Train the ML model on all events
    for entity_id in [f'user_{i:03d}' for i in range(10)]:
        await ueba.train_entity_model(entity_id)

    print('✅ UEBA model trained successfully!')

asyncio.run(train())
"
```

### Step 4: Test the Trained Model

```bash
curl -X POST http://localhost:8000/ueba/process-event \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "user_001",
    "entity_type": "user",
    "event_type": "login",
    "timestamp": "2025-11-16T10:30:00Z",
    "source_ip": "10.0.0.1",
    "location": "Unknown Location",
    "resource": "database_server",
    "success": true
  }'
```

---

## 📚 Detailed Training Guide by Model

### SOAR Workflow Engine (Rule-Based - No Training Needed)

The SOAR engine uses rule-based workflows. No ML training required.

**How to use:**

```bash
python -c "
import asyncio
from ml.app.soar.workflow_engine_prod import get_workflow_engine, create_malware_response_workflow

async def demo():
    engine = get_workflow_engine()

    # Create a workflow
    workflow = await create_malware_response_workflow()

    # Register it
    wf_id = await engine.register_workflow(workflow)
    print(f'Registered workflow: {wf_id}')

    # Execute it
    result = await engine.execute_workflow(wf_id, {
        'endpoint_id': 'ep_001',
        'threat_type': 'malware'
    })
    print(f'Execution result: {result}')

asyncio.run(demo())
"
```

---

### UEBA System (ML-Based - Trains on Historical Data)

**Training Requirements:**

- Minimum 1,000 events per user
- 30+ days of historical data recommended
- Mix of normal and anomalous behavior

**Training Data Format (JSONL):**

```json
{"entity_id": "user_001", "event_type": "login", "timestamp": "2025-11-16T10:00:00Z", "source_ip": "192.168.1.100", "location": "New York", "success": true}
{"entity_id": "user_001", "event_type": "file_access", "timestamp": "2025-11-16T11:00:00Z", "resource": "file_server", "bytes_transferred": 1024000}
{"entity_id": "user_001", "event_type": "login", "timestamp": "2025-11-16T10:30:00Z", "source_ip": "10.0.0.1", "location": "Tokyo", "success": false}
```

**Training Steps:**

```bash
python -c "
import asyncio
from ml.app.ueba.ueba_prod import get_ueba_system
import json

async def train_ueba():
    ueba = get_ueba_system()

    # 1. Load historical data
    events = []
    with open('training_data_ueba.jsonl', 'r') as f:
        for line in f:
            events.append(json.loads(line))

    # 2. Process events to establish baselines
    print(f'Processing {len(events)} events...')
    for event in events:
        await ueba.process_event(event)

    # 3. Train ML model per user
    users = set(e['entity_id'] for e in events)
    print(f'Training models for {len(users)} users...')
    for user_id in users:
        await ueba.train_entity_model(user_id)
        print(f'  ✅ Trained {user_id}')

    print('✅ UEBA training complete!')

asyncio.run(train_ueba())
"
```

---

### EDR System (Rule-Based - Detects Known Threats)

EDR uses heuristics and LOLBAS signatures. No training required, but you can tune sensitivity.

**Generate EDR Training Data:**

```bash
python -c "
import json
from datetime import datetime, timedelta
import random

events = []

# Normal processes
normal_processes = ['explorer.exe', 'svchost.exe', 'lsass.exe', 'winlogon.exe']
malicious_processes = ['powershell.exe -NoProfile -Command', 'cmd.exe /c whoami', 'rundll32.exe shell32.dll']

for i in range(500):
    if random.random() > 0.05:  # 95% normal
        process = random.choice(normal_processes)
        threat = False
    else:  # 5% malicious
        process = random.choice(malicious_processes)
        threat = True

    event = {
        'endpoint_id': f'ep_{i % 10:03d}',
        'event_type': 'process_create',
        'process_name': process.split()[0],
        'command_line': process,
        'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
        'threat': threat
    }
    events.append(event)

with open('training_data_edr.jsonl', 'w') as f:
    for event in events:
        f.write(json.dumps(event) + '\n')

print(f'✅ Generated {len(events)} EDR training events')
"
```

---

### Automatic Retraining Pipeline (2-Week Cycle)

The retraining pipeline automatically updates models every 2 weeks using production data.

**Start the Pipeline:**

```bash
python -c "
import asyncio
from ml.app.retraining_pipeline_prod import get_retraining_pipeline

async def start():
    pipeline = get_retraining_pipeline()

    # Start background retraining process
    pipeline.start_background_process()

    # Check status
    status = pipeline.get_status()
    print(f'Pipeline status: {status}')
    print(f'Next retraining cycle: {status.get(\"next_cycle_at\")}')

asyncio.run(start())
"
```

---

## 📊 Training Data Directory Structure

```
ml/
├── datasets/
│   ├── production/          # Live production data
│   │   ├── events_2025_11_16.jsonl
│   │   └── events_2025_11_15.jsonl
│   ├── labeled/             # Manually labeled data
│   │   ├── normal_behavior.jsonl
│   │   ├── anomalies.jsonl
│   │   └── threats.jsonl
│   ├── validation/          # Validation/test set
│   │   └── test_set.jsonl
│   └── performance/         # Model performance tracking
│       └── metrics_2025_11.json
├── training_data_ueba.jsonl
├── training_data_edr.jsonl
└── models/
    ├── ueba_v1.0.0.pkl
    ├── edr_v1.0.0.pkl
    └── version_history/
```

---

## 🎯 Step-by-Step: Train UEBA Model from Scratch

### 1. Collect Data (30 days minimum)

```bash
# Your application should collect events like:
# - User logins (successful and failed)
# - File access events
# - Resource access
# - Privilege changes
# Store in training_data_ueba.jsonl (JSONL format)
```

### 2. Prepare Data

```bash
python -c "
import json
import pandas as pd

# Load and validate data
with open('training_data_ueba.jsonl', 'r') as f:
    events = [json.loads(line) for line in f]

print(f'Total events: {len(events)}')
print(f'Unique users: {len(set(e[\"entity_id\"] for e in events))}')
print(f'Date range: {min(e[\"timestamp\"] for e in events)} to {max(e[\"timestamp\"] for e in events)}')
"
```

### 3. Build Baselines

```bash
python -c "
import asyncio
from ml.app.ueba.ueba_prod import get_ueba_system
import json

async def build_baselines():
    ueba = get_ueba_system()

    with open('training_data_ueba.jsonl', 'r') as f:
        for i, line in enumerate(f):
            event = json.loads(line)
            await ueba.process_event(event)

            if (i + 1) % 100 == 0:
                print(f'Processed {i + 1} events...')

    print('✅ Baselines built!')

asyncio.run(build_baselines())
"
```

### 4. Train ML Models

```bash
python -c "
import asyncio
from ml.app.ueba.ueba_prod import get_ueba_system

async def train_models():
    ueba = get_ueba_system()

    # Get all users from processed events
    # (In production, this comes from your data)
    users = [f'user_{i:03d}' for i in range(10)]

    for user_id in users:
        print(f'Training {user_id}...')
        await ueba.train_entity_model(user_id)

    print('✅ Models trained!')

asyncio.run(train_models())
"
```

### 5. Test the Model

```bash
python -c "
import asyncio
from ml.app.ueba.ueba_prod import get_ueba_system
from datetime import datetime

async def test():
    ueba = get_ueba_system()

    # Test with normal behavior
    result = await ueba.process_event({
        'entity_id': 'user_001',
        'event_type': 'login',
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.100',  # Known location
        'location': 'New York',
        'success': True
    })
    print(f'Normal behavior: {result}')

    # Test with anomalous behavior
    result = await ueba.process_event({
        'entity_id': 'user_001',
        'event_type': 'login',
        'timestamp': datetime.now().isoformat(),
        'source_ip': '10.0.0.1',  # Unknown location
        'location': 'Sydney',  # Impossible travel
        'success': False  # Failed login
    })
    print(f'Anomalous behavior: {result}')

asyncio.run(test())
"
```

---

## 📈 Monitor Training Progress

```bash
python -c "
from ml.app.retraining_pipeline_prod import get_retraining_pipeline

pipeline = get_retraining_pipeline()
status = pipeline.get_status()

print(f'Status: {status[\"status\"]}')
print(f'Current cycle: {status[\"current_cycle\"]}')
print(f'Next retraining: {status[\"next_cycle_at\"]}')

# Check individual model status
for model_id in ['soar', 'ueba', 'edr']:
    model_status = pipeline.get_model_status(model_id)
    print(f'{model_id}: v{model_status[\"current_version\"]} - {model_status[\"accuracy\"]:.2%} accuracy')
"
```

---

## 🔧 Tune Model Sensitivity (Optional)

**Increase Detection Sensitivity (catch more threats, more false positives):**

```bash
# In ueba_prod.py, decrease the anomaly threshold
ANOMALY_THRESHOLD = 0.3  # More sensitive (catch more)
```

**Decrease Detection Sensitivity (fewer false positives, miss some threats):**

```bash
# In ueba_prod.py, increase the anomaly threshold
ANOMALY_THRESHOLD = 0.7  # Less sensitive (catch fewer)
```

---

## ✅ Training Checklist

- [ ] Collected 30+ days of historical data
- [ ] Data format is valid JSONL
- [ ] At least 1,000 events per user/entity
- [ ] Training data includes normal and anomalous samples
- [ ] Baseline generation complete
- [ ] ML models trained successfully
- [ ] Testing shows reasonable accuracy
- [ ] Retraining pipeline running
- [ ] Monitoring dashboard set up

---

## 📞 Troubleshooting

**Problem:** "No module named 'ml'"  
**Solution:** Run from project root: `cd d:\Cybergardproject_V1.1` then `python ml/...`

**Problem:** Model training is slow  
**Solution:** Reduce training data size or use fewer users for initial training

**Problem:** High false positive rate  
**Solution:** Increase `ANOMALY_THRESHOLD` or collect more diverse training data

**Problem:** Can't find training data  
**Solution:** Ensure data is in correct format (JSONL) and location matches the script

---

**Status:** ✅ Models ready to train  
**Next Step:** Follow steps 1-5 above to train your first model  
**Time Required:** 10 minutes for setup, 5-10 minutes for training
