# ML Models Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Verify ML Models Are Running

```bash
cd d:\Cybergardproject_V1.1
cd backend

# Check if models are accessible
curl http://localhost:8000/ml/health
```

**Expected Response:**

```json
{
  "status": "healthy",
  "models": {
    "soar": "operational",
    "ueba": "operational",
    "edr": "operational"
  }
}
```

### Step 2: Test SOAR Workflow Engine

```bash
# List available workflows
curl http://localhost:8000/soar/workflows

# Execute a workflow
curl -X POST http://localhost:8000/soar/workflows/malware_response/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trigger_event": {
      "endpoint_id": "ep_001",
      "threat_type": "malware",
      "severity": "high"
    }
  }'

# Get execution status
curl http://localhost:8000/soar/executions/{execution_id}
```

### Step 3: Test UEBA System

```bash
# Process a behavior event
curl -X POST http://localhost:8000/ueba/process-event \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_001",
    "event_type": "login",
    "timestamp": "2025-11-16T10:30:00Z",
    "location": "192.168.1.100"
  }'

# Get entity risk
curl http://localhost:8000/ueba/entity-risk/user_001

# Get anomalies
curl http://localhost:8000/ueba/anomalies/user_001
```

### Step 4: Test EDR System

```bash
# Register an endpoint
curl -X POST http://localhost:8000/edr/endpoints/ep_001/register \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "workstation-001",
    "ip_address": "192.168.1.100"
  }'

# Process a process event
curl -X POST http://localhost:8000/edr/endpoints/ep_001/process-event \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "process_name": "powershell.exe",
    "command_line": "powershell -Command Get-Process",
    "parent_process": "explorer.exe",
    "user": "system"
  }'

# Get endpoint threats
curl http://localhost:8000/edr/threats?endpoint_id=ep_001
```

### Step 5: Run Full Verification

```bash
cd ml
python verify_production_models.py
```

---

## 📊 Model Capabilities at a Glance

### SOAR - Security Orchestration & Automated Response

**What it does:** Automates security incident response with templatable workflows

**Key Features:**

- Conditional logic and dependencies
- Error handling and rollback
- Multi-step orchestration
- Audit logging

**Quick Example:**

```python
from ml.app.soar.workflow_engine_prod import get_workflow_engine

engine = get_workflow_engine()

# Execute workflow
result = engine.execute_workflow(
    workflow_id="malware_response",
    context={"endpoint_id": "ep_001", "threat_type": "malware"}
)

print(f"Status: {result['status']}")  # completed, failed, rolled_back
print(f"Output: {result['output']}")
```

### UEBA - User and Entity Behavior Analytics

**What it does:** Detects abnormal user and entity behavior in real-time

**Key Features:**

- Isolation Forest ML model
- Baseline behavior modeling
- Multi-dimensional anomaly detection
- Real-time risk scoring

**Quick Example:**

```python
from ml.app.ueba.ueba_prod import get_ueba_system

system = get_ueba_system()

# Process behavior event
system.process_event({
    "user_id": "user_001",
    "event_type": "login",
    "timestamp": "2025-11-16T10:30:00Z",
    "location": "192.168.1.100"
})

# Get risk
risk = system.get_entity_risk("user_001")
print(f"Risk Level: {risk['risk_level']}")  # low, medium, high, critical
print(f"Risk Score: {risk['risk_score']}")  # 0-1.0

# Get anomalies
anomalies = system.get_anomalies("user_001")
for anomaly in anomalies:
    print(f"- {anomaly['anomaly_type']}: {anomaly['confidence']}")
```

### EDR - Endpoint Detection and Response

**What it does:** Detects threats on endpoints in real-time

**Key Features:**

- Process/file/network monitoring
- LOLBAS and suspicious process detection
- MITRE ATT&CK mapping
- Endpoint isolation

**Quick Example:**

```python
from ml.app.edr.edr_prod import get_edr_system

system = get_edr_system()

# Register endpoint
system.register_endpoint(
    endpoint_id="ep_001",
    hostname="workstation-001",
    ip_address="192.168.1.100"
)

# Process process event
threats = system.process_process_event(
    endpoint_id="ep_001",
    process_name="powershell.exe",
    command_line="powershell -Command Get-Process",
    parent_process="explorer.exe"
)

# Get endpoint status
status = system.get_endpoint_status("ep_001")
print(f"Risk: {status['risk_score']}")
print(f"Threats: {len(status['active_threats'])}")

# Isolate if needed
if status['risk_score'] > 0.8:
    system.isolate_endpoint("ep_001")
```

### Retraining Pipeline - Automatic Model Updates

**What it does:** Automatically retrains all models every 2 weeks

**Key Features:**

- 2-week automatic cycle
- Performance monitoring
- Automatic rollback
- Model versioning

**Quick Example:**

```python
from ml.app.retraining_pipeline_prod import get_retraining_pipeline

pipeline = get_retraining_pipeline()

# Start background process
pipeline.start_background_process()

# Get status
status = pipeline.get_status()
print(f"Status: {status['status']}")  # idle, preparing, training, evaluating, deploying
print(f"Next cycle: {status['next_cycle_at']}")
print(f"Models: {len(status['models'])}")

# Check specific model
model_status = pipeline.get_model_status("ueba")
print(f"Current version: {model_status['current_version']}")
print(f"Accuracy: {model_status['accuracy']}")
```

---

## 🔌 API Endpoint Reference

### SOAR Endpoints

| Method | Endpoint                       | Purpose              |
| ------ | ------------------------------ | -------------------- |
| GET    | `/soar/workflows`              | List all workflows   |
| POST   | `/soar/workflows/{id}/execute` | Execute workflow     |
| GET    | `/soar/executions/{id}`        | Get execution status |

### UEBA Endpoints

| Method | Endpoint                 | Purpose                |
| ------ | ------------------------ | ---------------------- |
| POST   | `/ueba/process-event`    | Process behavior event |
| GET    | `/ueba/entity-risk/{id}` | Get entity risk        |
| GET    | `/ueba/anomalies/{id}`   | Get detected anomalies |

### EDR Endpoints

| Method | Endpoint                            | Purpose               |
| ------ | ----------------------------------- | --------------------- |
| POST   | `/edr/endpoints/{id}/register`      | Register endpoint     |
| POST   | `/edr/endpoints/{id}/process-event` | Process process event |
| POST   | `/edr/endpoints/{id}/file-event`    | Process file event    |
| POST   | `/edr/endpoints/{id}/network-event` | Process network event |
| GET    | `/edr/endpoints/{id}`               | Get endpoint status   |
| POST   | `/edr/endpoints/{id}/isolate`       | Isolate endpoint      |
| GET    | `/edr/threats`                      | Get all threats       |

### ML Pipeline Endpoints

| Method | Endpoint                | Purpose             |
| ------ | ----------------------- | ------------------- |
| GET    | `/ml/retraining-status` | Get pipeline status |
| GET    | `/ml/model-status/{id}` | Get model status    |
| GET    | `/ml/health`            | Health check        |

---

## 🧪 Testing

### Run All Tests

```bash
cd ml
python verify_production_models.py
```

### Run Specific Model Test

```bash
python -c "
from verify_production_models import test_soar_workflow
test_soar_workflow()
"
```

### Load Test (Coming Soon)

```bash
cd backend
pytest tests/test_ml_integration.py -v --load
```

---

## 📈 Monitoring

### Check Model Performance

```bash
# Get retraining status
curl http://localhost:8000/ml/retraining-status

# Get specific model metrics
curl http://localhost:8000/ml/model-status/ueba
curl http://localhost:8000/ml/model-status/edr
```

### View Logs

```bash
# Backend ML logs
tail -f backend/logs/ml_integration.log

# ML service logs
tail -f ml/logs/ml_service.log
```

### Monitor Real-Time Activity

```bash
# Watch EDR threats
watch -n 5 'curl -s http://localhost:8000/edr/threats | python -m json.tool'

# Watch UEBA anomalies
watch -n 5 'curl -s http://localhost:8000/ueba/anomalies/user_001 | python -m json.tool'
```

---

## ⚙️ Configuration

### Adjust Model Sensitivity

**UEBA Anomaly Threshold** (in `ueba_prod.py`):

```python
# Lower = more sensitive, Higher = less sensitive
ANOMALY_THRESHOLD = 0.5  # Default: 0.5
```

**EDR Threat Severity** (in `edr_prod.py`):

```python
# Adjust minimum threat severity
MIN_THREAT_SEVERITY = 6  # 0-10 scale
```

**Retraining Cycle** (in `retraining_pipeline_prod.py`):

```python
# Adjust retraining interval (in seconds)
RETRAINING_INTERVAL = 14 * 24 * 60 * 60  # 2 weeks
```

---

## 🐛 Troubleshooting

### Models Not Responding

```bash
# Check model service
curl http://localhost:8000/ml/health

# Check backend logs
tail -f backend/logs/app.log | grep "ml"
```

### High False Positive Rate

1. Increase anomaly threshold
2. Retrain models with more data
3. Adjust sensitivity settings
4. Review detected anomalies

### Performance Issues

```bash
# Monitor memory usage
python -c "
from ml.app.ueba.ueba_prod import get_ueba_system
import psutil
import time

system = get_ueba_system()
process = psutil.Process()

for i in range(10):
    system.process_event({...})
    print(f'Memory: {process.memory_info().rss / 1024 / 1024:.2f} MB')
    time.sleep(1)
"
```

---

## 📚 Resources

- **Full Documentation:** `ML_TRAINING_DOCUMENTATION.md`
- **Integration Guide:** `ML_MODELS_INTEGRATION_GUIDE.md`
- **Source Code:**
  - SOAR: `ml/app/soar/workflow_engine_prod.py`
  - UEBA: `ml/app/ueba/ueba_prod.py`
  - EDR: `ml/app/edr/edr_prod.py`
  - Pipeline: `ml/app/retraining_pipeline_prod.py`
  - Backend: `backend/app/api/api_v1/endpoints/ml_integration.py`

---

## ✅ What's Next?

1. ✅ SOAR Workflow Engine - **COMPLETE**
2. ✅ UEBA System - **COMPLETE**
3. ✅ EDR System - **COMPLETE**
4. ✅ Retraining Pipeline - **COMPLETE**
5. ✅ Backend Integration - **COMPLETE**
6. 🔄 Frontend Dashboards - **IN PROGRESS**
7. 🔄 XDR Platform - **PLANNED**

---

**Status:** 🟢 All 5 ML Models Production Ready  
**Last Updated:** November 16, 2025  
**Test Status:** ✅ All Tests Passing
