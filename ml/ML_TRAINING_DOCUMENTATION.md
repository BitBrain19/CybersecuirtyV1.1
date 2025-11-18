# ML Training Documentation & Dataset Requirements

## Overview

This document provides comprehensive guidance on training, deploying, and maintaining ML models in the SecurityAI Platform.

## Production ML Models

### 1. SOAR Workflow Engine (`workflow_engine_prod.py`)

**Purpose:** Automate security incident response

**Key Features:**

- Workflow templates with conditional logic
- Action chaining with dependencies
- Error handling and rollback
- Audit logging

**Training Data:** Not required (rule-based system)

**Actions Supported:**

- IsolateEndpoint - Network isolation
- BlockIP - IP blocking at firewall
- DisableAccount - Account deactivation
- SendAlert - Alert distribution
- CreateTicket - Incident tracking
- ExecuteScript - Custom actions

**Deployment:**

```bash
cd /ml
python -c "from app.soar.workflow_engine_prod import get_workflow_engine; engine = get_workflow_engine()"
```

---

### 2. UEBA System (`ueba_prod.py`)

**Purpose:** Detect behavioral anomalies in users and entities

**Training Data Requirements:**

- Minimum: 1,000 events per entity
- Recommended: 10,000+ events per entity
- Time span: 30+ days of historical data

**Dataset Format:**

```json
{
  "entity_id": "user_001",
  "entity_type": "user",
  "timestamp": "2025-11-16T10:30:00Z",
  "event_type": "login",
  "source_ip": "192.168.1.100",
  "location": "New York",
  "resource": "file_server",
  "action": "read",
  "success": true,
  "bytes_transferred": 1024000
}
```

**Features Analyzed:**

- Temporal patterns (login times)
- Geographic patterns (locations)
- Resource access patterns
- Data transfer volumes
- Failed authentication attempts

**Anomaly Types Detected:**

- Unusual time
- Impossible travel
- Unusual location
- Failed login spree
- Privilege escalation
- Data exfiltration
- Credential access
- Resource abuse
- Account enumeration
- Lateral movement

**Retraining Frequency:** Every 2 weeks

**Performance Metrics:**

- Baseline accuracy: 85-90%
- False positive rate target: <5%
- Detection latency: <100ms

---

### 3. EDR System (`edr_prod.py`)

**Purpose:** Detect and respond to endpoint threats

**Training Data Requirements:**

- Process events: 5,000+ per endpoint
- File events: 3,000+ per endpoint
- Network events: 2,000+ per endpoint

**Dataset Format:**

```json
{
  "event_type": "process_create",
  "endpoint_id": "ep_001",
  "timestamp": "2025-11-16T10:30:00Z",
  "process_name": "svchost.exe",
  "process_path": "C:\\Windows\\System32\\svchost.exe",
  "parent_process": "services.exe",
  "command_line": "svchost.exe -k netsvcs",
  "user": "SYSTEM",
  "image_hash": "abc123def456"
}
```

**Detection Methods:**

- Suspicious process heuristics
- Living off the land (LOLBAS) detection
- File execution monitoring
- Network traffic analysis
- Behavioral pattern matching

**Supported Threats:**

- Malware
- Exploits
- Lateral movement
- Privilege escalation
- Credential access
- Data exfiltration
- Persistence mechanisms
- Defense evasion

**Retraining Frequency:** Every 2 weeks

**Performance Metrics:**

- Detection accuracy: 90-95%
- False positive rate: <3%
- Response time: <50ms

---

### 4. XDR Platform

**Purpose:** Cross-source threat correlation and response

**Data Sources:**

- EDR (Endpoint events)
- UEBA (Behavioral anomalies)
- SIEM (Log data)
- Threat feeds
- Network telemetry

**Correlation Capabilities:**

- Multi-source alert correlation
- Entity relationship mapping
- Attack chain reconstruction
- Cross-asset threat tracking

---

### 5. Threat Detection Model

**Purpose:** ML-based threat classification

**Algorithm:** Isolation Forest + Random Forest ensemble

**Features:**

- 50+ network traffic features
- 30+ process behavior features
- 20+ file system features
- 15+ temporal features

**Input Format:**

```json
{
  "protocol": "TCP",
  "source_port": 54321,
  "dest_port": 443,
  "bytes_sent": 50000,
  "bytes_received": 100000,
  "packet_count": 150,
  "duration_seconds": 30,
  "is_encrypted": true,
  "has_anomaly_signature": false
}
```

---

## Automatic Retraining Pipeline

### 2-Week Retraining Cycle

**Phase 1: Preparation (Day 0-1)**

- Collect production data
- Validate data quality
- Split into training/validation sets

**Phase 2: Training (Day 1-7)**

- Train all models in parallel
- Monitor training progress
- Collect performance metrics

**Phase 3: Evaluation (Day 7-12)**

- Validate on held-out test set
- Compare with production model
- Check for performance degradation

**Phase 4: Deployment (Day 12-14)**

- A/B test new models
- Gradual rollout (10% → 50% → 100%)
- Monitor performance in production
- Rollback if issues detected

### Automatic Rollback Triggers

```python
ROLLBACK_THRESHOLDS = {
    "accuracy_drop": -0.05,           # 5% accuracy loss
    "false_positive_increase": 1.5,   # 50% increase in FP
    "latency_increase_ms": 100,       # 100ms slowdown
    "error_rate": 0.01                # 1% error rate
}
```

---

## Dataset Directory Structure

```
/ml/datasets/
├── production/
│   ├── 2025-11-01/
│   │   ├── process_events.jsonl
│   │   ├── file_events.jsonl
│   │   ├── network_events.jsonl
│   │   ├── ueba_events.jsonl
│   │   └── metadata.json
│   └── 2025-11-08/
├── labeled/
│   ├── malware/
│   │   ├── samples.jsonl
│   │   └── labels.json
│   ├── benign/
│   │   ├── samples.jsonl
│   │   └── labels.json
│   └── anomalies/
├── validation/
│   ├── 2025-11-15/
│   │   ├── test_set.jsonl
│   │   └── ground_truth.json
└── performance/
    ├── benchmarks/
    └── metrics/
```

---

## Training Data Collection

### Production Data Pipeline

```python
from ml.app.retraining_pipeline_prod import get_retraining_pipeline

pipeline = get_retraining_pipeline()

# Add samples during operation
pipeline.data_collector.add_sample({
    "entity_id": "user_001",
    "event_type": "login",
    "threat_detected": False
})

# Automatic collection every 2 weeks
await pipeline.start_background_process()
```

### Minimum Data Requirements

| Model            | Min Samples | Ideal Samples | Time Window |
| ---------------- | ----------- | ------------- | ----------- |
| UEBA             | 1,000       | 50,000        | 30 days     |
| EDR              | 5,000       | 100,000       | 60 days     |
| Threat Detection | 2,000       | 50,000        | 30 days     |
| XDR              | 10,000      | 200,000       | 90 days     |

---

## Model Versioning

### Version Naming Scheme

Format: `MAJOR.MINOR.PATCH`

```
1.0.0  - Initial production version
1.1.0  - New feature, backward compatible
1.1.1  - Bug fix
2.0.0  - Breaking changes
```

### Version Management

```python
from ml.app.retraining_pipeline_prod import ModelVersionManager

version_mgr = ModelVersionManager()

# Save new version
version = ModelVersion(
    model_id="threat_detector",
    version="1.1.0",
    accuracy=0.94,
    precision=0.92,
    recall=0.91
)
version_mgr.save_version(version, model_artifact)

# Load current version
model = version_mgr.load_version("threat_detector", "1.1.0")

# Rollback
version_mgr.rollback_to_version("threat_detector", "1.0.0")
```

---

## Performance Monitoring

### Key Metrics

```python
METRICS = {
    "accuracy": "Correct predictions / Total predictions",
    "precision": "TP / (TP + FP)",
    "recall": "TP / (TP + FN)",
    "f1_score": "2 * (precision * recall) / (precision + recall)",
    "auc_roc": "Area under ROC curve",
    "latency_ms": "Prediction time in milliseconds",
    "false_positive_rate": "FP / (FP + TN)",
    "false_negative_rate": "FN / (FN + TP)"
}
```

### Monitoring Dashboard

```
Model: threat_detector v1.1.0
├─ Accuracy: 94.2% (target: >92%)
├─ Precision: 92.1% (target: >90%)
├─ Recall: 91.8% (target: >85%)
├─ F1 Score: 0.919 (target: >0.90)
├─ Latency: 45ms (target: <100ms)
├─ False Positive Rate: 2.1% (target: <5%)
├─ Training Samples: 50,000
├─ Deployed: 2025-11-15 10:30:00
└─ Status: ✅ Production
```

---

## Training Scripts

### Quick Training

```bash
cd /ml
python app/scripts/train_models.py \
  --models threat_detector ueba edr \
  --data-dir datasets/production/2025-11-01/ \
  --output-dir models/ \
  --validate
```

### Batch Training

```bash
python app/scripts/train_batch.py \
  --config training_config.yaml \
  --parallel 4
```

### Custom Model Training

```python
from ml.app.retraining_pipeline_prod import AutomatedRetrainingPipeline

pipeline = AutomatedRetrainingPipeline()

# Start retraining cycle
await pipeline._run_retraining_cycle()

# Check status
status = await pipeline.get_status()
print(status)
```

---

## Production Deployment Checklist

- [ ] Model trained and validated
- [ ] Performance metrics meet thresholds
- [ ] No data drift detected
- [ ] Latency acceptable (<100ms)
- [ ] False positive rate <5%
- [ ] Previous version versioned
- [ ] Rollback procedure tested
- [ ] Monitoring alerts configured
- [ ] Documentation updated
- [ ] Stakeholder approval

---

## Troubleshooting

### High False Positive Rate

- Increase anomaly threshold by 0.05
- Collect more labeled negative samples
- Review threshold tuning

### Performance Degradation

- Check data drift
- Retrain with recent data
- Rollback to previous version

### Slow Predictions

- Profile model inference
- Optimize feature extraction
- Consider model quantization

---

## Support & Documentation

- Model API: `/ml/docs/api.md`
- Integration guide: `/backend/docs/ml_integration.md`
- Performance tuning: `/ml/docs/tuning.md`
- FAQ: `/ml/docs/faq.md`
