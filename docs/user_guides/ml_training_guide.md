# ML Training Guide

## Purpose
This guide explains how to prepare datasets and train the SecurityAI Platform’s machine learning models. It details data requirements, preparation steps, training workflows, evaluation, and deployment.

## Supported Models and Data Requirements

Refer to the machine learning components overview for algorithms and outputs <mcfile name="ml_components.md" path="d:\Cybergardproject_V1.1\docs\components\ml_components.md"></mcfile>.

### Threat Detection (Random Forest - classification)
- Data sources: network traffic logs, system logs, user activity logs, historical alert outcomes (true/false positives)
- Features: network flow stats (bytes, duration, ports), auth outcomes, process events, user actions
- Labels: malicious vs. benign (required for supervised training)
- Volume: weeks of activity with sufficient positive examples; aim for class balance or use resampling
- Diversity: include different hosts, users, times of day, and attack types

### Vulnerability Assessment (Gradient Boosting - regression)
- Data sources: asset inventory, system configurations, patch levels, known CVE data
- Features: OS/version, exposed services, configuration flags, patch age, CVSS vectors
- Labels: historical risk scores (0–10) or severity categories (if classification variant)
- Volume: coverage across asset types; include historical states and outcomes
- Diversity: different environments (servers, endpoints, cloud), various software stacks

### Log Parsing (DistilBERT - NLP extraction)
- Data sources: raw log text from varied systems (Syslog, Windows Event Log, application logs)
- Labels: structured extractions (e.g., timestamp, host, event_type, user, source_ip)
- Volume: thousands to tens of thousands of annotated lines; multiple formats/vendors
- Diversity: mix of normal and error logs, varied schemas, multilingual if applicable

### Lateral Movement Detection (Graph + heuristics)
- Data sources: authentication events, process executions, network connections
- Features: graph edges (who connected to what), timestamps, auth outcomes, process lineage
- Labels: known lateral movement incidents (if supervised components used); otherwise heuristics baseline
- Volume: several weeks of topology and activity data
- Diversity: include different network segments and identity stores

### UEBA Baselines (behavior modeling)
- Data sources: user/system activity, authentication, resource access
- Baseline data: at least 2 weeks of historical activity to establish normal behavior
- Features: frequency, sequences, time-of-day, peer-group comparisons

## Dataset Specifications and Schemas

Provide datasets in CSV/Parquet/JSONL where feasible. Suggested schemas:

- Threat Detection (tabular):
  - fields: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes_in, bytes_out, duration, auth_success, process_name, user, label

- Vulnerability Assessment (tabular):
  - fields: asset_id, os, os_version, services, open_ports, config_flags, patch_level, cvss_vector, known_cves, historical_incidents, risk_score

- Log Parsing (text with labels):
  - fields: raw_log_text, parsed.timestamp, parsed.host, parsed.event_type, parsed.user, parsed.source_ip, parsed.severity

- Lateral Movement (edges):
  - fields: timestamp, subject (user/host), action (login/process), object (host/service), outcome, connection_id

- UEBA (entity timelines):
  - fields: entity_id, event_type, timestamp, resource, context

## Data Preparation Workflow

1. Collection
   - Extract from log collectors, endpoint agents, and cloud APIs <mcfile name="database_components.md" path="d:\Cybergardproject_V1.1\docs\components\database_components.md"></mcfile>.

2. Cleaning
   - Remove corrupt records; handle missing values; deduplicate; standardize timezones

3. Normalization
   - Convert fields to consistent types/units; map enums; anonymize PII where required

4. Feature Engineering
   - Aggregate windows (e.g., 5–15 min); encode categorical fields; compute ratios and rates

5. Labeling
   - Use validated incidents/cases for ground truth; avoid noisy labels; review ambiguous cases

6. Balancing
   - Address class imbalance with resampling or class weights

7. Splitting
   - Train/validation/test using temporal splits to avoid leakage; consider per-entity stratification

## Training Procedures

### UI-Based Training
Follow Administration > ML Management > Training <mcfile name="admin_guide.md" path="d:\Cybergardproject_V1.1\docs\user_guides\admin_guide.md"></mcfile>:
- Select model type (Threat Detection, Anomaly/UEBA, Risk Scoring, Attack Path) 
- Configure training parameters: dataset selection, features, algorithm settings, validation method
- Start training and monitor progress; review performance metrics

### API/Service-Based Training
- Use ML service endpoints to submit training jobs (see platform API and ML service docs)
- Provide dataset locations (object storage or DB queries) and configuration payloads

### Model Registry and Versioning
- Register trained models with metadata (dataset version, parameters, metrics)
- Support A/B testing and rollback via model registry (e.g., MLflow) <mcfile name="ml_components.md" path="d:\Cybergardproject_V1.1\docs\components\ml_components.md"></mcfile>.

## Evaluation and Metrics

- Classification: accuracy, precision, recall, F1, ROC-AUC; confusion matrix
- Regression: MAE, RMSE, R²; calibration curves
- Security-specific: alert lift, incident detection time, false positive rate, risk prioritization accuracy
- Perform cross-validation and temporal backtesting; validate on recent production-like data

## Deployment

- Promote approved models to staging/production via ML Management > Deployment <mcfile name="admin_guide.md" path="d:\Cybergardproject_V1.1\docs\user_guides\admin_guide.md"></mcfile>
- Configure thresholds and routing; monitor inference latency and error rates
- Maintain backward compatibility; document changes for operations

## Ongoing Maintenance

- Monitor for data drift and retrain periodically
- Track feature distributions; alert on skew
- Refresh UEBA baselines with new history windows
- Keep CVE/asset inventories current for vulnerability models

## Common Pitfalls and Remedies

## Artifacts and Reports (Updated)

The platform stores training outputs and reports under the top-level `artifacts` directory (renamed from `models`).

- `artifacts/saved`: Persistent outputs like `security_training_summary.json` and `security_training_summary.md`
- `artifacts/temp`: Temporary files created during training and evaluation

### Generate the Markdown Training Report

You can generate a Markdown training summary after running minimal training or ingesting evaluation metrics.

Commands (from the repo root):

- `python -m ml.app.scripts.train_minimal`
  - Produces `artifacts/saved/security_training_summary.json` with minimal metrics

- `python -m ml.app.scripts.generate_md_report`
  - Reads the JSON summary and writes `artifacts/saved/security_training_summary.md`

Report contents include EDR, XDR, and UEBA metrics, with notes on datasets and thresholds. Open the report directly at `artifacts/saved/security_training_summary.md`.

### Where to Find Outputs

- JSON summary: `artifacts/saved/security_training_summary.json`
- Markdown report: `artifacts/saved/security_training_summary.md`

If you previously looked under `models/saved`, update any bookmarks or scripts to use `artifacts/saved`.

- Insufficient positive examples: augment with synthetic hard negatives; expand time window
- Label noise: establish review workflows; use consensus labeling
- Data leakage: enforce temporal splits; avoid target leakage features
- Imbalanced classes: use class weights or focal loss (if applicable)

## Compliance and Security Considerations

- Apply least-privilege access to training data
- Anonymize or tokenize sensitive identifiers where possible
- Log lineage: record data sources, preprocessing steps, and approvals
- Store datasets and models with retention policies aligned to governance