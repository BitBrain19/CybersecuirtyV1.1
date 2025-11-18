# SecurityAI Platform

A production-grade enterprise IT infrastructure monitoring and threat detection platform.

## Overview

SecurityAI is a comprehensive security monitoring and threat detection platform that leverages machine learning to identify anomalies, classify threats, parse logs, and detect lateral movement in enterprise networks.

## Architecture

The platform follows a microservices architecture with the following components:

### Frontend
- React 18 with TypeScript
- Tailwind CSS for styling
- Real-time dashboard with WebSocket integration
- Role-based UI (Admin, Analyst, Viewer)

### Backend
- FastAPI with Python 3.11
- REST API and WebSocket endpoints
- JWT authentication with refresh tokens
- Celery + Redis for background tasks

### ML Pipeline
- Anomaly Detection: Isolation Forest
- Threat Classification: Random Forest
- Log Parsing: DistilBERT
- Lateral Movement Detection: NetworkX
- MLflow for model tracking and ONNX export

### Databases
- PostgreSQL: metadata (users, assets, alerts)
- InfluxDB: time-series event data and system metrics
- Elasticsearch: log data and threat intelligence
- Redis: caching and session storage

## Deployment

### Development
```bash
docker-compose up
```

### Production
```bash
helm install securityai ./helm
```

## Session Changes (Nov 12, 2025)

- Renamed top-level `models/` to `artifacts/` to avoid import confusion
  - Updated paths in ML scripts and config to `artifacts/saved` and `artifacts/temp`
  - Training outputs now write to `artifacts/saved/security_training_summary.json` and `.md`
- Added an updated Alerts API payload using `tags` and `metadata`
  - Replaced legacy `event_type`/`details` in alert creation examples
- Added pytest guidance for import paths
  - `pytest.ini` includes `pythonpath = ml/app`
  - Alternatively set `PYTHONPATH` in shell for tests

### Quick Commands

- Minimal training: `python -m ml.app.scripts.train_minimal`
- Generate MD report: `python -m ml.app.scripts.generate_md_report`
- Run tests with config: `pytest -c pytest.ini`
- If imports fail on Windows PowerShell:
  - Current session: `set PYTHONPATH=%CD%\ml\app`
  - Persist: `setx PYTHONPATH "%CD%\ml\app"` (restart shell)

### Updated Paths

- Artifacts root: `artifacts/`
- Saved outputs: `artifacts/saved/`
- Temp outputs: `artifacts/temp/`

## Documentation

- API documentation is available at `/api/docs` when the server is running
- Deployment guide is available in the `/infra/docs` directory
  - See `docs/user_guides/ml_training_guide.md` for artifacts/report usage
  - See `docs/api/api_reference.md` for updated alert payload
  - See `docs/user_guides/troubleshooting.md` for pytest import paths

## License

Proprietary - All rights reserved