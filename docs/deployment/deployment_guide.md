# Deployment Guide

## Overview

This guide provides detailed instructions for deploying the SecurityAI Platform in various environments. It covers prerequisites, installation steps, configuration options, and post-deployment verification.

## Prerequisites

### Hardware Requirements

**Minimum Production Environment**:
- **Kubernetes Cluster**:
  - Control Plane: 3 nodes (4 CPU cores, 16GB RAM each)
  - Worker Nodes: 5+ nodes (8 CPU cores, 32GB RAM each)
  - GPU Nodes (optional): 2+ nodes with NVIDIA GPUs (for ML acceleration)
- **Storage**:
  - 500GB+ SSD storage for databases
  - 1TB+ storage for logs and analytics data
- **Network**:
  - 1Gbps+ network interfaces
  - Load balancer for external access

**Development/Testing Environment**:
- **Kubernetes Cluster**:
  - Single-node or small cluster (4 CPU cores, 16GB RAM minimum)
- **Storage**:
  - 100GB+ storage
- **Network**:
  - Standard networking with port access

### Software Requirements

- **Kubernetes**: v1.22+ (v1.24+ recommended)
- **Helm**: v3.8+
- **Docker**: 20.10+
- **kubectl**: Matching Kubernetes version
- **Database Systems**:
  - PostgreSQL 14+
  - Elasticsearch 8.x
  - InfluxDB 2.x
  - Redis 6.x

### Network Requirements

- **Ingress Controller**: NGINX Ingress or equivalent
- **DNS**: Resolvable hostnames for services
- **Certificates**: TLS certificates for secure communication
- **Firewall Rules**: Appropriate access for services

### Access Requirements

- **Kubernetes**: Admin access to the cluster
- **Registry**: Access to container registry
- **Storage**: Permissions to create persistent volumes
- **DNS**: Ability to configure DNS records

## Deployment Options

### Option 1: Helm Chart Deployment

The recommended deployment method using Helm charts for Kubernetes.

#### Step 1: Add SecurityAI Helm Repository

```bash
helm repo add securityai https://charts.securityai.example.com
helm repo update
```

#### Step 2: Configure Values

Create a custom `values.yaml` file with your specific configuration:

```yaml
# values.yaml example
global:
  environment: production
  domain: securityai.example.com
  storageClass: managed-premium

frontend:
  replicas: 3
  resources:
    requests:
      cpu: 1
      memory: 2Gi
    limits:
      cpu: 2
      memory: 4Gi

backend:
  replicas: 5
  resources:
    requests:
      cpu: 2
      memory: 4Gi
    limits:
      cpu: 4
      memory: 8Gi

ml:
  replicas: 2
  gpuEnabled: true
  resources:
    requests:
      cpu: 4
      memory: 16Gi
    limits:
      cpu: 8
      memory: 32Gi
      nvidia.com/gpu: 1

databases:
  postgresql:
    enabled: true
    external: false
    size: 100Gi
  elasticsearch:
    enabled: true
    external: false
    size: 200Gi
  influxdb:
    enabled: true
    external: false
    size: 100Gi
  redis:
    enabled: true
    external: false
    size: 20Gi

ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod

monitoring:
  enabled: true
  prometheus:
    retention: 15d
  grafana:
    adminPassword: "changeme"
```

#### Step 3: Install the Chart

```bash
helm install securityai securityai/securityai-platform -f values.yaml -n securityai --create-namespace
```

#### Step 4: Verify Deployment

```bash
kubectl get pods -n securityai
kubectl get services -n securityai
kubectl get ingress -n securityai
```

### Option 2: Manual Deployment

For environments without Helm or for customized deployments.

#### Step 1: Create Namespace

```bash
kubectl create namespace securityai
```

#### Step 2: Deploy Databases

Apply database manifests:

```bash
kubectl apply -f manifests/databases/ -n securityai
```

#### Step 3: Deploy Backend Services

```bash
kubectl apply -f manifests/backend/ -n securityai
```

#### Step 4: Deploy ML Services

**Important**: The ML service requires the `ml_models` directory to be populated with the 9 production modules. Ensure your Persistent Volume Claim (PVC) is correctly bound and populated, or use an `initContainer` to download the latest models from the Model Registry.

```bash
kubectl apply -f manifests/ml/ -n securityai
```

**Example InitContainer Configuration:**
```yaml
initContainers:
  - name: download-models
    image: securityai/model-downloader:latest
    command: ["python", "download_models.py", "--all"]
    volumeMounts:
      - name: model-volume
        mountPath: /app/ml_models
```

#### Step 5: Deploy Frontend

```bash
kubectl apply -f manifests/frontend/ -n securityai
```

#### Step 6: Configure Ingress

```bash
kubectl apply -f manifests/ingress/ -n securityai
```

### Option 3: Docker Compose (Development Only)

For local development and testing environments.

#### Step 1: Clone Repository

```bash
git clone https://github.com/example/securityai-platform.git
cd securityai-platform
```

#### Step 2: Configure Environment

Create a `.env` file with required variables:

```
POSTGRES_PASSWORD=devpassword
ELASTICSEARCH_PASSWORD=devpassword
REDIS_PASSWORD=devpassword
SECRET_KEY=devsecretkey
DEBUG=true
```

#### Step 3: Start Services

```bash
docker-compose up -d
```

## Configuration

### Environment Variables

#### Backend Service

| Variable | Description | Default |
|----------|-------------|--------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@postgres:5432/securityai` |
| `ELASTICSEARCH_URL` | Elasticsearch connection | `http://elasticsearch:9200` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `SECRET_KEY` | Secret key for sessions | *Required* |
| `DEBUG` | Enable debug mode | `false` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hosts | `*` |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000` |

#### ML Service

| Variable | Description | Default |
|----------|-------------|--------|
| `MLFLOW_TRACKING_URI` | MLflow tracking server URI | `http://mlflow:5000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@postgres:5432/securityai` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `MODEL_REGISTRY_PATH` | Path to model registry | `/app/models` |
| `ENABLE_GPU` | Enable GPU acceleration | `false` |
| `BATCH_SIZE` | Batch size for processing | `32` |
| `ENABLE_UEBA` | Enable UEBA features | `true` |
| `ENABLE_SOAR` | Enable SOAR features | `true` |
| `ENABLE_EDR` | Enable EDR features | `true` |
| `ENABLE_XDR` | Enable XDR features | `true` |
| `SPLUNK_URL` | Splunk URL for XDR integration | *Optional* |
| `CROWDSTRIKE_URL` | CrowdStrike URL for XDR integration | *Optional* |

#### Frontend Service

| Variable | Description | Default |
|----------|-------------|--------|
| `VITE_API_URL` | Backend API URL | `http://localhost:8000` |
| `VITE_WS_URL` | WebSocket URL | `ws://localhost:8000/ws` |
| `VITE_AUTH_PROVIDER` | Authentication provider | `local` |
| `VITE_ENABLE_ANALYTICS` | Enable usage analytics | `false` |

### Custom Configuration Files

#### Backend Configuration

Create a `config.yaml` file and mount it to `/app/config/config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8000
  workers: 4
  timeout: 60

logging:
  level: INFO
  format: json
  output: stdout

security:
  allowed_hosts:
    - securityai.example.com
  cors_origins:
    - https://securityai.example.com
  auth:
    jwt_expiration: 86400
    refresh_expiration: 604800
```

#### ML Configuration

Create a `ml-config.yaml` file and mount it to `/app/config/ml-config.yaml`:

```yaml
models:
  default_threat_model: "threat-detection-v2"
  default_vulnerability_model: "vuln-assessment-v1"
  model_refresh_interval: 3600

processing:
  batch_size: 64
  max_queue_size: 1000
  workers: 4

integration:
  splunk:
    enabled: true
    url: "https://splunk.example.com"
    index: "security_events"
  crowdstrike:
    enabled: true
    url: "https://api.crowdstrike.com"
    poll_interval: 300
```

## Database Initialization

### PostgreSQL

#### Option 1: Automatic Migration

The backend service can automatically apply migrations on startup:

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.db.init_db
```

#### Option 2: Manual Migration

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- alembic upgrade head
```

### Elasticsearch

Initialize Elasticsearch indices and templates:

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.db.init_elasticsearch
```

### InfluxDB

Create required buckets and retention policies:

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.db.init_influxdb
```

## Post-Deployment Steps

### Create Initial Admin User

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.scripts.create_admin \
  --username admin \
  --password "securepassword" \
  --email "admin@example.com"
```

### Load Initial Data

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.scripts.load_initial_data
```

### Verify Services

1. **Backend API**:
   ```bash
   curl https://api.securityai.example.com/health
   ```

2. **ML Service**:
   ```bash
   curl https://api.securityai.example.com/ml/health
   ```

3. **Frontend**:
   Open `https://securityai.example.com` in a browser

## Scaling Configuration

### Horizontal Pod Autoscaler

Create HPA for dynamic scaling:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: securityai-backend-hpa
  namespace: securityai
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: securityai-backend
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

Apply the configuration:

```bash
kubectl apply -f hpa.yaml
```

### Vertical Pod Autoscaler (Optional)

For environments with VPA support:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: securityai-ml-vpa
  namespace: securityai
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: securityai-ml
  updatePolicy:
    updateMode: Auto
  resourcePolicy:
    containerPolicies:
    - containerName: '*'
      minAllowed:
        cpu: 1
        memory: 1Gi
      maxAllowed:
        cpu: 8
        memory: 32Gi
```

## Monitoring Setup

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: securityai-monitor
  namespace: securityai
spec:
  selector:
    matchLabels:
      app: securityai
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
```

### Grafana Dashboards

Import the provided dashboards into Grafana:

1. Navigate to Grafana UI
2. Go to Dashboards > Import
3. Upload the JSON files from `monitoring/dashboards/`

## Backup Configuration

### Database Backups

Configure regular PostgreSQL backups:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: securityai
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:14
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres -U postgres -d securityai -F c -f /backup/securityai-$(date +%Y%m%d).dump
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-secret
                  key: password
            volumeMounts:
            - name: backup-volume
              mountPath: /backup
          volumes:
          - name: backup-volume
            persistentVolumeClaim:
              claimName: postgres-backup-pvc
          restartPolicy: OnFailure
```

## Troubleshooting

### Common Issues

#### Database Connection Failures

**Symptoms**: Backend services failing to start, connection timeout errors

**Solutions**:
1. Verify database pods are running:
   ```bash
   kubectl get pods -n securityai -l app=postgres
   ```
2. Check database logs:
   ```bash
   kubectl logs -n securityai deployment/securityai-postgres
   ```
3. Verify connection string in environment variables or config

#### ML Service Errors

**Symptoms**: ML endpoints returning 500 errors, model loading failures

**Solutions**:
1. Check ML service logs:
   ```bash
   kubectl logs -n securityai deployment/securityai-ml
   ```
2. Verify model files exist in the model registry
3. Check GPU availability if GPU acceleration is enabled:
   ```bash
   kubectl exec -it deployment/securityai-ml -n securityai -- nvidia-smi
   ```

#### Ingress Issues

**Symptoms**: Unable to access services externally

**Solutions**:
1. Verify ingress controller is running:
   ```bash
   kubectl get pods -n ingress-nginx
   ```
2. Check ingress configuration:
   ```bash
   kubectl describe ingress -n securityai
   ```
3. Verify DNS resolution for configured hostnames

### Diagnostic Commands

#### Check Pod Status

```bash
kubectl get pods -n securityai
kubectl describe pod <pod-name> -n securityai
```

#### View Container Logs

```bash
kubectl logs -f deployment/securityai-backend -n securityai
kubectl logs -f deployment/securityai-ml -n securityai
kubectl logs -f deployment/securityai-frontend -n securityai
```

#### Check Service Connectivity

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- curl -v postgres:5432
kubectl exec -it deployment/securityai-backend -n securityai -- curl -v elasticsearch:9200
```

#### Restart Deployments

```bash
kubectl rollout restart deployment/securityai-backend -n securityai
kubectl rollout restart deployment/securityai-ml -n securityai
kubectl rollout restart deployment/securityai-frontend -n securityai
```

## Maintenance Procedures

### Version Upgrades

#### Helm Upgrade

```bash
helm repo update
helm upgrade securityai securityai/securityai-platform -f values.yaml -n securityai
```

#### Manual Upgrade

```bash
kubectl apply -f manifests/updated/ -n securityai
kubectl rollout status deployment/securityai-backend -n securityai
kubectl rollout status deployment/securityai-ml -n securityai
kubectl rollout status deployment/securityai-frontend -n securityai
```

### Database Maintenance

#### PostgreSQL Vacuum

```bash
kubectl exec -it deployment/securityai-postgres -n securityai -- psql -U postgres -d securityai -c "VACUUM ANALYZE;"
```

#### Elasticsearch Index Management

```bash
kubectl exec -it deployment/securityai-backend -n securityai -- python -m app.scripts.manage_indices --operation optimize
```

## Uninstallation

### Helm Uninstall

```bash
helm uninstall securityai -n securityai
```

### Manual Uninstall

```bash
kubectl delete -f manifests/ -n securityai
kubectl delete namespace securityai
```

### Data Cleanup (Optional)

```bash
kubectl delete pvc --all -n securityai
```

> **Warning**: This will delete all persistent data. Make sure you have backups if needed.