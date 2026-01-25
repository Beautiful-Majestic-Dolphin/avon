# AVON Deployment Guide

This guide covers deploying AVON in production environments using Helm on Kubernetes.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Scaling Guidelines](#scaling-guidelines)
- [High Availability](#high-availability)
- [Backup and Recovery](#backup-and-recovery)
- [Upgrades](#upgrades)
- [Uninstallation](#uninstallation)

## Prerequisites

### Kubernetes Cluster Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Kubernetes Version | 1.26+ | 1.28+ |
| Nodes | 3 | 5+ |
| CPU (total) | 8 cores | 16+ cores |
| Memory (total) | 16 GB | 32+ GB |
| Storage Class | Standard | SSD-backed |

### Required Tools

```bash
# kubectl (1.26+)
kubectl version --client

# Helm (3.12+)
helm version

# (Optional) k9s for cluster management
brew install k9s  # macOS
```

### External Dependencies

1. **PostgreSQL 14+**: For persistent storage
   - Managed: AWS RDS, GCP Cloud SQL, Azure Database
   - Self-hosted: PostgreSQL Helm chart (included)

2. **Redis 7+**: For session caching
   - Managed: AWS ElastiCache, GCP Memorystore
   - Self-hosted: Redis Helm chart (included)

3. **Load Balancer**: For gateway exposure
   - Cloud: AWS NLB, GCP Network LB, Azure LB
   - On-premise: MetalLB, F5

4. **TLS Certificates**: For ingress
   - cert-manager with Let's Encrypt (recommended)
   - Manual certificate management

## Quick Start

For a minimal development deployment:

```bash
# Add AVON Helm repository (if using OCI)
helm pull oci://ghcr.io/shanedolphin/avons-corners/charts/avon

# Or clone the repository
git clone https://github.com/ShaneDolphin/avons-corners.git
cd avons-corners

# Install with development values
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-dev.yaml \
  --namespace avon \
  --create-namespace

# Verify installation
kubectl get pods -n avon
```

## Installation

### Step 1: Create Namespace

```bash
kubectl create namespace avon
```

### Step 2: Configure Secrets

Create a secrets file (do not commit to version control):

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: avon-secrets
  namespace: avon
type: Opaque
stringData:
  jwt-secret: "your-secure-jwt-secret-min-32-chars"
  database-url: "postgresql://avon:password@postgres:5432/avon"
  redis-url: "redis://:password@redis:6379"
  # For external databases in production
  database-password: "your-database-password"
  redis-password: "your-redis-password"
```

```bash
kubectl apply -f secrets.yaml
```

### Step 3: Install AVON

**Development:**
```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-dev.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets
```

**Staging:**
```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-staging.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets
```

**Production:**
```bash
helm install avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  --namespace avon \
  --set secrets.existingSecret=avon-secrets \
  --set externalDatabase.host=your-rds-endpoint.amazonaws.com \
  --set externalRedis.host=your-elasticache-endpoint.amazonaws.com
```

### Step 4: Verify Installation

```bash
# Check all pods are running
kubectl get pods -n avon

# Expected output:
# NAME                                  READY   STATUS    RESTARTS   AGE
# avon-gateway-xxxxx                    1/1     Running   0          2m
# avon-gateway-xxxxx                    1/1     Running   0          2m
# avon-gateway-xxxxx                    1/1     Running   0          2m
# avon-auth-xxxxx                       1/1     Running   0          2m
# avon-ca-0                             1/1     Running   0          2m
# avon-pulse-xxxxx                      1/1     Running   0          2m
# avon-policy-engine-xxxxx              1/1     Running   0          2m
# avon-admin-api-xxxxx                  1/1     Running   0          2m

# Check services
kubectl get svc -n avon

# Get gateway external IP
kubectl get svc avon-gateway -n avon -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

## Configuration

### Core Values

```yaml
# values.yaml overrides
global:
  imageRegistry: "ghcr.io/shanedolphin/avons-corners"

gateway:
  replicaCount: 3
  service:
    type: LoadBalancer
    port: 4600
    annotations:
      # AWS NLB
      service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
      service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"

auth:
  replicaCount: 3
  logLevel: info

ca:
  replicaCount: 2
  persistence:
    enabled: true
    size: 10Gi
    storageClass: "gp3"
  # Enable HSM for production
  hsm:
    enabled: true
    provider: "aws-cloudhsm"

pulse:
  replicaCount: 3
  pulseInterval: "10s"
  tokenRotationInterval: "30s"

policyEngine:
  replicaCount: 3

adminApi:
  replicaCount: 2
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
    hosts:
      - host: admin.avon.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.avon.example.com
```

### Resource Allocation

| Environment | Gateway | Auth | CA | Pulse | Policy | Admin |
|-------------|---------|------|-----|-------|--------|-------|
| Dev | 50m/64Mi | 50m/64Mi | 50m/64Mi | 50m/64Mi | 50m/64Mi | 50m/64Mi |
| Staging | 100m/128Mi | 100m/128Mi | 100m/128Mi | 100m/128Mi | 100m/128Mi | 100m/128Mi |
| Production | 500m/512Mi | 250m/256Mi | 250m/256Mi | 250m/256Mi | 250m/256Mi | 250m/256Mi |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AVON_LOG_LEVEL` | Logging level (trace, debug, info, warn, error) | `info` |
| `AVON_GRPC_PORT` | gRPC service port | Service-specific |
| `AVON_HEALTH_PORT` | Health check port | `8080` |
| `AVON_METRICS_PORT` | Prometheus metrics port | `9090` |
| `AVON_PULSE_INTERVAL` | Heartbeat interval | `10s` |
| `AVON_TOKEN_ROTATION_INTERVAL` | Session token rotation | `30s` |

## Scaling Guidelines

### Horizontal Scaling

**Gateway**: Scale based on connection count
```bash
# Manual scaling
kubectl scale deployment avon-gateway -n avon --replicas=5

# Or enable HPA
kubectl autoscale deployment avon-gateway -n avon \
  --min=3 --max=20 --cpu-percent=60
```

**Auth/Pulse/Policy Engine**: Scale based on request rate
```yaml
# values.yaml
auth:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
```

### Vertical Scaling

For services hitting memory limits:

```yaml
auth:
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi
```

### Capacity Planning

| Agents | Gateway Pods | Auth Pods | Pulse Pods | DB Connections |
|--------|--------------|-----------|------------|----------------|
| 100 | 2 | 2 | 2 | 20 |
| 1,000 | 3 | 3 | 3 | 50 |
| 10,000 | 5 | 5 | 5 | 100 |
| 100,000 | 15 | 10 | 10 | 300 |

## High Availability

### Pod Disruption Budgets

Enabled by default:
```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1  # At least 1 pod always available
```

For stricter HA:
```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 2  # At least 2 pods always available
```

### Anti-Affinity Rules

Default configuration spreads pods across nodes:
```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/component: gateway
          topologyKey: kubernetes.io/hostname
```

For zone-aware spreading (production):
```yaml
gateway:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app.kubernetes.io/component: gateway
```

### Database High Availability

**PostgreSQL (External)**:
- Use managed service with Multi-AZ (RDS, Cloud SQL)
- Configure read replicas for scaling reads
- Enable automated backups

**Redis (External)**:
- Use managed service with replication (ElastiCache, Memorystore)
- Configure Redis Cluster mode for large deployments

## Backup and Recovery

### Database Backups

**PostgreSQL Backup Script**:
```bash
#!/bin/bash
# backup-postgres.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="avon_backup_${TIMESTAMP}.sql"

# Create backup
pg_dump -h $DB_HOST -U avon -d avon > $BACKUP_FILE

# Upload to S3
aws s3 cp $BACKUP_FILE s3://avon-backups/postgres/

# Cleanup local file
rm $BACKUP_FILE
```

**Automated Backup CronJob**:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: avon
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: postgres:16
              command:
                - /bin/sh
                - -c
                - |
                  pg_dump -h $DB_HOST -U avon -d avon | \
                  gzip | \
                  aws s3 cp - s3://avon-backups/postgres/backup-$(date +%Y%m%d).sql.gz
              envFrom:
                - secretRef:
                    name: avon-secrets
          restartPolicy: OnFailure
```

### CA Key Backup

**Critical**: CA private keys must be backed up securely.

```bash
# Export CA data (encrypted)
kubectl exec -n avon avon-ca-0 -- \
  avon-ca export --encrypt --output /data/ca-export.enc

# Copy to local
kubectl cp avon/avon-ca-0:/data/ca-export.enc ./ca-backup.enc

# Store in secure location (HSM, offline storage)
```

### Recovery Procedures

**Database Recovery**:
```bash
# Download backup
aws s3 cp s3://avon-backups/postgres/backup-20240101.sql.gz ./

# Restore
gunzip -c backup-20240101.sql.gz | psql -h $DB_HOST -U avon -d avon
```

**CA Recovery**:
```bash
# Copy backup to new CA pod
kubectl cp ca-backup.enc avon/avon-ca-0:/data/

# Import CA data
kubectl exec -n avon avon-ca-0 -- \
  avon-ca import --decrypt --input /data/ca-export.enc
```

## Upgrades

### Rolling Upgrade

```bash
# Update to new version
helm upgrade avon deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  --namespace avon \
  --set global.imageTag=v1.2.0

# Monitor rollout
kubectl rollout status deployment/avon-gateway -n avon
kubectl rollout status deployment/avon-auth -n avon
```

### Blue-Green Deployment

For zero-downtime upgrades:

```bash
# Deploy new version to separate namespace
helm install avon-v2 deploy/helm/avon \
  -f deploy/helm/avon/values-production.yaml \
  --namespace avon-v2 \
  --create-namespace

# Test new version
kubectl port-forward svc/avon-admin-api -n avon-v2 8080:8080
curl http://localhost:8080/health

# Switch traffic (update DNS/LB)
# Then remove old version
helm uninstall avon -n avon
```

### Rollback

```bash
# View history
helm history avon -n avon

# Rollback to previous version
helm rollback avon 1 -n avon

# Or rollback to specific revision
helm rollback avon 3 -n avon
```

## Uninstallation

```bash
# Remove AVON
helm uninstall avon -n avon

# Remove persistent volume claims (WARNING: destroys data)
kubectl delete pvc -n avon --all

# Remove namespace
kubectl delete namespace avon
```

## Troubleshooting Installation

### Common Issues

**Pods stuck in Pending**:
```bash
kubectl describe pod <pod-name> -n avon
# Check for resource constraints or node selector issues
```

**Database connection failures**:
```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:16 -n avon -- \
  psql -h avon-postgresql -U avon -d avon -c "SELECT 1"
```

**Gateway not getting external IP**:
```bash
# Check LoadBalancer events
kubectl describe svc avon-gateway -n avon

# For on-premise, ensure MetalLB is configured
kubectl get configmap -n metallb-system
```

## Related Documentation

- [Architecture Overview](architecture.md)
- [Operations Guide](operations.md)
- [Security Documentation](security.md)
