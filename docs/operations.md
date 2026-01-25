# AVON Operations Guide

This guide covers day-to-day operations, monitoring, and troubleshooting for AVON deployments.

## Table of Contents

- [Monitoring](#monitoring)
- [Alerting](#alerting)
- [Log Analysis](#log-analysis)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)
- [Maintenance Tasks](#maintenance-tasks)

## Monitoring

### Metrics Overview

AVON exposes Prometheus metrics on port 9090 for all services. Key metrics include:

#### Gateway Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `avon_gateway_packets_total` | Counter | Total packets processed by direction |
| `avon_gateway_bytes_total` | Counter | Total bytes processed |
| `avon_gateway_connections_active` | Gauge | Current active connections |
| `avon_gateway_packet_duration_seconds` | Histogram | Packet processing latency |
| `avon_gateway_errors_total` | Counter | Total errors by type |

#### Auth Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `avon_auth_requests_total` | Counter | Auth requests by status |
| `avon_auth_duration_seconds` | Histogram | Authentication latency |
| `avon_auth_sessions_active` | Gauge | Current active sessions |
| `avon_auth_enrollments_total` | Counter | Agent enrollments |

#### Pulse Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `avon_pulse_heartbeats_total` | Counter | Heartbeats processed |
| `avon_pulse_sessions_expired` | Counter | Sessions expired due to timeout |
| `avon_pulse_token_rotations_total` | Counter | Token rotations performed |

#### Policy Engine Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `avon_policy_evaluations_total` | Counter | Policy decisions by result |
| `avon_policy_evaluation_duration_seconds` | Histogram | Policy evaluation latency |
| `avon_policy_cache_hits_total` | Counter | Policy cache hit rate |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'avon'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - avon
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: ${1}:9090
```

### ServiceMonitor (Prometheus Operator)

If using Prometheus Operator, enable ServiceMonitor:

```yaml
# values.yaml
monitoring:
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus
    interval: 30s
```

### Grafana Dashboard

Import the AVON dashboard from the Helm chart:

```bash
# Dashboard is automatically created as a ConfigMap
kubectl get configmap -n avon -l grafana_dashboard=1
```

Key dashboard panels:
- **Connected Agents**: Real-time count of active agents
- **Active Tunnels**: Number of established tunnels
- **Auth Latency (p95)**: Authentication performance
- **Packet Rate**: Gateway throughput
- **Policy Decisions**: Allow/deny distribution
- **Error Rate**: System health indicator

### Health Checks

All services expose health endpoints:

```bash
# Check gateway health
kubectl exec -n avon deploy/avon-gateway -- curl -s http://localhost:8080/health

# Check readiness
kubectl exec -n avon deploy/avon-auth -- curl -s http://localhost:8080/ready

# Kubernetes probes automatically check these endpoints
```

## Alerting

### Critical Alerts

```yaml
# prometheus-alerts.yaml
groups:
  - name: avon-critical
    rules:
      - alert: AVONGatewayDown
        expr: up{job="avon-gateway"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AVON Gateway is down"
          description: "Gateway {{ $labels.instance }} has been down for more than 1 minute"

      - alert: AVONAuthHighLatency
        expr: histogram_quantile(0.95, rate(avon_auth_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "AVON Auth latency is high"
          description: "p95 auth latency is {{ $value }}s"

      - alert: AVONDatabaseConnectionFailure
        expr: avon_database_connections_failed_total > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AVON cannot connect to database"

      - alert: AVONCAUnavailable
        expr: up{job="avon-ca"} == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "AVON CA is unavailable"
          description: "CA unavailability prevents new agent enrollments"
```

### Warning Alerts

```yaml
      - alert: AVONHighSessionCount
        expr: avon_auth_sessions_active > 10000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High number of active sessions"
          description: "{{ $value }} active sessions may indicate scaling needs"

      - alert: AVONHeartbeatFailureRate
        expr: rate(avon_pulse_heartbeats_failed_total[5m]) / rate(avon_pulse_heartbeats_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Heartbeat failure rate above 1%"

      - alert: AVONPolicyDenialSpike
        expr: rate(avon_policy_evaluations_total{result="deny"}[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Spike in policy denials"
          description: "May indicate misconfiguration or attack"
```

## Log Analysis

### Log Format

All AVON services use structured JSON logging:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "info",
  "target": "avon_gateway::handler",
  "message": "Connection established",
  "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "session_id": "sess_xyz789",
  "source_ip": "192.168.1.100",
  "span_id": "abc123"
}
```

### Accessing Logs

```bash
# View gateway logs
kubectl logs -n avon -l app.kubernetes.io/component=gateway --tail=100 -f

# View auth service logs
kubectl logs -n avon -l app.kubernetes.io/component=auth --tail=100 -f

# View logs from all services
kubectl logs -n avon -l app.kubernetes.io/name=avon --tail=100 -f

# Search for specific agent
kubectl logs -n avon -l app.kubernetes.io/component=auth | grep "agent_id.*a1b2c3d4"
```

### Log Aggregation (Loki)

```yaml
# Promtail configuration
scrape_configs:
  - job_name: avon
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - avon
    pipeline_stages:
      - json:
          expressions:
            level: level
            agent_id: agent_id
            session_id: session_id
      - labels:
          level:
          agent_id:
```

### Common Log Queries

**Failed authentications**:
```logql
{namespace="avon", app="auth"} |= "authentication failed"
```

**Policy denials for specific agent**:
```logql
{namespace="avon", app="policy-engine"} | json | agent_id="a1b2c3d4" | result="deny"
```

**Errors in last hour**:
```logql
{namespace="avon"} | json | level="error" | __timestamp__ > now() - 1h
```

## Troubleshooting

### Agent Connection Issues

**Symptom**: Agent cannot connect to gateway

1. **Check gateway accessibility**:
   ```bash
   # Get gateway external IP
   GATEWAY_IP=$(kubectl get svc avon-gateway -n avon -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

   # Test UDP connectivity (from agent network)
   nc -u -v $GATEWAY_IP 4600
   ```

2. **Check gateway logs**:
   ```bash
   kubectl logs -n avon -l app.kubernetes.io/component=gateway | grep -i error
   ```

3. **Verify agent certificate**:
   ```bash
   # On the agent
   avon-agent status --verbose
   ```

### Authentication Failures

**Symptom**: Agent connects but authentication fails

1. **Check auth service logs**:
   ```bash
   kubectl logs -n avon -l app.kubernetes.io/component=auth | grep -i "auth.*fail"
   ```

2. **Verify agent enrollment status**:
   ```bash
   # Via Admin API
   curl -H "Authorization: Bearer $TOKEN" \
     https://admin.avon.example.com/api/v1/agents/$AGENT_ID
   ```

3. **Check certificate validity**:
   ```bash
   kubectl exec -n avon deploy/avon-ca -- \
     avon-ca verify-cert --agent-id $AGENT_ID
   ```

### Session Drops

**Symptom**: Agents frequently disconnecting

1. **Check pulse service**:
   ```bash
   kubectl logs -n avon -l app.kubernetes.io/component=pulse | grep -i "session.*expired"
   ```

2. **Verify heartbeat interval**:
   ```bash
   # Agent side
   avon-agent config get pulse_interval

   # Server side
   kubectl get deployment avon-pulse -n avon -o jsonpath='{.spec.template.spec.containers[0].env}'
   ```

3. **Check for network issues**:
   ```bash
   # On agent, check packet loss
   avon-agent diagnostics --network-test
   ```

### Policy Evaluation Errors

**Symptom**: Unexpected policy denials

1. **Check policy engine logs**:
   ```bash
   kubectl logs -n avon -l app.kubernetes.io/component=policy-engine | grep $AGENT_ID
   ```

2. **Test policy evaluation**:
   ```bash
   # Dry-run policy check
   curl -X POST -H "Content-Type: application/json" \
     -d '{"agent_id": "...", "resource": "..."}' \
     https://admin.avon.example.com/api/v1/policies/evaluate?dry_run=true
   ```

3. **Review current policies**:
   ```bash
   curl https://admin.avon.example.com/api/v1/policies
   ```

### Database Issues

**Symptom**: Services failing with database errors

1. **Check database connectivity**:
   ```bash
   kubectl run -it --rm debug --image=postgres:16 -n avon -- \
     psql -h avon-postgresql -U avon -c "SELECT 1"
   ```

2. **Check connection pool**:
   ```bash
   kubectl exec -n avon deploy/avon-auth -- \
     curl -s http://localhost:9090/metrics | grep pool
   ```

3. **Review database logs**:
   ```bash
   kubectl logs -n avon -l app.kubernetes.io/name=postgresql
   ```

### Redis Issues

**Symptom**: Session caching failures

1. **Test Redis connectivity**:
   ```bash
   kubectl run -it --rm debug --image=redis:7 -n avon -- \
     redis-cli -h avon-redis-master ping
   ```

2. **Check memory usage**:
   ```bash
   kubectl exec -n avon -it avon-redis-master-0 -- redis-cli info memory
   ```

## Performance Tuning

### Gateway Optimization

**For high connection counts**:
```yaml
gateway:
  resources:
    requests:
      cpu: 1000m
      memory: 1Gi
    limits:
      cpu: 4000m
      memory: 4Gi
  env:
    - name: AVON_WORKER_THREADS
      value: "8"
    - name: AVON_MAX_CONNECTIONS
      value: "50000"
```

### Auth Service Optimization

**For high authentication rates**:
```yaml
auth:
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
  env:
    - name: AVON_DB_POOL_SIZE
      value: "50"
    - name: AVON_REDIS_POOL_SIZE
      value: "20"
```

### Database Tuning

**PostgreSQL settings for AVON**:
```sql
-- Recommended for high-throughput
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';

SELECT pg_reload_conf();
```

### Redis Tuning

```bash
# Increase max memory for session storage
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

### Network Tuning

**Kernel parameters for high-throughput** (on gateway nodes):
```bash
# /etc/sysctl.d/99-avon.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_mem = 65536 131072 262144
```

## Maintenance Tasks

### Certificate Rotation

CA certificates should be rotated annually:

```bash
# Generate new CA certificate (keeps existing agents valid)
kubectl exec -n avon avon-ca-0 -- \
  avon-ca rotate-root --transition-period 30d

# Monitor rotation status
kubectl logs -n avon avon-ca-0 -f | grep rotation
```

### Database Maintenance

**Weekly vacuum**:
```bash
kubectl exec -n avon avon-postgresql-0 -- \
  psql -U avon -c "VACUUM ANALYZE;"
```

**Index maintenance**:
```bash
kubectl exec -n avon avon-postgresql-0 -- \
  psql -U avon -c "REINDEX DATABASE avon;"
```

### Session Cleanup

Expired sessions are automatically cleaned, but manual cleanup is available:

```bash
# Via Admin API
curl -X POST https://admin.avon.example.com/api/v1/sessions/cleanup \
  -H "Authorization: Bearer $TOKEN"
```

### Log Rotation

If not using centralized logging, configure log rotation:

```yaml
# In deployment
containers:
  - name: gateway
    volumeMounts:
      - name: logs
        mountPath: /var/log/avon
volumes:
  - name: logs
    emptyDir:
      sizeLimit: 1Gi
```

## Related Documentation

- [Architecture Overview](architecture.md)
- [Deployment Guide](deployment.md)
- [Security Documentation](security.md)
