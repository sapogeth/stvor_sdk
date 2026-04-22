# STVOR Deployment

Complete deployment and setup guide.

---

## Quick Start (Local Development)

### Prerequisites

- Docker 24+
- Docker Compose 2+
- Node.js 20+

### 1. Clone & Setup

```bash
git clone https://github.com/sapogeth/stvor_sdk.git
cd stvor_sdk
npm install
cd packages/sdk && npm install
```

### 2. Start Services (Docker)

```bash
docker-compose up
```

**Services**:
- API: http://localhost:3001
- Relay: http://localhost:3002
- Dashboard: http://localhost:3001/dashboard
- PostgreSQL: localhost:5433
- Redis: localhost:6379

### 3. Bootstrap Project

```bash
curl -X POST http://localhost:3001/bootstrap
```

Response:
```json
{
  "project_id": "uuid-xxx",
  "api_key": "stvor_live_xxx"
}
```

### 4. Test Connection

```bash
# Terminal 1: Alice
node -e "
const { Stvor } = require('@stvor/sdk');
(async () => {
  const alice = await Stvor.connect({
    userId: 'alice',
    appToken: 'stvor_live_xxx',
    relayUrl: 'http://localhost:3002',
  });
  console.log('Alice connected:', alice.userId);
  alice.onMessage(m => console.log('Alice received:', m.data));
  await new Promise(() => {});
})();
"

# Terminal 2: Bob
node -e "
const { Stvor } = require('@stvor/sdk');
(async () => {
  const bob = await Stvor.connect({
    userId: 'bob',
    appToken: 'stvor_live_xxx',
    relayUrl: 'http://localhost:3002',
  });
  console.log('Bob connected:', bob.userId);
  await bob.send('alice', 'Hello from Bob!');
})();
"
```

---

## Production Deployment

### Architecture Checklist

- [ ] HTTPS/TLS (certificate from Let's Encrypt)
- [ ] PostgreSQL 15+ (managed service or HA setup)
- [ ] Redis 7+ (for replay protection)
- [ ] Load balancer (Nginx/HAProxy)
- [ ] Monitoring (Prometheus + Grafana)
- [ ] Log aggregation (ELK Stack)
- [ ] Backup & restore strategy
- [ ] Disaster recovery plan

### 1. Environment Setup

Create `.env.production`:

```bash
# Node
NODE_ENV=production
PORT=3001
LOG_LEVEL=info

# Database
DATABASE_URL=postgresql://user:pass@db.prod.internal:5432/stvor
DB_POOL_MAX=20
DB_TIMEOUT=5000

# Redis
REDIS_URL=redis://redis.prod.internal:6379
REDIS_PASSWORD=secure_password

# Security
API_KEY_PREFIX=stvor_live
RATE_LIMIT=100  # per minute per IP
CORS_ORIGIN=https://example.com

# Relay
RELAY_PORT=3002
RELAY_MESSAGE_TTL=600000  # 10 minutes
RELAY_MAX_QUEUE=10000

# Analytics
METRICS_ENABLED=true
METRICS_RETENTION=7  # days
```

### 2. Database Setup

#### 2a. PostgreSQL (Managed)

Use AWS RDS, Azure Database, or Google Cloud SQL:

```
Recommended:
- Instance: db.r6i.xlarge (4 CPU, 32GB RAM)
- Storage: 500GB SSD (auto-scaling enabled)
- Backups: Daily, 30-day retention
- Replication: Multi-AZ
- Monitoring: CloudWatch + Datadog
```

**SSL Connection**:
```bash
# Download certificate
wget https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

# Update connection string
DATABASE_URL="postgresql://user:pass@db.prod:5432/stvor?sslmode=require&sslrootcert=global-bundle.pem"
```

#### 2b. Local PostgreSQL (Docker)

```yaml
# docker-compose.prod.yml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: stvor
      POSTGRES_USER: stvor
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5433:5432"
```

#### 2c. Run Migrations

```bash
# Local
npm run migrate

# Production (via CI/CD)
node migrate.js --env production
```

**Migration files**:
```
migrations/
├── 001_initial_schema.sql
├── 002_metrics_schema.sql
├── 003_analytics_schema.sql
└── 004_analytics_handshakes.sql
```

### 3. Redis Setup

#### 3a. AWS ElastiCache

```
Recommended:
- Node type: cache.r6g.xlarge (4 CPU, 32GB RAM)
- Engine: Redis 7.0
- Replication: Multi-AZ (automatic failover)
- Encryption: TLS in transit + at rest
- Backup: Daily automated snapshots
```

#### 3b. Self-Hosted Redis

```bash
# Install on Linux
sudo apt-get install redis-server

# Start
sudo systemctl start redis-server

# Enable on boot
sudo systemctl enable redis-server

# Verify
redis-cli ping  # Should return PONG
```

**Redis Configuration** (`/etc/redis/redis.conf`):

```conf
# Security
requirepass your_secure_password
maxclients 10000

# Memory
maxmemory 16gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1        # Save if 1 key changes in 900s
save 300 10       # Save if 10 keys change in 300s
appendonly yes    # AOF (durability)
appendfsync everysec
```

### 4. API Server Setup

#### 4a. Docker Image

Build:
```bash
docker build -t stvor-api:3.3.0 .
```

Push to registry:
```bash
docker tag stvor-api:3.3.0 registry.example.com/stvor-api:3.3.0
docker push registry.example.com/stvor-api:3.3.0
```

#### 4b. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stvor-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: stvor-api
  template:
    metadata:
      labels:
        app: stvor-api
    spec:
      containers:
      - name: stvor-api
        image: registry.example.com/stvor-api:3.3.0
        ports:
        - containerPort: 3001
        - containerPort: 3002
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: stvor-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: stvor-secrets
              key: redis-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: stvor-api
spec:
  selector:
    app: stvor-api
  ports:
  - name: api
    port: 3001
    targetPort: 3001
  - name: relay
    port: 3002
    targetPort: 3002
  type: LoadBalancer
```

Deploy:
```bash
kubectl apply -f stvor-api.yml
kubectl logs -f deployment/stvor-api
```

### 5. Load Balancer (Nginx)

```nginx
upstream stvor_api {
  least_conn;  # Connection-based load balancing
  server api1.internal:3001 weight=1 max_fails=3 fail_timeout=30s;
  server api2.internal:3001 weight=1 max_fails=3 fail_timeout=30s;
  server api3.internal:3001 weight=1 max_fails=3 fail_timeout=30s;
}

upstream stvor_relay {
  least_conn;
  server relay1.internal:3002 weight=1 max_fails=3 fail_timeout=30s;
  server relay2.internal:3002 weight=1 max_fails=3 fail_timeout=30s;
}

# Redirect HTTP → HTTPS
server {
  listen 80;
  server_name api.stvor.xyz relay.stvor.xyz;
  return 301 https://$server_name$request_uri;
}

# HTTPS API
server {
  listen 443 ssl http2;
  server_name api.stvor.xyz;

  ssl_certificate /etc/letsencrypt/live/api.stvor.xyz/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/api.stvor.xyz/privkey.pem;
  ssl_protocols TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_prefer_server_ciphers on;

  # Security headers
  add_header Strict-Transport-Security "max-age=31536000" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;

  # Rate limiting
  limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
  limit_req zone=api burst=200 nodelay;

  location / {
    proxy_pass http://stvor_api;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
  }
}

# HTTPS Relay
server {
  listen 443 ssl http2;
  server_name relay.stvor.xyz;

  ssl_certificate /etc/letsencrypt/live/relay.stvor.xyz/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/relay.stvor.xyz/privkey.pem;

  location / {
    proxy_pass http://stvor_relay;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_read_timeout 60s;
  }
}
```

### 6. SSL/TLS Certificates

#### 6a. Let's Encrypt (Free)

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot certonly --nginx -d api.stvor.xyz -d relay.stvor.xyz

# Auto-renewal (runs daily)
sudo certbot renew --dry-run
```

#### 6b. Custom Certificate (Paid)

```bash
# Generate CSR
openssl req -new -newkey rsa:4096 -keyout relay.key -out relay.csr

# Submit to CA (Sectigo, DigiCert, etc.)
# Receive: relay.crt + intermediate.crt + root.crt

# Create full chain
cat relay.crt intermediate.crt root.crt > full-chain.pem

# Update Nginx config
ssl_certificate /path/to/full-chain.pem;
ssl_certificate_key /path/to/relay.key;
```

### 7. Monitoring & Logging

#### 7a. Application Monitoring (Prometheus)

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'stvor-api'
    static_configs:
      - targets: ['localhost:3001']
    metrics_path: '/metrics'
```

#### 7b. Log Aggregation (ELK)

```docker
# docker-compose.yml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.0.0
    environment:
      discovery.type: single-node
    ports:
      - "9200:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:8.0.0
    ports:
      - "5601:5601"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.0.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"
```

#### 7c. Application Logs (Winston)

```ts
// src/logger.ts
import * as winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

export default logger;
```

### 8. Backup & Restore

#### 8a. PostgreSQL Backup

```bash
# Full backup
pg_dump \
  --host=db.prod.internal \
  --user=stvor \
  --password \
  stvor > backup_$(date +%Y%m%d).sql

# Compressed backup
pg_dump \
  --host=db.prod.internal \
  --user=stvor \
  --format=custom \
  stvor > backup_$(date +%Y%m%d).dump

# Upload to S3
aws s3 cp backup_*.dump s3://stvor-backups/
```

**Restore**:
```bash
# From SQL
psql stvor < backup_20240101.sql

# From dump
pg_restore -d stvor backup_20240101.dump
```

#### 8b. Redis Backup

```bash
# Manual snapshot
redis-cli BGSAVE
# Creates: /var/lib/redis/dump.rdb

# Upload
aws s3 cp /var/lib/redis/dump.rdb s3://stvor-backups/
```

**Restore**:
```bash
# Copy dump.rdb to Redis data directory
cp dump.rdb /var/lib/redis/

# Restart Redis
sudo systemctl restart redis-server
```

### 9. Security Hardening

#### 9a. Firewall Rules

```bash
# Allow HTTPS only
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp    # SSH (restrict to admin IPs)
sudo ufw deny 3001       # Block direct API access
sudo ufw deny 5433       # Block direct DB access
```

#### 9b. Database Security

```sql
-- Create restricted user (not admin)
CREATE USER stvor_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE stvor TO stvor_app;
GRANT USAGE ON SCHEMA public TO stvor_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO stvor_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO stvor_app;

-- Revoke public access
REVOKE ALL ON DATABASE stvor FROM public;
REVOKE ALL ON SCHEMA public FROM public;
```

#### 9c. Redis Security

```bash
# Disable dangerous commands
redis-cli CONFIG SET slowlog-max-len 0
redis-cli CONFIG REWRITE

# Enable ACL (Redis 6+)
redis-cli ACL SETUSER stvor_app on >strong_password ~* &* +@all -@admin -flushdb -flushall
redis-cli ACL SAVE
```

### 10. CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: docker/setup-buildx-action@v2
      - uses: docker/login-action@v2
        with:
          registry: ${{ secrets.REGISTRY }}
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
      - uses: docker/build-push-action@v4
        with:
          push: true
          tags: ${{ secrets.REGISTRY }}/stvor-api:latest

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -X POST ${{ secrets.DEPLOY_WEBHOOK }} \
            -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}"
```

---

## Troubleshooting

### PostgreSQL Connection Failed

```
Error: connect ECONNREFUSED 127.0.0.1:5433
```

**Fix**:
```bash
# Check if running
docker ps | grep postgres

# Restart
docker-compose down postgres
docker-compose up postgres

# Verify connection
psql postgresql://user:pass@localhost:5433/stvor
```

### Redis Connection Failed

```
Error: Redis connection refused
```

**Fix**:
```bash
# Check if running
docker ps | grep redis

# Test connection
redis-cli ping

# If not running
docker-compose up redis
```

### Rate Limiting Errors

```
Error: ERR_RATE_LIMITED (100 requests per minute per IP)
```

**Fix**:
- Increase limit in `.env`: `RATE_LIMIT=200`
- Implement exponential backoff in client
- Use API key-based rate limiting (per-project limits)

### High Memory Usage

```
Docker container uses 2GB+
```

**Fix**:
```bash
# Check memory usage
docker stats stvor-api

# Reduce in docker-compose
docker-compose.yml:
  services:
    api:
      mem_limit: 512m
```

---

## Performance Tuning

### PostgreSQL

```sql
-- Connection pooling (PgBouncer)
-- Max 100 connections per app instance
max_connections = 1000;
shared_buffers = 256MB;
effective_cache_size = 2GB;
work_mem = 64MB;

-- Indexes
CREATE INDEX idx_messages_recipient ON messages(to_user_id);
CREATE INDEX idx_metrics_timestamp ON metrics(timestamp DESC);
```

### Redis

```conf
# Memory optimization
maxmemory 2gb
maxmemory-policy allkeys-lru

# Network optimization
tcp-backlog 511
timeout 0
```

### API Server

```ts
// Enable compression
import compress from '@fastify/compress';
app.register(compress);

// Connection pooling
pool.max = 50;

// Query batching
await batchedInsert(metrics, 1000);
```

---

## Monitoring Dashboard

Access metrics at: `http://localhost:3001/metrics`

**Key Metrics**:
- `http_requests_total` - Total requests
- `http_request_duration_seconds` - Response time
- `db_pool_connections_used` - DB connections
- `redis_connected` - Redis status
- `encryption_operations_total` - Crypto operations

---

## Disaster Recovery

### RTO/RPO Targets

| Component | RTO | RPO |
|-----------|-----|-----|
| API Server | 5 min | 0 (stateless) |
| PostgreSQL | 15 min | 1 min |
| Redis | 5 min | 5 min |
| Full Outage | 30 min | 15 min |

### Failover Procedure

1. **Detect failure** (monitoring alert)
2. **Promote standby DB** (if multi-AZ)
3. **Restart API servers** (on backup infrastructure)
4. **Verify connectivity** (health check passing)
5. **Monitor metrics** (error rates normal)
6. **RCA** (root cause analysis)

---

## License

MIT
