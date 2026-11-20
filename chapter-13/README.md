# Chapter 13: Containers, Cloud & Operations Engineering

Comprehensive implementation guide for production containerization, replica set resilience, telemetry monitoring, Kubernetes orchestration, and HashiCorp Terraform cloud infrastructure.

---

## 1. Architecture Overview

```
                      +------------------------------------------+
                      |         CTI Operations Platform          |
                      |  (FastAPI Backend + Pine-Green Frontend) |
                      +--------------------+---------------------+
                                           |
                +--------------------------+--------------------------+
                |                          |                          |
+---------------+----------------+ +-------+--------+ +---------------+----------------+
|  Docker Distributed Clusters   | |   Monitoring   | |     Cloud & Orchestration      |
|  • Standalone: mongo1 (27017)  | |  • Prometheus  | |  • Kubernetes StatefulSet:     |
|  • ReplicaSet: mongo10 (27018) | |    (Port 9090) | |    mongo-0, mongo-1, mongo-2   |
|  • Sharding: mongos (27019)    | |  • Grafana     | |  • MongoDB Atlas via Terraform |
|  • Auto-Failover Engine        | |    (Port 3013) | |    (AWS us-east-1 M10 Cluster) |
+--------------------------------+ +----------------+ +--------------------------------+
```

---

## 2. Implemented Backend Endpoints

### 1. `GET /api/services/lab13`
Reports live status across all 4 operational layers:
- **Replica Set rs0:** Live connection check, member roles (`PRIMARY` vs `SECONDARY`), optime timestamps, uptime, and heartbeat ping.
- **Failover Status:** Previous vs newly elected primary, election duration in ms, and read-loss audit during step-down.
- **Monitoring:** Live Prometheus exporter status and direct Grafana / Prometheus URLs.
- **Kubernetes StatefulSet:** Pod health (`mongo-0`, `mongo-1`, `mongo-2`), role distribution, data integrity checks, and recovery latency.
- **MongoDB Atlas:** Cluster tier, AWS region, deployment status, and error diagnosis if API keys are missing.

### 2. `POST /api/services/lab13/failover`
Executes an automated, safe primary step-down (`replSetStepDown`) on replica set `rs0`.
- **Security:** Requires explicit administrator confirmation payload `{"confirm": true}`.
- Measures election duration, reads served during failover, and verifies zero data loss (`failed_reads: 0`).

### 3. `GET /api/ops/metrics/deployment?minutes=15|30|60|360`
Returns time-series deployment telemetry for:
- Operations count by type (`query`, `insert`, `update`, `delete`).
- Replica set member state timeline.
- Replication lag and heartbeat ping.
- Active client connections.
- WiredTiger memory cache usage in MiB.
- Election counts.

---

## 3. Dedicated Admin Workspace UI

The Chapter 13 workspace is available at both:
- [http://localhost:8000/extras/lab13](http://localhost:8000/extras/lab13)
- [http://localhost:8000/admin/ops?tab=deployment](http://localhost:8000/admin/ops?tab=deployment)

### 6 Specialized Tabs:
1. **Overview:** High-level executive cards for Primary, Replica Members, Last Failover, Ops/sec, Kubernetes, and Atlas.
2. **Replica Set:** Live topology table with member roles, health (1.0), uptime, and latency.
3. **Failover & Resilience:** Election duration metrics with the **"⚡ Test Automated Failover"** button (with modal confirmation).
4. **Monitoring:** Operations-by-type time-series charts with 15m, 30m, 1h, and 6h interval filters, linking to Prometheus (9090) and Grafana (3013).
5. **Kubernetes StatefulSet:** Declarative table showing pods `mongo-0`, `mongo-1`, `mongo-2` with persistent volume recovery verification.
6. **MongoDB Atlas:** Terraform blueprint status, cluster configuration, and API configuration assistant.

---

## 4. Infrastructure Manifests

- **Kubernetes StatefulSet:** `chapter-13/k8s/mongo-statefulset.yaml`
  - Deploys a 3-replica MongoDB StatefulSet with headless Service and persistent volume claims.
- **HashiCorp Terraform:** `chapter-13/terraform/main.tf`
  - Declarative infrastructure-as-code for provisioning a MongoDB Atlas dedicated `M10` replica set in `AWS us-east-1`.
- **Prometheus Scrape Configuration:** `chapter-13/monitoring/prometheus.yml`

---

## 5. Verification & Testing

To run the automated Chapter 13 test suite:
```bash
cd no-sql_lab-7/backend
PYTHONPATH=. ./.venv_mac/bin/pytest tests/test_lab13.py
```
*Result:* 5/5 test cases passing.
