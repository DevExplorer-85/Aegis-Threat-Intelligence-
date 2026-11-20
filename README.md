# 🛡️ Aegis Cyber Threat Intelligence (CTI) Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47A248.svg)](https://www.mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg)](https://www.docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-StatefulSet-326CE5.svg)](https://kubernetes.io)
[![Prometheus](https://img.shields.io/badge/Prometheus-Monitoring-E6522C.svg)](https://prometheus.io)
[![Grafana](https://img.shields.io/badge/Grafana-Dashboards-F46800.svg)](https://grafana.com)

**Aegis** is an enterprise-grade Cyber Threat Intelligence & Incident Response platform built on MongoDB distributed architectures. It integrates real-time OSINT feeds (CIRCL, Botvrij.eu, ThreatFox), polymorphic threat correlation, ACID-compliant incident isolation, horizontal sharding, Zero-Trust RBAC with field-level redaction, container orchestration, automated disaster recovery, and hybrid graph/vector analytics.

---

## 🏛️ Platform Architecture

```text
                               ┌──────────────────────────────────────────────────────────┐
                               │             Aegis Analyst & Admin Frontend               │
                               │           (Pine & Cream Modern Editorial UI)             │
                               └────────────────────────────┬─────────────────────────────┘
                                                            │ HTTP / SSE / REST
                                                            ▼
                               ┌──────────────────────────────────────────────────────────┐
                               │                 FastAPI Backend Service                  │
                               │        (JWT Auth, RBAC Enforcement, Prometheus Metrics)  │
                               └──────────┬──────────────┬──────────────┬───────────────┬─┘
                                          │              │              │               │
                 ┌────────────────────────┘              │              │               └───────────────────────┐
                 ▼                                       ▼              ▼                                       ▼
    ┌───────────────────────────┐          ┌──────────────────┐  ┌───────────────────────────┐    ┌───────────────────────────┐
    │ Standalone CTI Database   │          │ Replica Set rs0  │  │ Distributed Sharded       │    │ Observability Stack       │
    │ mongo1:27017              │          │ mongo10:27018    │  │ mongos:27019              │    │ Prometheus (:9090)        │
    │ - Feed Events & IOCs      │          │ - Multi-Doc ACID │  │ - Sharded Collections     │    │ Grafana (:3013)           │
    │ - Threat Actors & Passages│          │ - Auto Failover  │  │ - ConfigSvr + Shard Nodes │    │ MongoDB Exporter (:9216)  │
    └───────────────────────────┘          └──────────────────┘  └───────────────────────────┘    └───────────────────────────┘
```

---

## 📂 Project Directory Structure

```text
├── backend/                        # FastAPI REST API & Core Engine
│   ├── app/                        # Application Source Code
│   │   ├── auth.py                 # JWT Authentication & RBAC Role Enforcement
│   │   ├── database.py             # Database Client & Connection Pools
│   │   ├── lab_api.py              # Lab & Operations API Dispatcher
│   │   ├── lab13_api.py            # Container & Cloud Orchestration API
│   │   ├── lab14_api.py            # Backup, Restore & Alerting Engine
│   │   ├── lab15_api.py            # Multi-Tenant Case Management API
│   │   ├── lab16_api.py            # Cassandra & Neo4j Hybrid Investigations
│   │   ├── lab17_api.py            # Vector Search & RAG Semantic Answering
│   │   ├── lab18_api.py            # Comparative Database Benchmark API
│   │   └── main.py                 # FastAPI Application Factory & Routes
│   ├── scripts/                    # Automation, Migration & Lab Execution Scripts
│   ├── tests/                      # Automated PyTest Test Suite (46+ Tests)
│   ├── requirements.txt            # Python Dependencies
│   └── .env.example                # Backend Environment Template
│
├── frontend/                       # Modern Editorial Threat Intelligence UI
│   ├── cluster.css                 # Enterprise Design System & Typography
│   ├── cluster.js                  # Dynamic Sidebar, RBAC Switcher & Navigation
│   ├── index.html                  # Live Threat Stream & IOC Search Dashboard
│   ├── experiments.html            # Enterprise Capabilities & Module Hub
│   ├── experiment.html             # Interactive Lab Execution Console
│   ├── lab13.html                  # Containers & Cloud Orchestration Console
│   ├── lab14.html                  # Disaster Recovery & Observability Workspace
│   └── cases.html                  # Incident Response & Case Management
│
├── chapter-12/                     # Zero-Trust Security & RBAC Configuration
├── chapter-13/                     # Containers & Cloud Deployment
│   ├── docker-compose/             # 3-Node Replica Set with KeyFile Auth & Exporter
│   ├── k8s/                        # Kubernetes StatefulSet & Headless Service Manifests
│   ├── monitoring/                 # Prometheus Telemetry & Scrape Configuration
│   ├── terraform/                  # MongoDB Atlas Infrastructure Blueprint (HCL)
│   └── README.md                   # Chapter 13 Architecture & Setup Guide
├── chapter-14/                     # Monitoring, Backup & Disaster Recovery
├── chapter-15/                     # Multi-Tenant Case Management Specifications
├── chapter-16/                     # Cassandra & Neo4j Polyglot Configurations
├── chapter-17/                     # Vector Embeddings & RAG Configurations
├── chapter-18/                     # Multi-Database Comparative Capstone
│
├── docker-compose.yml              # Complete Multi-Container Lab Orchestration
├── Dockerfile                      # Production Multi-Stage Container Definition
├── lab.py                          # Unified CLI Lab Runner (Chapters 7-18)
├── .env.example                    # Global Environment Template
└── .gitignore                      # Security-First Git Exclusion Rules
```

---

## ⚡ Core Capabilities by Chapter

| Chapter | Domain | Highlights |
|---|---|---|
| **Chapter 7** | **Cache & Performance** | WiredTiger cache sizing, schema memory analysis, working set optimization. |
| **Chapter 8** | **IOC Correlation Engine** | Polymorphic threat actor inventory, heterogeneous schema indexing, cross-feed correlation. |
| **Chapter 9** | **Ingestion SLA & Integrity** | WriteConcern (`w: majority`, `j: true`), ingestion latency SLA benchmarking, tamper-proof auditing. |
| **Chapter 10** | **Atomic Incident Response** | ACID multi-document transactions, automatic retry backoff, quota reservation ledger. |
| **Chapter 11** | **Global Sharded Cluster** | Range/hash shard keys, hotspot mitigation, zero-downtime resharding simulation. |
| **Chapter 12** | **Zero-Trust & Security** | Granular RBAC (`admin`, `threat_hunter`, `soc_analyst`, `compliance_auditor`), TLS encryption, field redaction. |
| **Chapter 13** | **Containers & Cloud Ops** | 3-node Docker replica set with keyfile auth, Prometheus sidecar, K8s StatefulSet, Atlas Terraform. |
| **Chapter 14** | **Monitoring & Backup** | Continuous metric telemetry, threshold alerting, automated hourly backups, restore verification. |
| **Chapter 15** | **Multi-Tenant Case Mgmt** | Isolated incident playbooks, audit logs, organizational tenant boundaries. |
| **Chapter 16** | **Polyglot Graph Analysis** | Neo4j threat graph exploration, Cassandra append-only high-velocity telemetry logs. |
| **Chapter 17** | **Vector Search & RAG** | High-dimensional embeddings, semantic security report chunking, LLM-assisted threat insights. |
| **Chapter 18** | **Comparative Capstone** | Workload benchmarks comparing document, relational, columnar, and graph engines. |

---

## 🚀 Quickstart & Deployment

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Python 3.12+ (for local development)

### 2. Configuration
Copy the sample environment file and configure local credentials:

```bash
cp .env.example .env
cp backend/.env.example backend/.env
```

### 3. Launch via Docker Compose
Start the complete infrastructure with a single command:

```bash
docker compose up -d
```

This provisions:
- **`mongo1`**: Standalone CTI database on port `27017`
- **`mongo10`**: Replica set node on port `27018`
- **`mongos`**: Distributed sharding router on port `27019`
- **`cti`**: FastAPI backend service on port `8000`
- **`prometheus`**: Time-series metrics on port `9090`
- **`grafana`**: Interactive dashboards on port `3013`

### 4. Access the Services

- **Web Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Module Hub**: [http://localhost:8000/experiments.html](http://localhost:8000/experiments.html)
- **Chapter 13 Cloud Ops**: [http://localhost:8000/extras/lab13](http://localhost:8000/extras/lab13)
- **Prometheus UI**: [http://localhost:9090](http://localhost:9090)
- **Grafana Dashboards**: [http://localhost:3013](http://localhost:3013) *(Login: admin / admin)*
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## ☸️ Kubernetes Deployment (Chapter 13.2)

Deploy the 3-node MongoDB StatefulSet with headless DNS discovery and persistent volume claims:

```bash
# 1. Apply Headless Service & StatefulSet manifests
kubectl apply -f chapter-13/k8s/mongo-headless-svc.yaml
kubectl apply -f chapter-13/k8s/mongo-statefulset.yaml

# 2. Monitor pod provisioning
kubectl get pods -l app=mongo -w

# 3. Initialize Replica Set inside mongo-0
kubectl exec -it mongo-0 -- mongosh --eval "
  rs.initiate({
    _id: 'rs0',
    members: [
      { _id: 0, host: 'mongo-0.mongo-headless-svc.mongodb-cluster.svc.cluster.local:27017' },
      { _id: 1, host: 'mongo-1.mongo-headless-svc.mongodb-cluster.svc.cluster.local:27017' },
      { _id: 2, host: 'mongo-2.mongo-headless-svc.mongodb-cluster.svc.cluster.local:27017' }
    ]
  })
"

# 4. Verify pod resiliency & self-healing
kubectl delete pod mongo-2
kubectl get pods -l app=mongo -w
```

---

## 🧪 Testing & Verification

Run the full backend test suite to verify route registration, JWT security, ACID transactions, and cluster health:

```bash
cd backend
PYTHONPATH=. pytest tests/ -v
```

All 46+ test suites validate:
- Role-based authorization and boundary denials
- Non-destructive replica set failovers
- Tamper-proof audit logs and field redaction
- Prometheus metric parsers and Kubernetes status reporting

---

## 🔐 Security & Governance

- **Zero-Trust Access**: JWT authentication with strictly segregated RBAC roles.
- **Redaction by Design**: Sensitive employee & indicator attributes masked at the aggregation view layer.
- **Auditing**: Tamper-evident transaction logging for critical SOC analyst actions.
- **Secrets Management**: Credentials, keyfiles, and private keys excluded from version control.

---

## 📄 License & Attribution

This project is licensed under the MIT License. Threat data feeds provided by CIRCL, Botvrij.eu, and abuse.ch ThreatFox under their respective OSINT terms.
