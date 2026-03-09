##BLUETEAMING Cyber-Physical Security Platform

> **An AI-driven security platform that unifies cybersecurity monitoring, physical access control, video surveillance, and safety systems into a single autonomous intelligence layer.**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Security Threat Detection Pipeline](#3-security-threat-detection-pipeline)
   - [Pipeline Architecture](#31-pipeline-architecture)
   - [Stage 1 — Data Sources](#32-stage-1--data-sources)
   - [Stage 2 — Data Ingestion Layer](#33-stage-2--data-ingestion-layer)
   - [Stage 3 — Normalization Layer](#34-stage-3--normalization-layer)
   - [Stage 4 — Feature Extraction](#35-stage-4--feature-extraction)
   - [Stage 5 — Detection Engines](#36-stage-5--detection-engines)
   - [Stage 6 — Event Correlation Engine](#37-stage-6--event-correlation-engine)
   - [Stage 7 — Threat Classification](#38-stage-7--threat-classification)
   - [Stage 8 — Automated Response](#39-stage-8--automated-response)
   - [Stage 9 — Incident Management](#310-stage-9--incident-management)
4. [Technology Stack](#4-technology-stack)
5. [Project Structure](#5-project-structure)
6. [Core Data Models](#6-core-data-models)
7. [AI Agent & Tool System](#7-ai-agent--tool-system)
8. [Database Schema](#8-database-schema)
9. [API Reference](#9-api-reference)
10. [Licensing & Subscription Tiers](#10-licensing--subscription-tiers)
11. [Plugin Architecture & Future Integrations](#11-plugin-architecture--future-integrations)
12. [Security Requirements](#12-security-requirements)
13. [Development Phases & Roadmap](#13-development-phases--roadmap)
14. [Getting Started](#14-getting-started)
15. [Contributing Guidelines](#15-contributing-guidelines)
16. [Training Mode](#16-training-mode)

---

## 1. Project Overview

This platform integrates the following domains into one unified AI-driven system:

| Domain | Capabilities |
|---|---|
| **Cybersecurity Monitoring** | Network anomaly detection, log correlation, threat intelligence |
| **AI Video Surveillance** | Object detection, behavior analysis, restricted zone monitoring |
| **Access Control** | Badge readers, biometric systems, door controllers |
| **Safety Monitoring** | Fire, gas, and environmental sensors |
| **Incident Investigation** | Timeline reconstruction, forensic evidence, AI analysis |
| **Autonomous AI Operations** | Automated threat response, tool orchestration |
| **Voice Interaction** | Speech-to-text command interface, conversational AI |

The architecture is **modular and microservice-based**, designed so that future modules — drones, robotic patrols, smart city integrations, predictive risk modeling, and autonomous facility management — can be added without restructuring the core system.

---

## 2. System Architecture

```
+----------------------------------------------------+
|                 Voice Interface                     |
|        Speech Recognition + Conversational AI      |
+----------------------------------------------------+
                        |
                        v
+----------------------------------------------------+
|                AI Security Agent                    |
|         Reasoning Engine + Tool Orchestration      |
+----------------------------------------------------+
                        |
                        v
+----------------------------------------------------+
|         Security Threat Detection Pipeline         |
|  Ingest → Normalize → Detect → Correlate → Classify|
+----------------------------------------------------+
                        |
                        v
+----------------------------------------------------+
|                Tool Execution Layer                |
|  Cyber Tools | Vision Tools | Access | Safety      |
+----------------------------------------------------+
        |             |             |         |
        v             v             v         v
 Network Logs    Camera Feeds    Door Logs  Sensors
        |             |             |         |
        +-------------+-------------+---------+
                        |
                        v
+----------------------------------------------------+
|              Event Correlation Engine              |
+----------------------------------------------------+
                        |
                        v
+----------------------------------------------------+
|              Incident Management System            |
|      Alerts | Reports | Timeline | Forensics       |
+----------------------------------------------------+
```

**How it fits together:**

```
Devices → Event Ingestion → Threat Detection Pipeline → AI Security Agent → Response
```

The pipeline is the critical middle layer. Without it, alerts become chaotic and the AI agent cannot reason reliably.

---

## 3. Security Threat Detection Pipeline

The pipeline is the backbone of the platform. It processes every incoming security signal and classifies it as:

- **Normal activity** — no action required
- **Suspicious activity** — monitoring escalated
- **Confirmed security threat** — automated response triggered

### 3.1 Pipeline Architecture

```
Data Sources
    ↓
Data Ingestion Layer         ← Collects raw events from all devices
    ↓
Normalization Layer          ← Converts varied formats into a standard schema
    ↓
Feature Extraction           ← Derives analytical features for AI models
    ↓
Detection Engines            ← Rule-based, AI-based, and computer vision
    ↓
Event Correlation Engine     ← Combines alerts to identify real threats
    ↓
Threat Classification        ← Assigns risk level (low / suspicious / high / critical)
    ↓
Response Automation          ← Executes countermeasures
    ↓
Incident Management          ← Records timeline, evidence, and actions taken
```

---

### 3.2 Stage 1 — Data Sources

The pipeline ingests signals from every security domain.

**Cyber Sources**
- Firewall logs
- Network traffic captures
- Endpoint telemetry
- Authentication systems (Active Directory, LDAP, SSO)
- Cloud platform logs (AWS CloudTrail, Azure Monitor, GCP Logging)

**Physical Security**
- CCTV cameras
- Door access systems and badge readers
- Motion sensors

**Safety Systems**
- Fire alarms
- Temperature and humidity sensors
- Gas sensors

**Future / Expansion Sources**
- Drone telemetry
- Robotic patrol units
- Autonomous vehicles
- Smart city infrastructure sensors

---

### 3.3 Stage 2 — Data Ingestion Layer

This layer collects raw data, queues it, and distributes it for downstream processing.

**Responsibilities:**
- Receive events from all data sources
- Buffer events during high-load periods
- Distribute events to the normalization layer

**Recommended Technologies:**
- Apache Kafka (event streaming at scale)
- Redis Streams (lightweight queueing)
- WebSocket connections (real-time device feeds)

**Example Raw Event:**

```json
{
  "source": "camera_warehouse_2",
  "event": "motion_detected",
  "timestamp": "2026-03-06T02:14:00Z"
}
```

> **Developer Note:** Every device must have a registered `device_id` in the devices table before its events are accepted by the ingestion layer. Unregistered sources are quarantined for review.

---

### 3.4 Stage 3 — Normalization Layer

Different devices produce different payload formats. This layer converts all of them into a single **Standard Security Event Schema**.

**Standard Security Event Schema:**

```json
{
  "event_id": "uuid",
  "event_type": "intruder_detected",
  "device_type": "camera",
  "device_id": "warehouse_camera_2",
  "severity": "medium",
  "timestamp": "2026-03-06T02:14:00Z",
  "location": "warehouse sector A",
  "data": {
    "object_type": "person",
    "confidence": 0.93
  }
}
```

**Severity Scale:**

| Level | Value | Meaning |
|---|---|---|
| Informational | `info` | Routine system events |
| Low | `low` | Minor deviations, no immediate action |
| Medium | `medium` | Potential concern, escalate for review |
| High | `high` | Likely threat, trigger alert |
| Critical | `critical` | Confirmed incident, immediate response required |

---

### 3.5 Stage 4 — Feature Extraction

Before AI models process an event, relevant analytical features are extracted.

**Network Log Features:**
- Packet frequency per second
- Unusual destination IP addresses
- Abnormal traffic volume relative to baseline
- Protocol anomalies

**Video Analytics Features:**
- Object type detected (person, vehicle, object)
- Motion speed and direction
- Entry direction (toward restricted zone or away)
- Dwell time in a location

**Authentication Event Features:**
- IP geolocation (matches expected region?)
- Login time (within working hours?)
- Device fingerprint (known device?)
- Failure count within time window

> **Developer Note:** Feature extraction should be parallelized per event source type. Network log features and video features should run in separate workers to prevent one source from blocking the other.

---

### 3.6 Stage 5 — Detection Engines

Multiple detection engines run in parallel on extracted features.

#### Rule-Based Detection Engine
Deterministic rules that trigger immediately on known patterns.

Examples:
- Login attempt outside defined working hours
- More than 5 failed login attempts within 60 seconds
- Door forced open (sensor reports door open without valid access event)
- Badge used at a location more than 500 km from the last swipe

#### AI-Based Anomaly Detection Engine
Statistical and machine learning models that detect deviations from baseline behavior.

Examples:
- Network traffic volume 3 standard deviations above historical baseline
- System calling an API it has never contacted before
- Unusual data transfer volume initiated at night

#### Computer Vision Engine
YOLO-based object detection and behavioral models for video feeds.

Examples:
- Person detected in a restricted zone
- Fire or smoke detected in a monitored area
- Weapon-like object detected
- Crowd formation anomaly

Each engine outputs **alert objects** which feed into the correlation engine.

---

### 3.7 Stage 6 — Event Correlation Engine

The correlation engine is where isolated alerts become meaningful intelligence. It combines alerts from multiple sources to surface real threats and suppress false positives.

**Example Correlation Scenario:**

```
02:14:00  Camera detects a person in warehouse sector A
02:14:05  Door access denied (badge not authorized for that zone)
02:14:12  Server login attempt from an internal IP in that warehouse
```

**AI Conclusion:**
```
Threat: Possible internal breach attempt
Confidence: 87%
Recommended Action: Lock sector doors, alert SOC, flag server account
```

Without correlation, each of these events might be dismissed individually. Together, they form a high-confidence incident.

**Correlation Rules are defined using:**
- Temporal proximity (events within a time window)
- Spatial proximity (events from the same physical location or network segment)
- Entity linking (same person, device, or IP across multiple alerts)
- Behavioral sequencing (known attack patterns from MITRE ATT&CK framework)

---

### 3.8 Stage 7 — Threat Classification

The AI agent assigns a final risk classification to the correlated event.

| Classification | Response Mode |
|---|---|
| `low_risk` | Log and monitor |
| `suspicious` | Flag for SOC review, increase monitoring frequency |
| `high_threat` | Trigger automated response, alert on-call team |
| `critical_incident` | Full incident response activated, escalate to leadership |

**Example Classification Output:**

```json
{
  "threat_level": "critical",
  "incident_type": "data_center_intrusion",
  "confidence": 0.91,
  "correlated_events": ["evt_001", "evt_002", "evt_003"],
  "recommended_actions": ["lock_sector_doors", "isolate_server", "alert_soc"]
}
```

---

### 3.9 Stage 8 — Automated Response

Based on threat classification, the system can execute responses automatically without human intervention (configurable per tier and policy).

**Cyber Responses:**
- Block IP at firewall level
- Isolate a compromised server from the network
- Disable a flagged user account
- Force multi-factor re-authentication

**Physical Responses:**
- Lock sector doors remotely
- Activate facility alarms
- Initiate camera tracking on detected intruder
- Notify security personnel with location data

**Safety Responses:**
- Shut down machinery in a hazardous zone
- Activate fire suppression systems
- Trigger emergency ventilation for gas events

> **Developer Note:** All automated response actions must be logged to the `ai_actions` table with full parameters, tool used, and result. This is critical for post-incident forensic review and regulatory compliance.

---

### 3.10 Stage 9 — Incident Management

Every confirmed threat produces a structured incident record.

**Incident Record Contains:**
- Full event timeline with timestamps
- Evidence references (video clips, log excerpts, sensor readings)
- Automated actions taken and their outcomes
- AI analysis narrative
- Assigned status (open / investigating / resolved / closed)

**Example Incident Timeline:**

```
02:14:00  Person detected in warehouse sector A by camera_warehouse_2
02:14:05  Door access denied — badge not authorized for sector A
02:14:12  Server login attempt detected from 192.168.10.44
02:14:15  Large outbound data transfer initiated (2.3 GB)
02:14:16  AI Agent: server isolated, sector doors locked, SOC alerted
02:14:18  Incident record created — ID: INC-2026-0892
```

---

## 4. Technology Stack

| Category | Technology | Purpose |
|---|---|---|
| **Primary Language** | Python | Orchestration, AI, API |
| **High-Performance Services** | Rust / Go | Real-time event processing |
| **API Framework** | FastAPI | REST endpoints |
| **Inter-Service Communication** | gRPC, WebSocket | Low-latency service calls |
| **Message Broker** | Apache Kafka | Event streaming |
| **Caching** | Redis | Session state, fast lookups |
| **AI / ML** | PyTorch | Model training and inference |
| **Computer Vision** | OpenCV, YOLO | Video analytics |
| **Orchestration** | Kubernetes | Deployment at scale |
| **Infrastructure as Code** | Terraform | Cloud provisioning |
| **Primary Database** | PostgreSQL | Structured relational data |
| **Time-Series Data** | TimescaleDB | Event and sensor time-series |
| **Object Storage** | S3-compatible | Video recordings, forensic files |

---

## 5. Project Structure

```
security-ai-platform/
│
├── backend/
│   ├── api-gateway/
│   │   ├── main.py                  # FastAPI app entry point
│   │   └── routes/                  # Route definitions per domain
│   │
│   ├── ai-agent/
│   │   ├── agent.py                 # Main AI agent decision loop
│   │   ├── tool_registry.py         # Dynamic tool registration
│   │   └── reasoning_engine.py      # Threat reasoning logic
│   │
│   ├── threat-pipeline/             # ← Security Threat Detection Pipeline
│   │   ├── ingestion.py             # Stage 2: Data ingestion
│   │   ├── normalizer.py            # Stage 3: Event normalization
│   │   ├── feature_extractor.py     # Stage 4: Feature extraction
│   │   ├── detection_engines/
│   │   │   ├── rule_engine.py       # Stage 5a: Rule-based detection
│   │   │   ├── anomaly_engine.py    # Stage 5b: AI anomaly detection
│   │   │   └── vision_engine.py     # Stage 5c: Computer vision detection
│   │   ├── correlation_engine.py    # Stage 6: Event correlation
│   │   ├── classifier.py            # Stage 7: Threat classification
│   │   └── responder.py             # Stage 8: Automated response
│   │
│   ├── cyber-monitor/
│   │   ├── network_monitor.py
│   │   ├── log_collector.py
│   │   └── anomaly_detection.py
│   │
│   ├── video-analytics/
│   │   ├── camera_service.py
│   │   ├── object_detection.py
│   │   └── behavior_analysis.py
│   │
│   ├── access-control/
│   │   ├── badge_monitor.py
│   │   ├── biometric_service.py
│   │   └── door_controller.py
│   │
│   ├── safety-monitor/
│   │   ├── fire_detection.py
│   │   ├── gas_sensor_monitor.py
│   │   └── environmental_monitor.py
│   │
│   ├── incident-manager/
│   │   ├── incident_service.py
│   │   ├── timeline_builder.py
│   │   └── report_generator.py
│   │
│   └── voice-interface/
│       ├── speech_to_text.py
│       ├── command_parser.py
│       └── text_to_speech.py
│
├── database/
│   ├── schema.sql
│   └── migrations/
│
├── frontend/
│   ├── dashboard/
│   ├── incident-viewer/
│   └── camera-monitor/
│
├── ai-models/
│   ├── vision-models/
│   ├── anomaly-models/
│   └── behavior-models/
│
├── integrations/
│   ├── drone-api/
│   ├── robot-patrol/
│   ├── smart-city/
│   ├── vehicle-control/
│   └── facility-management/
│
└── docs/
    ├── architecture.md
    ├── pipeline.md
    └── api-reference.md
```

---

## 6. Core Data Models

### Standard Security Event

All normalized events across the platform use this schema:

```json
{
  "event_id": "uuid",
  "event_type": "intruder_detected",
  "timestamp": "2026-03-06T02:14:00Z",
  "source": {
    "device_id": "camera_warehouse_3",
    "device_type": "camera"
  },
  "severity": "high",
  "location": "warehouse sector A",
  "data": {
    "object_type": "person",
    "confidence": 0.93
  }
}
```

### Incident Timeline Entry

```json
{
  "incident_id": "INC-2026-0892",
  "timeline": [
    { "time": "02:14:00", "event": "Person detected in warehouse", "source": "camera_warehouse_2" },
    { "time": "02:14:05", "event": "Door access denied", "source": "access_control_sectorA" },
    { "time": "02:14:12", "event": "Server login detected", "source": "auth_server_01" },
    { "time": "02:14:15", "event": "Large data transfer started", "source": "network_monitor" }
  ]
}
```

### Device Types Reference

| Type | Description |
|---|---|
| `camera` | CCTV or IP camera |
| `door_lock` | Electronic door controller |
| `sensor` | Fire, gas, environmental sensor |
| `server` | Physical or virtual server |
| `robot` | Robotic patrol unit |
| `drone` | Aerial surveillance drone |
| `vehicle` | Security vehicle |

---

## 7. AI Agent & Tool System

### Agent Decision Loop

```python
class SecurityAgent:

    def __init__(self, tools):
        self.tools = tools

    def investigate(self, alert):

        if alert["type"] == "network_anomaly":
            return self.tools.execute(
                "analyze_network_logs",
                {"ip": alert["source_ip"]}
            )

        if alert["type"] == "intruder_detected":
            return self.tools.execute(
                "track_camera_target",
                {"camera_id": alert["camera"]}
            )
```

### Tool Registry

The tool registry allows dynamic registration and execution of security tools.

```python
class ToolRegistry:

    def __init__(self):
        self.tools = {}

    def register(self, name, function):
        self.tools[name] = function

    def execute(self, name, params):
        if name in self.tools:
            return self.tools[name](**params)
        else:
            raise Exception(f"Tool not found: {name}")
```

### Tool Interface Specification

Every tool in the platform must implement the standard `SecurityTool` interface:

```python
class SecurityTool:
    name = "tool_name"

    def execute(self, params: dict) -> dict:
        pass
```

**Example — Block IP Tool:**

```python
class BlockIP(SecurityTool):
    name = "block_ip"

    def execute(self, params):
        ip = params["ip"]
        firewall.block(ip)
        return {"status": "blocked", "ip": ip}
```

> **Developer Note:** Every tool execution is logged to the `ai_actions` table. Tools must return a consistent result dict. Never raise unhandled exceptions inside a tool — catch errors and return `{"status": "failed", "error": "..."}`.

---

## 8. Database Schema

### Core Tables

```sql
-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR NOT NULL UNIQUE,
    password_hash VARCHAR NOT NULL,
    role VARCHAR NOT NULL,
    subscription_plan VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Devices
CREATE TABLE devices (
    id UUID PRIMARY KEY,
    device_type VARCHAR NOT NULL,  -- camera | door_lock | sensor | server | robot | drone | vehicle
    location VARCHAR,
    status VARCHAR DEFAULT 'active',
    ip_address VARCHAR,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Events
CREATE TABLE events (
    id UUID PRIMARY KEY,
    event_type VARCHAR NOT NULL,
    device_id UUID REFERENCES devices(id),
    timestamp TIMESTAMP NOT NULL,
    severity VARCHAR NOT NULL,
    raw_data JSONB
);

-- Incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    title VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'open',
    severity VARCHAR NOT NULL,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    description TEXT
);

-- Incident Events (join table)
CREATE TABLE incident_events (
    incident_id UUID REFERENCES incidents(id),
    event_id UUID REFERENCES events(id),
    PRIMARY KEY (incident_id, event_id)
);

-- AI Actions Log
CREATE TABLE ai_actions (
    id UUID PRIMARY KEY,
    incident_id UUID REFERENCES incidents(id),
    action_type VARCHAR NOT NULL,
    tool_used VARCHAR NOT NULL,
    parameters JSONB,
    timestamp TIMESTAMP DEFAULT NOW(),
    result JSONB
);
```

---

## 9. API Reference

### Main Server Entry Point

```python
from fastapi import FastAPI
from api.routes import alerts, incidents

app = FastAPI(title="AI Security Platform")

app.include_router(alerts.router)
app.include_router(incidents.router)

@app.get("/")
def root():
    return {"status": "AI Security Platform Running"}
```

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/events` | Ingest a raw security event |
| `GET` | `/incidents` | List all incidents |
| `GET` | `/incidents/{id}` | Get incident details and timeline |
| `POST` | `/incidents/{id}/respond` | Trigger manual response action |
| `GET` | `/devices` | List all registered devices |
| `POST` | `/devices` | Register a new device |
| `GET` | `/alerts` | List active alerts |
| `GET` | `/health` | Platform health check |

### Event Ingestion Endpoint

```python
from fastapi import APIRouter
from services.event_service import process_event

router = APIRouter()

@router.post("/events")
async def receive_event(event: dict):
    result = process_event(event)
    return {"status": "received", "analysis": result}
```

---

## 10. Licensing & Subscription Tiers

| Feature | Free | Professional | Enterprise |
|---|---|---|---|
| Cameras | 5 | Unlimited | Unlimited |
| Devices | 10 | Unlimited | Unlimited |
| Events per day | 1,000 | Unlimited | Unlimited |
| AI Investigations | Basic | Full autonomous | Full autonomous |
| Advanced Analytics | ✗ | ✓ | ✓ |
| API Integrations | ✗ | ✓ | ✓ |
| Robotics & Drones | ✗ | ✗ | ✓ |
| Predictive Security AI | ✗ | ✗ | ✓ |
| Private Deployment | ✗ | ✗ | ✓ |

---

## 11. Plugin Architecture & Future Integrations

All external system integrations use a standard plugin interface to keep the core platform stable while extensions expand.

### Plugin Interface

```python
class ExternalSystemPlugin:

    def connect(self):
        pass

    def send_command(self, command: dict):
        pass

    def receive_data(self) -> dict:
        pass
```

### Planned Integration Modules

| Module | Capabilities |
|---|---|
| **Drone Surveillance** | Aerial patrol, thermal cameras, perimeter monitoring |
| **Robotic Patrol Units** | Autonomous patrol, suspicious person detection, emergency response |
| **Vehicle Control Systems** | Autonomous patrol routes, GPS tracking, remote control |
| **Smart City Integration** | Traffic cameras, public sensors, emergency services data |
| **Autonomous Facility Management** | Lighting, HVAC, power, locks, elevators |
| **Predictive Risk Modeling** | Fire risk prediction, equipment failure forecasting, threat anticipation |

---

## 12. Security Requirements

All components of the platform must meet these baseline security standards:

- **End-to-end encryption** for all data in transit (TLS 1.3 minimum)
- **Encryption at rest** for all stored events, incidents, and video
- **Multi-factor authentication** for all human access to the platform
- **Tamper-proof audit logs** — log entries must be append-only and cryptographically signed
- **Strict role-based access control (RBAC)** — users access only the resources their role permits
- **Audit trails** — all actions (human and AI) are logged with actor, timestamp, and full parameters
- **Secrets management** — API keys and credentials stored in a dedicated secrets manager (HashiCorp Vault or cloud equivalent), never in code or environment files

---

## 13. Development Phases & Roadmap

| Phase | Focus | Deliverables |
|---|---|---|
| **Phase 1** | Core monitoring and logging | Event ingestion, normalization, database, basic dashboards |
| **Phase 2** | AI investigation engine | Correlation engine, threat classification, AI agent, tool registry |
| **Phase 3** | AI surveillance | Video analytics, YOLO integration, behavior analysis |
| **Phase 4** | Incident automation | Automated response, incident management, reporting |
| **Phase 5** | Voice AI interface | Speech-to-text, command parser, conversational AI |
| **Phase 6** | Robotics and drones | Plugin architecture, drone API, robotic patrol integration |

---

## 14. Getting Started

### Prerequisites

- Python 3.11+
- Node.js 20+ (for frontend)
- PostgreSQL 15+
- Apache Kafka

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/security-ai-platform.git
cd security-ai-platform

# Install Python dependencies
cd backend
pip install -r requirements.txt

# Run database migrations
python database/migrate.py

# Start the API gateway
uvicorn api-gateway.main:app --reload --port 8000
```

### Environment Variables

```env
DATABASE_URL=postgresql://user:password@localhost:5432/security_platform
KAFKA_BROKER=localhost:9092
REDIS_URL=redis://localhost:6379
AI_MODEL_PATH=./ai-models/
SECRET_KEY=your-secret-key-here
```

---

## 15. Contributing Guidelines

### Branch Naming

```
feature/pipeline-normalization
fix/correlation-engine-timeout
docs/update-api-reference
```

### Commit Message Format

```
feat(pipeline): add feature extraction for video analytics
fix(agent): handle missing tool gracefully with error result
docs(readme): update getting started section
```

### Pull Request Requirements

- All new pipeline stages must include unit tests with at least one normal case and one edge case
- All AI tool implementations must implement the `SecurityTool` interface
- All database changes must include a migration file
- All automated response actions must log to the `ai_actions` table

---

---

## 16. Training Mode

The platform includes a fully isolated **Training Mode** designed for two audiences:

- **Students** learning cybersecurity fundamentals through hands-on simulation
- **Corporate security personnel** drilling real-world detection, response, and threat prediction scenarios

Training Mode runs in a sandboxed environment completely separated from production systems. No real infrastructure is ever at risk.

### Four Training Environments

| Environment | Best For |
|---|---|
| **Simulated Attack Labs** | Hands-on detection and response skill-building |
| **CTF-Style Challenges** | Individual skill progression and certification prep |
| **Red Team vs Blue Team Drills** | Corporate team coordination and SOC readiness |
| **AI Threat Prediction Sandbox** | Behavioral threat modeling and predictive intelligence |

### How It Fits in the Platform

Training Mode plugs directly into the existing pipeline architecture using **synthetic event generators** and **cloned sandbox environments** — so trainees use the exact same tools, dashboards, and AI agent as production operators. The only difference is the data source.

```
[Synthetic Attack Generator] → [Real Detection Pipeline] → [Real AI Agent] → [Trainee Dashboard]
         ↑                                                                           ↓
  Scenario Engine                                                          Score + Debrief Engine
```

> For full training architecture, scenario catalog, scoring systems, role progression, and implementation guide, see the complete training documentation:
>
> **📄 [TRAINING_MODE.md](./TRAINING_MODE.md)**

---

*Built on the principle that structured intelligence defeats chaos — in security, as in strategy.*


# Training Mode — AI Cyber-Physical Security Platform

> **A fully sandboxed training system for cybersecurity students and corporate security personnel to learn detection, monitoring, prevention, capture, and threat prediction using the same tools and pipeline as production.**

---

## Table of Contents

1. [Overview & Philosophy](#1-overview--philosophy)
2. [Who This Is For](#2-who-this-is-for)
3. [How Training Mode Works](#3-how-training-mode-works)
4. [Architecture — Training vs Production](#4-architecture--training-vs-production)
5. [Environment 1 — Simulated Attack Labs](#5-environment-1--simulated-attack-labs)
6. [Environment 2 — CTF-Style Challenges](#6-environment-2--ctf-style-challenges)
7. [Environment 3 — Red Team vs Blue Team Drills](#7-environment-3--red-team-vs-blue-team-drills)
8. [Environment 4 — AI Threat Prediction Sandbox](#8-environment-4--ai-threat-prediction-sandbox)
9. [Skill Progression & Role Tracks](#9-skill-progression--role-tracks)
10. [Scoring, Debrief & Performance Metrics](#10-scoring-debrief--performance-metrics)
11. [Synthetic Attack Generator](#11-synthetic-attack-generator)
12. [Safety & Isolation Guarantees](#12-safety--isolation-guarantees)
13. [Training Mode API Reference](#13-training-mode-api-reference)
14. [Implementation Guide for Administrators](#14-implementation-guide-for-administrators)
15. [Scenario Catalog](#15-scenario-catalog)

---

## 1. Overview & Philosophy

Most cybersecurity training fails for one reason: **trainees never touch real systems under real pressure.** They read documentation, watch demonstrations, then face actual threats with zero hands-on experience in high-stakes conditions.

Training Mode solves this by giving every trainee access to the **exact same pipeline, AI agent, tools, and dashboards** used in production — but fed with **synthetic threat data** generated by a scenario engine that replicates real-world attack patterns.

**Core principles:**

- **Learn by doing, not by watching.** Every training session requires active decision-making.
- **Fail safely.** All training runs in a fully isolated sandbox. No real systems, networks, or data are ever involved.
- **Use real tools.** Trainees use Nmap, Wireshark, Burp Suite, Metasploit (sandboxed), Splunk, and the platform's own AI agent — not toy simulations.
- **Debrief everything.** Every session ends with a scored debrief showing what the trainee missed, what they caught, and what the AI agent would have done differently.
- **Predict, don't just react.** Advanced scenarios train personnel to identify threat behaviors *before* an attack completes.

---

## 2. Who This Is For

### Students (Academic & Certification Track)

| Level | Profile | Goal |
|---|---|---|
| **Beginner** | No prior cybersecurity experience | Understand how attacks work and how defenses respond |
| **Intermediate** | Basic networking and OS knowledge | Operate detection tools, analyze logs, respond to incidents |
| **Advanced** | Security+ or equivalent | Conduct penetration tests, threat hunt, build detection rules |

Suitable for students pursuing:
- CompTIA Security+, CySA+, PenTest+
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- University cybersecurity degree programs
- Bootcamp cohorts

### Corporate Security Personnel

| Role | Training Focus |
|---|---|
| **SOC Analyst (L1/L2)** | Alert triage, escalation decisions, tool operation |
| **Incident Responder** | Containment, evidence preservation, timeline reconstruction |
| **Threat Hunter** | Proactive hunting, anomaly identification, hypothesis-driven investigation |
| **Red Team Operator** | Offensive simulation, exploitation, post-exploitation techniques |
| **Blue Team Defender** | Detection engineering, hardening, automated response tuning |
| **Security Manager / CISO** | Tabletop exercises, strategic decision-making under attack pressure |

---

## 3. How Training Mode Works

### Activation

Training Mode is a platform-level toggle. It can be enabled per organization, per team, or per individual user. It is **never active on the same environment as production data**.

```bash
# Enable training mode for an organization
POST /admin/training/enable
{
  "org_id": "org_uuid",
  "mode": "training",
  "environment": "isolated_sandbox"
}
```

### What Changes in Training Mode

| Component | Production | Training Mode |
|---|---|---|
| Data Sources | Real devices, real networks | Synthetic event generator |
| AI Agent | Operates on real threats | Operates on synthetic threats with scoring overlay |
| Tools (Nmap, Wireshark, etc.) | Target real infrastructure | Target sandboxed virtual networks |
| Response Actions | Affect real systems | Simulated — logged but not executed |
| Dashboards | Live operational data | Scenario-driven synthetic data |
| Debrief Engine | Not present | Active — scores every decision |

### What Stays Identical

- The full **Security Threat Detection Pipeline** (all 9 stages)
- The **AI Agent reasoning engine** and tool registry
- The **Event Correlation Engine**
- All **dashboards and monitoring interfaces**
- **Forensics and incident management tools**
- The **voice interface**

Trainees experience the real system under controlled conditions.

---

## 4. Architecture — Training vs Production

```
PRODUCTION ENVIRONMENT
┌─────────────────────────────────────────────┐
│  Real Devices → Real Pipeline → Real Agent  │
│         → Real Response Actions             │
└─────────────────────────────────────────────┘

TRAINING ENVIRONMENT (fully isolated)
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  ┌─────────────────────┐      ┌──────────────────────────────┐  │
│  │  Scenario Engine    │      │   Sandboxed Virtual Network  │  │
│  │  (Attack Generator) │      │   (Cloned device topology)   │  │
│  └────────┬────────────┘      └──────────────┬───────────────┘  │
│           │                                  │                  │
│           └──────────────┬───────────────────┘                  │
│                          ↓                                       │
│          ┌───────────────────────────────┐                       │
│          │  Real Detection Pipeline      │                       │
│          │  (All 9 stages — unchanged)   │                       │
│          └───────────────┬───────────────┘                       │
│                          ↓                                       │
│          ┌───────────────────────────────┐                       │
│          │  Real AI Security Agent       │                       │
│          │  + Scoring Overlay            │                       │
│          └───────────────┬───────────────┘                       │
│                          ↓                                       │
│    ┌─────────────────────────────────────────┐                   │
│    │  Trainee Dashboard + Debrief Engine     │                   │
│    │  Score | Missed Alerts | AI Comparison  │                   │
│    └─────────────────────────────────────────┘                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

The two environments share **zero data, zero network access, and zero infrastructure**. The training environment runs on dedicated isolated containers.

---

## 5. Environment 1 — Simulated Attack Labs

### Purpose

Hands-on guided exercises where trainees operate real detection and response tools against realistic synthetic attack scenarios. Designed for building muscle memory with tools and procedures.

### How a Lab Session Works

```
Instructor (or AI) launches a scenario
        ↓
Synthetic attack events begin flowing into the trainee's pipeline
        ↓
Trainee monitors dashboards, investigates alerts, uses tools
        ↓
Trainee makes response decisions (block IP, isolate server, lock door, etc.)
        ↓
Scenario concludes (attack completes, is stopped, or time expires)
        ↓
Debrief engine scores the session and generates a report
```

### Lab Categories

#### Category A — Detection Labs
*"Can you see what's happening?"*

Trainees practice identifying attacks that are already underway.

| Lab | Attack Type | Skills Practiced |
|---|---|---|
| **Lab A-1** | Port scan reconnaissance | Nmap log analysis, baseline comparison |
| **Lab A-2** | Brute force login attack | Authentication log monitoring, threshold alerts |
| **Lab A-3** | Lateral movement (internal) | Network segmentation analysis, Wireshark |
| **Lab A-4** | Data exfiltration attempt | Traffic volume anomaly detection, DLP alerts |
| **Lab A-5** | Physical intruder + server login | Cross-domain correlation, camera + auth logs |
| **Lab A-6** | Ransomware deployment early stage | Endpoint behavior analysis, file system monitoring |
| **Lab A-7** | Insider threat — data theft | User behavior analytics, access pattern deviation |
| **Lab A-8** | Malware C2 beacon | DNS anomaly detection, outbound traffic analysis |

#### Category B — Response Labs
*"Can you stop it and contain the damage?"*

Trainees practice executing the right response at the right moment.

| Lab | Scenario | Skills Practiced |
|---|---|---|
| **Lab B-1** | Active network intrusion | IP blocking, network isolation, evidence preservation |
| **Lab B-2** | Compromised user account | Account lockout, session termination, forensic review |
| **Lab B-3** | Physical breach in progress | Door lock sequencing, camera tracking, alarm activation |
| **Lab B-4** | Ransomware spreading across servers | Server isolation, backup verification, recovery initiation |
| **Lab B-5** | DDoS attack on web services | Traffic filtering, rate limiting, CDN failover |
| **Lab B-6** | Malware on endpoint | Endpoint quarantine, memory dump, IOC extraction |

#### Category C — Forensics Labs
*"Can you reconstruct what happened after the fact?"*

Trainees investigate synthetic incidents using the platform's forensics tools.

| Lab | Scenario | Skills Practiced |
|---|---|---|
| **Lab C-1** | Post-breach timeline reconstruction | Log correlation, Autopsy, timeline builder |
| **Lab C-2** | Malware reverse engineering (sandbox) | Cuckoo Sandbox, static analysis, YARA rules |
| **Lab C-3** | Insider threat investigation | Access logs, email metadata, behavioral patterns |
| **Lab C-4** | Memory forensics on compromised server | Volatility, process analysis, credential extraction |
| **Lab C-5** | Network forensics reconstruction | Wireshark, NetworkMiner, packet reassembly |

### Lab Configuration Object

```json
{
  "lab_id": "A-5",
  "name": "Physical Intruder + Server Login Correlation",
  "difficulty": "intermediate",
  "duration_minutes": 45,
  "attack_sequence": [
    { "time_offset_seconds": 0,   "event": "person_detected_warehouse", "severity": "medium" },
    { "time_offset_seconds": 300, "event": "door_access_denied",        "severity": "medium" },
    { "time_offset_seconds": 720, "event": "server_login_attempt",      "severity": "high"   },
    { "time_offset_seconds": 900, "event": "data_transfer_anomaly",     "severity": "critical" }
  ],
  "learning_objectives": [
    "Correlate physical and cyber events across domains",
    "Identify multi-stage attack patterns",
    "Execute appropriate containment response"
  ],
  "tools_required": ["correlation_dashboard", "camera_monitor", "network_monitor"],
  "passing_score": 75
}
```

---

## 6. Environment 2 — CTF-Style Challenges

### Purpose

Individual skill challenges with point values, leaderboards, and time pressure. Designed for skill validation, healthy competition, and certification preparation.

### Challenge Structure

Each CTF challenge presents a **frozen synthetic incident** — a snapshot of a security event — and asks the trainee to investigate and answer specific questions to earn points.

```
Challenge presented (synthetic evidence packet)
        ↓
Trainee investigates using platform tools
        ↓
Trainee submits answers (flags, findings, classifications)
        ↓
Points awarded based on accuracy and time
        ↓
Leaderboard updated
```

### Challenge Categories & Point Values

| Category | Point Range | Description |
|---|---|---|
| **Reconnaissance** | 50–150 pts | Identify scanning activity, map attacker footprint |
| **Malware Analysis** | 100–300 pts | Analyze a sandboxed malware sample, extract IOCs |
| **Log Investigation** | 75–200 pts | Find the needle in a log haystack |
| **Network Forensics** | 100–250 pts | Reconstruct attack from packet captures |
| **Cryptography** | 100–300 pts | Decrypt intercepted communications, crack weak keys |
| **Physical + Cyber Correlation** | 150–350 pts | Link physical access events to cyber attack timeline |
| **Threat Attribution** | 200–400 pts | Identify attack group based on TTPs and IOCs |
| **Prediction Challenge** | 200–500 pts | Predict the next attack step from partial evidence |

### Example Challenge

**Challenge: The Midnight Transfer**
*Category: Network Forensics | Points: 250 | Difficulty: Intermediate*

```
You have been given a packet capture file recorded between 00:00 and 02:00.
During this window, an unauthorized data transfer occurred.

Your objectives:
1. Identify the source IP of the transfer (50 pts)
2. Identify the destination IP and geolocation (50 pts)
3. Determine the volume of data transferred in MB (50 pts)
4. Identify the protocol used to exfiltrate data (50 pts)
5. Find the flag hidden in the exfiltrated payload (100 pts — bonus)

Tools available: Wireshark, NetworkMiner, platform network monitor
Time limit: 30 minutes
```

### CTF Leaderboard Schema

```json
{
  "leaderboard": [
    {
      "rank": 1,
      "trainee_id": "uuid",
      "display_name": "CyberSamurai_01",
      "total_points": 4850,
      "challenges_completed": 22,
      "fastest_solve_minutes": 8,
      "badge": "Elite Defender"
    }
  ]
}
```

### Badges & Achievements

| Badge | Requirement |
|---|---|
| **First Blood** | Complete your first challenge |
| **Log Whisperer** | Solve 5 log investigation challenges |
| **Packet Hunter** | Solve 5 network forensics challenges |
| **Malware Slayer** | Complete all malware analysis challenges |
| **Speed Demon** | Solve any hard challenge in under 10 minutes |
| **Perfect Analyst** | Score 100% on a challenge with no hints |
| **Elite Defender** | Reach 5,000 total points |
| **Threat Prophet** | Correctly predict 3 attack sequences before completion |

---

## 7. Environment 3 — Red Team vs Blue Team Drills

### Purpose

Corporate team exercises that simulate real organizational attacks. Red Team operators execute synthetic attack campaigns while Blue Team defenders detect, contain, and respond — using the full platform in real time.

### Drill Structure

```
Pre-Drill Briefing
        ↓
Attack Window Opens (Red Team begins)
        ↓
Detection & Response Window (Blue Team operates)
        ↓
Attack Window Closes
        ↓
Debrief Session (both teams present timelines)
        ↓
Instructor-led gap analysis
```

### Roles

#### Red Team Operators

Red Team participants use the **Attack Simulation Console** — a restricted operator interface that lets them launch pre-approved synthetic attack sequences against the sandboxed environment.

Available attack capabilities:

| Capability | Description |
|---|---|
| **Network Reconnaissance** | Synthetic Nmap scans, service enumeration |
| **Credential Attack** | Brute force simulation, credential stuffing |
| **Lateral Movement** | Simulated pivot across network segments |
| **Privilege Escalation** | Synthetic privilege escalation events |
| **Data Exfiltration** | Simulated data staging and transfer |
| **Physical Breach Simulation** | Synthetic badge cloning, tailgating events |
| **Ransomware Deployment** | Controlled synthetic ransomware spread |
| **Social Engineering** | Synthetic phishing campaign events |

Red Team operators **cannot** affect any real infrastructure. All attack commands are intercepted by the sandbox layer and converted to synthetic event streams.

#### Blue Team Defenders

Blue Team operates the **standard platform interface** — the same dashboards, AI agent, and tools as production — but receiving only synthetic attack data from the Red Team's actions.

Blue Team objectives:
- Detect the attack as early in the kill chain as possible
- Correctly classify the threat level
- Execute appropriate containment responses
- Preserve forensic evidence
- Reconstruct the full attack timeline post-incident

#### Purple Team Facilitator (Optional)

A senior instructor or security architect who observes both teams, injects additional complexity mid-drill, and facilitates the debrief. The Purple Team role bridges offensive and defensive perspectives.

### Drill Scenarios

| Scenario | Complexity | Duration | Focus |
|---|---|---|---|
| **Drill-01: The Opportunist** | Basic | 1 hour | External attacker exploiting a known vulnerability |
| **Drill-02: The Insider** | Intermediate | 2 hours | Malicious insider stealing data over 30 days |
| **Drill-03: The APT Campaign** | Advanced | 4 hours | Multi-stage nation-state-style attack |
| **Drill-04: Physical + Cyber Combined** | Advanced | 3 hours | Physical breach enabling network intrusion |
| **Drill-05: Zero-Day Simulation** | Expert | 4+ hours | Novel attack with no existing detection rules |
| **Drill-06: Supply Chain Attack** | Expert | 4+ hours | Compromise via trusted third-party software |
| **Drill-07: Ransomware Outbreak** | Intermediate | 2 hours | Rapid-spreading ransomware across segments |
| **Drill-08: Tabletop — Board Level** | Strategic | 2 hours | Executive decision-making during crisis (no tools) |

### Scoring Matrix

Both teams are scored independently.

**Blue Team Scoring:**

| Metric | Max Points | Description |
|---|---|---|
| Time to First Detection | 300 | Earlier detection = higher score |
| Alert Accuracy | 200 | Ratio of correct to false-positive responses |
| Containment Effectiveness | 250 | Did the attack spread beyond initial compromise? |
| Evidence Preservation | 150 | Forensic chain of custody maintained? |
| Timeline Reconstruction | 100 | How accurately was the full attack rebuilt? |
| **Total** | **1,000** | |

**Red Team Scoring:**

| Metric | Max Points | Description |
|---|---|---|
| Objective Completion | 300 | Were attack goals achieved? |
| Stealth | 250 | How long before Blue Team detected? |
| Coverage | 200 | Number of attack vectors successfully executed |
| Documentation | 150 | Quality of attack runbook submitted |
| Novel Technique | 100 | Bonus for creative approach not in standard playbook |
| **Total** | **1,000** | |

---

## 8. Environment 4 — AI Threat Prediction Sandbox

### Purpose

Train personnel and AI models to **predict attack behavior before it completes** — shifting from reactive security to predictive security. This is the most advanced training environment and is designed for experienced analysts and security architects.

### Core Concept: The Attack Kill Chain

Every attack follows a sequence. The earlier in the chain a threat is identified, the less damage it causes.

```
Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Exfiltration
     ↑                                                                              ↑
Earliest possible detection                                              Latest acceptable detection
(ideal)                                                                  (too late — damage done)
```

The AI Prediction Sandbox trains analysts to detect at **Reconnaissance** and **Delivery** — not at **Exfiltration**.

### How It Works

The sandbox presents a **partial attack sequence** — events representing the early stages of an attack — and asks the trainee (and the AI model) to predict:

1. What is the most likely next attack step?
2. What is the attacker's probable final objective?
3. What defensive action should be taken *right now* to prevent completion?

```
Partial event stream presented (Stages 1–3 of a kill chain)
        ↓
Trainee submits prediction (next step + objective + recommended action)
        ↓
AI agent submits its own independent prediction
        ↓
Scenario completes — full attack sequence revealed
        ↓
Trainee prediction scored against actual outcome
        ↓
AI prediction scored against actual outcome
        ↓
Comparison debrief: Where did human and AI agree? Where did they diverge?
```

### Threat Behavior Patterns Trained

| Pattern | Description | Indicators |
|---|---|---|
| **Reconnaissance Loop** | Attacker gathering information before striking | Port scans, OSINT queries, repeated probes |
| **Credential Harvest** | Preparing for account-based attack | Multiple failed logins, password spray patterns |
| **Beachhead Establishment** | Attacker gaining initial foothold quietly | Low-volume C2 beacons, unusual outbound connections |
| **Lateral Expansion** | Moving through network after initial access | Internal scan traffic, unusual inter-server comms |
| **Data Staging** | Preparing exfiltration before transfer | Unusual archive creation, temp directory activity |
| **Persistence Installation** | Ensuring attacker can return | New scheduled tasks, registry modifications, backdoors |
| **Living Off the Land** | Using legitimate tools to attack | PowerShell abuse, WMI attacks, LOLBins |
| **Physical Reconnaissance** | Scoping a facility before physical breach | Repeated badge failures in specific zones |

### Prediction Challenge Example

**Scenario: The Patient Attacker**

```
You are observing the following event sequence over 72 hours:

Day 1, 09:14  — Port scan detected from external IP 203.x.x.x (1,024 ports)
Day 1, 14:33  — DNS lookup for internal mail server from same IP range
Day 2, 02:11  — Single failed SSH login to web server (admin account)
Day 2, 02:12  — Single failed SSH login to web server (root account)
Day 3, 03:45  — Outbound DNS query to domain registered 3 days ago
Day 3, 03:47  — 4.2 KB outbound transfer to same domain

PREDICTION REQUIRED:
1. What attack stage is this? (select one)
   [ ] Opportunistic scanning
   [ ] Targeted reconnaissance with C2 establishment
   [ ] Insider data staging
   [ ] Automated botnet activity

2. What is the most likely next step in the next 48 hours?

3. What single action would most effectively disrupt this attack right now?
```

**Correct Answer Analysis:**

- Stage: Targeted reconnaissance with C2 establishment (Day 3 events confirm C2 beacon)
- Next step: Credential brute force or phishing campaign to gain initial access
- Best action: Block the C2 domain immediately, alert on any further connection attempts from that IP range, initiate threat intelligence lookup on the domain and IP

### AI vs Human Prediction Tracking

The sandbox tracks prediction accuracy over time for both individuals and the AI model, enabling continuous improvement.

```json
{
  "trainee_id": "uuid",
  "prediction_history": [
    {
      "scenario_id": "pred_047",
      "trainee_prediction": "lateral_movement",
      "ai_prediction": "credential_harvest",
      "actual_outcome": "credential_harvest",
      "trainee_correct": false,
      "ai_correct": true,
      "debrief_note": "Early DNS patterns indicated targeting, not post-access movement"
    }
  ],
  "accuracy_rate": 0.71,
  "ai_accuracy_rate": 0.89,
  "gap_analysis": "Trainee underweights DNS anomalies as early indicators"
}
```

---

## 9. Skill Progression & Role Tracks

### Student Track

```
LEVEL 1 — SENTINEL (Beginner)
  Complete: Labs A-1, A-2, A-3
  Complete: 5 CTF challenges (any category)
  Pass score: 60%+
        ↓
LEVEL 2 — ANALYST (Intermediate)
  Complete: Labs A-4 through B-3
  Complete: 10 CTF challenges including 2 forensics
  Pass score: 70%+
        ↓
LEVEL 3 — OPERATOR (Advanced)
  Complete: All Category C (Forensics) labs
  Complete: 5 Prediction Sandbox challenges
  Pass score: 75%+
        ↓
LEVEL 4 — HUNTER (Expert)
  Complete: Full Red Team vs Blue Team drill (Blue Team role)
  Pass AI Prediction: 70%+ accuracy across 10 scenarios
  Pass score: 80%+
        ↓
CERTIFICATION READY
  Platform-issued training certificate
  Recommended for: Security+, CySA+, CEH preparation
```

### Corporate Personnel Track

```
SOC ANALYST TRACK
  Mandatory: Labs A-1 through A-8 (Detection Labs)
  Mandatory: Labs B-1 through B-6 (Response Labs)
  Quarterly: Red Team vs Blue Team Drill (Blue Team)
  Annual: Full APT scenario drill

INCIDENT RESPONDER TRACK
  Mandatory: All Category C (Forensics Labs)
  Mandatory: Labs B-1, B-4, B-6
  Quarterly: Purple Team drill participation
  Annual: Zero-Day simulation

THREAT HUNTER TRACK
  Mandatory: AI Prediction Sandbox — 20 scenarios minimum
  Mandatory: CTF challenges — Threat Attribution category
  Quarterly: Red Team vs Blue Team drill (Purple Team facilitation)

RED TEAM OPERATOR TRACK
  Mandatory: All lab categories (attacker perspective)
  Mandatory: Red Team role in 4+ drills
  Qualification: Pass Red Team scoring 750+/1000 on Advanced scenario
```

---

## 10. Scoring, Debrief & Performance Metrics

### Session Debrief Report

Every completed training session generates a debrief report automatically.

```json
{
  "session_id": "uuid",
  "trainee_id": "uuid",
  "scenario": "Lab A-5: Physical Intruder + Server Login",
  "duration_minutes": 38,
  "final_score": 82,
  "passing_threshold": 75,
  "result": "PASS",

  "timeline_comparison": {
    "attack_started_at": "00:00",
    "trainee_first_detected_at": "00:12",
    "optimal_detection_at": "00:04",
    "detection_gap_minutes": 8
  },

  "alerts_issued": 6,
  "correct_alerts": 5,
  "false_positives": 1,
  "missed_alerts": 1,

  "response_actions": [
    { "action": "block_ip",        "correct": true,  "timing": "good" },
    { "action": "lock_sector_door","correct": true,  "timing": "good" },
    { "action": "isolate_server",  "correct": true,  "timing": "late" },
    { "action": "disable_account", "correct": false, "timing": "n/a", "note": "User account was not compromised in this scenario" }
  ],

  "what_ai_would_have_done": [
    "Correlated physical and cyber events at 00:04 based on location proximity",
    "Issued high-threat classification at 00:06",
    "Locked sector doors and alerted SOC at 00:07",
    "Initiated server isolation at 00:08"
  ],

  "improvement_areas": [
    "Physical-cyber correlation speed — practice cross-domain event linking",
    "Reduce false positive rate — review door access denied threshold settings"
  ],

  "recommended_next_lab": "Lab B-5: DDoS Attack on Web Services"
}
```

### Organizational Training Dashboard

Administrators see aggregate metrics across all trainees.

| Metric | Description |
|---|---|
| **Average Detection Time** | How fast is the team identifying threats on average |
| **False Positive Rate** | Are personnel triggering unnecessary responses |
| **Scenario Pass Rate** | Percentage of sessions passed at each difficulty level |
| **Coverage Gaps** | Which attack categories have the lowest scores |
| **AI vs Human Prediction Gap** | Where humans consistently diverge from the AI model |
| **Drill Readiness Score** | Composite score indicating team's operational readiness |

---

## 11. Synthetic Attack Generator

The attack generator is the engine that feeds all four training environments. It produces realistic event streams that flow through the real detection pipeline.

### Generator Architecture

```python
class SyntheticAttackGenerator:

    def __init__(self, scenario: dict, sandbox_network: SandboxNetwork):
        self.scenario = scenario
        self.network = sandbox_network
        self.event_queue = []

    def load_scenario(self, scenario_id: str):
        """Load a predefined attack scenario from the scenario catalog."""
        self.scenario = ScenarioCatalog.get(scenario_id)

    def generate_event_stream(self) -> list:
        """
        Generate a time-sequenced stream of synthetic security events
        matching the scenario's attack sequence.
        """
        events = []
        for step in self.scenario["attack_sequence"]:
            event = self._build_event(step)
            events.append(event)
        return events

    def _build_event(self, step: dict) -> dict:
        """Build a normalized synthetic event from an attack step definition."""
        return {
            "event_id": str(uuid4()),
            "event_type": step["event"],
            "device_id": self.network.get_device_for_step(step),
            "severity": step["severity"],
            "timestamp": self._calculate_timestamp(step["time_offset_seconds"]),
            "synthetic": True,
            "scenario_id": self.scenario["id"]
        }

    def inject_noise(self, noise_level: float = 0.2):
        """
        Inject realistic background noise events (normal activity)
        to prevent trainees from identifying attacks by absence of normal traffic.
        noise_level: 0.0 = no noise, 1.0 = production-level noise
        """
        pass
```

### Noise Injection

A critical realism feature. Real environments are noisy. Trainees must learn to detect threats against a background of normal activity — not in an artificially quiet lab.

```python
# Noise levels by difficulty
NOISE_LEVELS = {
    "beginner":     0.1,   # 10% normal background traffic
    "intermediate": 0.4,   # 40% normal background traffic
    "advanced":     0.7,   # 70% normal background traffic
    "expert":       1.0    # Full production-level background noise
}
```

---

## 12. Safety & Isolation Guarantees

Training Mode is engineered to be **impossible to accidentally affect production systems**.

### Isolation Layers

| Layer | Mechanism |
|---|---|
| **Network isolation** | Training containers run on a completely separate VLAN with no routing to production |
| **Data isolation** | Training database is a separate instance with no replication from or to production |
| **Tool sandboxing** | All offensive tools (Nmap, Metasploit, etc.) are restricted to the sandbox network at the firewall level |
| **Response action interception** | All automated response commands in training mode are intercepted before execution and logged as simulated only |
| **Credential isolation** | Training environment uses entirely separate credentials — no shared accounts with production |
| **Audit logging** | All training session activity is logged separately from production audit logs |

### Verification Check

Administrators can verify isolation status at any time:

```bash
GET /admin/training/isolation-status

Response:
{
  "production_network_accessible": false,
  "production_database_accessible": false,
  "real_response_actions_enabled": false,
  "sandbox_network_status": "healthy",
  "isolation_verified_at": "2026-03-06T08:00:00Z"
}
```

---

## 13. Training Mode API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/training/sessions/start` | Start a new training session |
| `GET` | `/training/sessions/{id}` | Get session status and live score |
| `POST` | `/training/sessions/{id}/end` | End session and trigger debrief |
| `GET` | `/training/sessions/{id}/debrief` | Get full debrief report |
| `GET` | `/training/scenarios` | List all available scenarios |
| `GET` | `/training/scenarios/{id}` | Get scenario details |
| `POST` | `/training/ctf/submit` | Submit a CTF challenge answer |
| `GET` | `/training/ctf/leaderboard` | Get current leaderboard |
| `POST` | `/training/drills/start` | Start a Red vs Blue drill |
| `GET` | `/training/drills/{id}/status` | Get live drill status |
| `POST` | `/training/prediction/submit` | Submit a threat prediction |
| `GET` | `/training/progress/{trainee_id}` | Get trainee progress and level |
| `GET` | `/training/org/{org_id}/dashboard` | Get organizational training metrics |

---

## 14. Implementation Guide for Administrators

### Enabling Training Mode

```bash
# 1. Start training sandbox services

# 2. Verify isolation
curl -X GET /admin/training/isolation-status

# 3. Load scenario catalog
python manage.py load_scenarios --catalog scenarios/catalog.json

# 4. Create trainee accounts
python manage.py create_trainees --file trainees.csv --track student

# 5. Enable training mode for organization
curl -X POST /admin/training/enable \
  -d '{"org_id": "your_org_id", "mode": "training"}'
```

### Scenario Management

Administrators can load, customize, and create scenarios:

```bash
# List available scenarios
GET /admin/training/scenarios

# Load a custom scenario
POST /admin/training/scenarios
Content-Type: application/json

{
  "name": "Custom Insider Threat",
  "difficulty": "advanced",
  "duration_minutes": 90,
  "attack_sequence": [ ... ],
  "learning_objectives": [ ... ],
  "passing_score": 80
}
```

### Scheduling Drills

```bash
# Schedule a Red vs Blue drill for a team
POST /admin/training/drills/schedule
{
  "scenario_id": "Drill-03",
  "scheduled_at": "2026-04-15T09:00:00Z",
  "red_team_members": ["uuid1", "uuid2"],
  "blue_team_members": ["uuid3", "uuid4", "uuid5"],
  "facilitator_id": "uuid6"
}
```

---

## 15. Scenario Catalog

### Quick Reference

| ID | Name | Type | Difficulty | Duration |
|---|---|---|---|---|
| A-1 | Port Scan Reconnaissance | Detection Lab | Beginner | 20 min |
| A-2 | Brute Force Login Attack | Detection Lab | Beginner | 25 min |
| A-3 | Lateral Movement | Detection Lab | Intermediate | 35 min |
| A-4 | Data Exfiltration | Detection Lab | Intermediate | 40 min |
| A-5 | Physical + Cyber Correlation | Detection Lab | Intermediate | 45 min |
| A-6 | Ransomware Early Stage | Detection Lab | Advanced | 50 min |
| A-7 | Insider Threat | Detection Lab | Advanced | 60 min |
| A-8 | Malware C2 Beacon | Detection Lab | Advanced | 45 min |
| B-1 | Active Network Intrusion | Response Lab | Intermediate | 40 min |
| B-2 | Compromised Account | Response Lab | Beginner | 30 min |
| B-3 | Physical Breach Response | Response Lab | Intermediate | 45 min |
| B-4 | Ransomware Spread | Response Lab | Advanced | 60 min |
| B-5 | DDoS Attack | Response Lab | Intermediate | 35 min |
| B-6 | Malware on Endpoint | Response Lab | Advanced | 50 min |
| C-1 | Timeline Reconstruction | Forensics Lab | Intermediate | 60 min |
| C-2 | Malware Reverse Engineering | Forensics Lab | Advanced | 90 min |
| C-3 | Insider Threat Investigation | Forensics Lab | Advanced | 75 min |
| C-4 | Memory Forensics | Forensics Lab | Expert | 90 min |
| C-5 | Network Forensics | Forensics Lab | Advanced | 60 min |
| Drill-01 | The Opportunist | Red vs Blue | Basic | 1 hr |
| Drill-02 | The Insider | Red vs Blue | Intermediate | 2 hr |
| Drill-03 | The APT Campaign | Red vs Blue | Advanced | 4 hr |
| Drill-04 | Physical + Cyber Combined | Red vs Blue | Advanced | 3 hr |
| Drill-05 | Zero-Day Simulation | Red vs Blue | Expert | 4+ hr |
| Drill-06 | Supply Chain Attack | Red vs Blue | Expert | 4+ hr |
| Drill-07 | Ransomware Outbreak | Red vs Blue | Intermediate | 2 hr |
| Drill-08 | Tabletop — Board Level | Strategic | Strategic | 2 hr |
| PRED-01 | The Patient Attacker | Prediction | Intermediate | 20 min |
| PRED-02 | The Opportunistic Scanner | Prediction | Beginner | 15 min |
| PRED-03 | The Insider Setup | Prediction | Advanced | 25 min |
| PRED-04 | The Supply Chain Probe | Prediction | Expert | 30 min |

---

*The difference between a security professional and a cybersecurity warrior is practice under pressure. Training Mode is where that transformation happens.*