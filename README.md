

# 🛡️ ThreatLens

**ThreatLens** is an advanced, real-time code security and threat intelligence platform. It combines a high-performance **Electron/React** frontend with a dual-engine backend—**Python FastAPI** for static analysis and a **Go microservice** for concurrent threat enrichment.

Designed for security researchers and developers, ThreatLens doesn't just find vulnerabilities; it correlates code patterns with live global threat indicators (IOCs).

---

## 🚀 Features

### 💻 Premium Frontend Editor

* **Monaco Integration**: A full-featured VS Code-like experience powered by `@monaco-editor/react`.
* **Native Diagnostics**: Real-time "Error Squiggles" and scrollbar markers using the native Monaco `setModelMarkers` API.
* **Reactive Enrichment**: Automatically extracts and enriches IPs, Hashes, and URLs as you type using a debounced 800ms execution loop.
* **Visual Severity Upgrades**: Watch vulnerabilities escalate from "Warning" to "Critical" in real-time as the threat intel microservice flags malicious artifacts.

### 🐍 Python Analysis Engine

* **Regex Vulnerability Shield**: Deep-scanning for AWS keys, SQL injection patterns, shell escapes (`os.system`, `eval`), and risky network binds.
* **Automated IOC Extraction**: Smart filtering of IPv4 addresses (ignoring local subnets), MD5/SHA256 hashes, and URIs.
* **FastAPI Backbone**: Asynchronous endpoint handling with built-in SQLite-based Identity & Access Management (IAM).

### 🐹 Go Threat Intel Microservice

* **High Concurrency**: Leverages `sync.WaitGroup` and Goroutines to process dozens of IOC lookups in parallel without blocking.
* **Intelligent Caching**: A `modernc.org/sqlite` (No-CGO) caching layer that persists enrichment data for 24 hours to optimize performance.
* **Deterministic Mocking**: A sophisticated simulation engine that provides realistic API latency and specific demo-ready verdicts.

---

## 🏗️ Architectural Breakdown

ThreatLens utilizes a distributed architecture to ensure UI responsiveness while performing heavy analysis.

### Tech Stack

| Component | Technology |
| --- | --- |
| **Frontend** | Electron, React, Monaco Editor, CSS3 Animations |
| **Primary API** | Python 3.10+, FastAPI, Pydantic, HTTPX |
| **Microservice** | Go 1.21+, Goroutines, SQLite (CGO-free) |
| **Database** | SQLite (User Auth & Enrichment Cache) |

---

## 🛠️ Installation & Setup

### 1. Go Microservice (Port 8081)

```bash
cd services/intel-go
go run main.go

```

### 2. Python Backend (Port 8000)

```bash
cd services/analysis-py
pip install -r requirements.txt
uvicorn main:app --reload

```

### 3. Electron Frontend

```bash
cd frontend
npm install
npm start

```

---

## 🧪 Demo Scenarios

The project includes pre-configured scripts to demonstrate full-spectrum detection:

1. **`demo1_secrets.py`**: Triggers critical flags for hardcoded AWS credentials and SQLi.
2. **`demo2_malicious_domain.py`**: Demonstrates URL extraction and Go-based domain reputation lookups.
3. **`demo3_c2_ip_hash.py`**: Showcases the **Dynamic Severity Upgrade**—an IP is detected, enriched as "Malicious," and the UI automatically upgrades the alert level.

---

## 📈 Roadmap (Phase 4 Milestone Reached)

* [x] Phase 1: Core Electron/Monaco Integration
* [x] Phase 2: Python Regex Analysis Engine
* [x] Phase 3: Go Microservice & Concurrent Processing
* [x] Phase 4: Reactive UI & Visual Enrichment Upgrades
* [ ] *Would be implemented in future: LLM-based Remediation Suggestions*


