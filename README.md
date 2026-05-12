ThreatLens 🛡️

Real-Time Secure Code Analysis & Threat Intelligence Platform

ThreatLens is a full-stack cybersecurity platform that combines static code analysis, IOC extraction, asynchronous threat intelligence enrichment, and real-time IDE diagnostics into a modern desktop security dashboard.

Built with Electron, React, FastAPI, and Go, ThreatLens delivers a developer-first DevSecOps experience inspired by professional SOC tooling and modern secure coding workflows.

✨ Features
🔍 Real-Time Vulnerability Detection

ThreatLens continuously scans code as users type and detects:

Hardcoded AWS Keys
Hardcoded Passwords
SQL Injection Patterns
Shell Injection Vulnerabilities
Dangerous Functions (eval, exec, subprocess)
Risky Network Binds (0.0.0.0)
🧠 Native Monaco Editor Diagnostics
Embedded Monaco Editor
VS Code-style:
Error Squiggles
Warning Markers
Scrollbar Indicators
Debounced backend analysis for optimized performance
🌐 IOC Extraction Engine

Automatically extracts:

IPv4 Addresses
URLs & Domains
MD5 Hashes
SHA256 Hashes

Additional capabilities:

Local/private subnet filtering
IOC de-duplication using Python set()
⚡ Threat Intelligence Enrichment

Extracted IOCs are enriched through a high-performance Go microservice.

Includes:
Concurrent IOC processing with Goroutines
Threat scoring system
Vendor verdict simulation
Dynamic severity escalation
24-hour SQLite caching layer
🎨 Premium Security Dashboard
Animated Threat Score Bars
Dynamic Verdict Cards
Real-Time UI Updates
Loading States & Spinners
Scan History Tracking
🔐 Authentication & IAM
SQLite-backed authentication
RBAC support
FastAPI lifespan DB initialization
Secure login API
🏗️ Architecture
┌──────────────────────┐
│  Electron + React    │
│  Monaco Editor UI    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   FastAPI Backend    │
│ Regex Analysis Engine│
│    IOC Extraction    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Go Microservice    │
│ Threat Intelligence  │
│ Concurrent Enrichment│
│    SQLite Cache      │
└──────────────────────┘
🛠️ Tech Stack
Frontend
Electron
React
Monaco Editor
Lodash
CSS Animations
Backend
Python FastAPI
SQLite
HTTPX
Threat Intel Microservice
Golang
Goroutines
WaitGroups
Mutex Locks
SQLite (modernc.org/sqlite)
🚀 Installation
1️⃣ Clone the Repository
git clone https://github.com/yourusername/threatlens.git
cd threatlens
2️⃣ Frontend Setup
cd frontend
npm install
npm run dev
3️⃣ Backend Setup (FastAPI)
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
4️⃣ Go Microservice Setup
cd go-service
go mod tidy
go run main.go
▶️ Running ThreatLens

Start services in the following order:

FastAPI Backend
Go Threat Intel Microservice
Electron Frontend

The application will automatically begin real-time scanning.

🧪 Demo Scenarios
demo1_secrets.py

Triggers:

AWS Key Detection
SQL Injection Detection
demo2_malicious_domain.py

Triggers:

URL Extraction
Threat Intelligence Enrichment
demo3_c2_ip_hash.py

Triggers:

IP & Hash Extraction
Dynamic Severity Escalation
🔎 Detection Examples
Hardcoded AWS Keys
(AKIA[0-9A-Z]{16})
Hardcoded Passwords
(?i)password\s*=\s*[\"']([^\"']+)[\"']
SQL Injection
(?i)(SELECT\s+.*?\s+FROM\s+.*?|UNION\s+ALL\s+SELECT|INSERT\s+INTO\s+.*?\s+VALUES)
Dangerous Function Usage
(\beval\s*\()
⚙️ Key Engineering Highlights
Reactive frontend state management
Real-time Monaco diagnostics API integration
Concurrent IOC enrichment architecture
Intelligent SQLite caching
Async FastAPI ↔ Go communication
Deterministic mock threat engine for demos
Dynamic severity upgrades based on enrichment verdicts
📌 Future Enhancements
VirusTotal API Integration
YARA Rule Support
MITRE ATT&CK Mapping
AI-Assisted Threat Analysis
Docker Deployment
SIEM Integrations
WebSocket Live Updates
File Upload Scanning
🎯 Project Goals

ThreatLens was designed to demonstrate:

Real-time secure coding workflows
Threat intelligence integration
Concurrent microservice design
Native IDE security diagnostics
Modern DevSecOps principles
📄 License

MIT License

## ⚠️ Disclaimer

ThreatLens is currently developed for **educational, research, and demonstration purposes** including:

* Learning
* Research
* Hackathons
* Security Prototyping

The platform is actively evolving and is planned to mature into a more production-ready cybersecurity solution with expanded threat intelligence integrations, improved scalability, enhanced detection capabilities, and enterprise-grade security features in future iterations.
