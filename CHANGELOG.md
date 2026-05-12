# ThreatLens Comprehensive Changelog (100% Completion Milestone)

This document serves as the complete technical changelog and architectural breakdown of all features implemented in the ThreatLens project, from inception to the final Phase 4 completion mark.

---

## 1. Frontend Architecture (Electron + React)
The frontend was completely overhauled from a basic scaffold into a deeply reactive, premium dashboard utilizing advanced React state management and native VS Code APIs.

### Core Editor & Event Handling
- **Embedded Monaco Editor**: Integrated `@monaco-editor/react` configured with a custom `vs-dark` theme, a font size of 14, and disabled minimap for a cleaner UI.
- **Debounced Execution**: Implemented `lodash.debounce` on the `analyzeCode` function (800ms delay). This prevents the UI from spamming the backend API on every single keystroke, significantly improving editor performance.
- **Native VS Code Diagnostics**: Replaced CSS-based visual hacks with the native `monaco.editor.setModelMarkers` API. The app now communicates directly with the Monaco engine to inject native error squiggles (red/yellow) and scrollbar ticks based on backend findings.

### Asynchronous Threat Intelligence (Phase 3 & 4 additions)
- **Advanced State Management**: Added deep state tracking for `findings` (base vulnerabilities), `iocs` (extracted indicators), and `enrichments` (asynchronous threat intel data).
- **Reactive Polling**: Implemented a `useEffect` hook that actively watches the `iocs` array. When a new IP, URL, or Hash is detected, it automatically fires off a `POST /enrich` request to the backend proxy.
- **Dynamic Severity Upgrades**: If the Go microservice flags a previously "Medium" severity artifact as `malicious`, the React component re-renders the Monaco markers and instantly upgrades the visual squiggle from a Warning (Yellow) to a Critical Error (Red).

### Premium UI/UX Design System
- **Dynamic Verdict Cards**: Threat Cards were upgraded into dynamic components. When querying intel, they display a custom CSS loading spinner (`.spinner`). Once data arrives, they expand to display:
  - A responsive **0-100 Threat Score Progress Bar** with animated CSS width transitions.
  - Color-coded vendor verdicts (`.verdict-malicious` vs `.verdict-benign`).
  - Specific threat context strings.
- **Scan History Strip**: Built a horizontal, overflow-scrolling flex container (`.history-strip`) at the top of the side panel that maintains a unique `Set` of the last 5 scanned artifacts for better context.
- **Demo Controls**: Added a "Clear" button that triggers `handleClear()`, which aggressively resets all React state hooks and flushes the Monaco editor markers, preparing the app for the next demo pitch.

---

## 2. Backend Architecture (Python FastAPI)
The Python backend serves as the core real-time analysis engine and the authentication gateway.

### The Regex Vulnerability Engine
The `/analyze` endpoint splits incoming code line-by-line and evaluates it against a comprehensive dictionary of regex patterns:
- **Hardcoded AWS Keys**: `r"(AKIA[0-9A-Z]{16})"` -> Flags as `critical`.
- **Hardcoded Passwords**: `r"(?i)password\s*=\s*[\"']([^\"']+)[\"']"` -> Flags as `critical`.
- **SQL Injections**: `r"(?i)(SELECT\s+.*?\s+FROM\s+.*?|UNION\s+ALL\s+SELECT|INSERT\s+INTO\s+.*?\s+VALUES)"` -> Flags as `critical`.
- **Dangerous Functions**: `r"(\beval\s*\()"` -> Flags as `critical`.
- **Shell Injections**: `r"(\b(?:os\.system|subprocess\.Popen|exec)\s*\()"` -> Flags as `critical`.
- **Risky Binds**: `r"(\b0\.0\.0\.0\b)"` -> Flags as `low`.

### Indicator of Compromise (IOC) Extractor
As code is scanned, the engine simultaneously runs a secondary extraction pass:
- **IPv4 Filtering**: `r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"` (Explicitly ignores local subnets like `127.x`, `192.168.x`, and `10.x` to reduce noise).
- **URLs and Domains**: Extracts embedded `http`/`https` strings.
- **Hashes**: Extracts standard 32-char (MD5) and 64-char (SHA256) strings.
- **De-duplication**: Uses a Python `set()` to ensure identical IOCs are only forwarded to the Go microservice once per scan.

### Identity & Access Management (IAM)
- **Lifespan Initialization**: Utilizes FastAPI's `lifespan` context manager to automatically generate a local `threatlens.db` SQLite database on startup.
- **Authentication**: `POST /login` validates credentials against the SQLite table and returns user profile objects containing Role-Based Access Control (RBAC) definitions.

---

## 3. Threat Intelligence Microservice (Go)
To ensure maximum performance during threat lookups, a standalone Go microservice was built on port `8081`.

### Concurrent Processing
- The service uses a `sync.WaitGroup` and a `sync.Mutex` lock to spawn separate Goroutines for every single IOC submitted in the payload. This allows the system to theoretically query 50 IPs simultaneously without blocking the HTTP response.

### Intelligent Caching Layer
- **No-CGO SQLite**: Integrated the `modernc.org/sqlite` package, allowing native SQLite database caching without requiring complex C/GCC compiler toolchains on Windows.
- **24-Hour Cache Rule**: Before executing a lookup, the service queries the `enrichment_cache.db`. If a matching artifact is found and the timestamp is less than 24 hours old, it instantly returns the cached JSON, bypassing the mocked network delay.

### Deterministic Mock Fallback
- To guarantee a 100% successful hackathon presentation, the service implements a highly realistic mock engine.
- It injects a random `time.Sleep` of 1-3 seconds to simulate real-world API latency.
- It returns deterministic, hardcoded threat intelligence for specific demo payloads (e.g., scoring `45.33.32.156` as an 88/100 SSH Brute Force IP), while returning randomized low scores for arbitrary IP addresses to demonstrate dynamic behavior.
- FastAPI connects to this service via a newly added `POST /enrich` endpoint utilizing the asynchronous `httpx` HTTP client.

---

## 4. Final Demo Materials
To round out the project, three standalone Python scripts were generated for the pitch:
1. `demo1_secrets.py`: Designed to trigger the Python Regex engine (AWS Keys & SQLi).
2. `demo2_malicious_domain.py`: Designed to trigger the Go Threat Intel engine via URL extraction.
3. `demo3_c2_ip_hash.py`: Designed to trigger the Go Threat Intel engine via IP and Hash extraction, showcasing the dynamic severity upgrade feature.
