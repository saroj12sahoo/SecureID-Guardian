# SecureID Guardian 🛡️
### Enterprise Zero-Trust Identity Defense, UEBA & Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Zero Trust](https://img.shields.io/badge/Architecture-Zero--Trust-6366f1.svg)](#architecture-principles)
[![RFC 6238](https://img.shields.io/badge/MFA-RFC--6238%20TOTP-10b981.svg)](#mfa-lab)
[![MITRE ATT&CK](https://img.shields.io/badge/Threat%20Defense-MITRE%20ATT%26CK-ef4444.svg)](#threat-defense)

**SecureID Guardian** is an enterprise-grade cybersecurity command center and Zero-Trust Identity Threat Detection & Response (ITDR) platform. It provides real-time User & Entity Behavior Analytics (UEBA), cryptographic multi-factor authentication (MFA), password entropy audits, dark web breach intelligence, dynamic access control policies, and automated incident containment mapped to the MITRE ATT&CK framework.

---

## 🌟 Key Capabilities

### 1. 📊 SOC Command Overview
- **Real-Time Security Posture Score:** Dynamic calculation based on enterprise-wide weighted identity risk evaluations.
- **Threat Level Monitoring:** Automated elevation between `NORMAL` and `ELEVATED` based on active security incidents.
- **Key Metrics Dashboard:** Real-time counters for high-risk accounts, quarantined identities, active policies, and recent telemetry events.

### 2. 👥 Identity Directory & SOC Containment
- **Granular Privilege Tiers:** Multi-level privilege classification (`Standard`, `Elevated`, `SuperAdmin`).
- **Real-Time Identity Status:** Tracks `ACTIVE`, `QUARANTINED`, `STEP_UP_REQUIRED`, and `SUSPENDED` states.
- **Instant Containment (One-Click Quarantine):** Rapidly revoke all active sessions and isolate compromised credentials (`MITRE T1531 - Account Access Removal`).
- **Step-Up Authentication Trigger:** Force immediate multi-factor challenge on suspicious behavior.

### 3. 🌐 UEBA & Impossible Travel Anomaly Detection
- **Haversine Geolocation Engine:** Calculates great-circle physical distance between successive login coordinates.
- **Velocity Threshold Analysis:** Flags logins with calculated travel velocities exceeding commercial aviation thresholds (> 950 km/h).
- **Interactive Cyber Attack Simulator:** Test live response mechanisms against:
  - ✈️ *Impossible Travel Anomaly* (e.g., London to Tokyo in 15 minutes)
  - 🧅 *TOR / Bulletproof Proxy Exit Node Login*
  - 💥 *Credential Stuffing & Brute Force Bursts*
  - 🔓 *Privilege Escalation & Abnormal Hours Access*

### 4. 🔐 Breach Fortress & Password Auditor
- **NIST / Shannon Entropy Engine:** Calculates password randomness, character pool coverage, and bit entropy.
- **Brute Force Crack Time Estimation:** Real-time cracking difficulty estimation from instantaneous offline attacks to centuries.
- **Common Breach Dictionary Check:** Instant detection against known leaked credential hashes.
- **Simulated Dark Web Domain Scanner:** Inspect enterprise domains and email accounts for compromised database leaks.

### 5. ⏱️ RFC-6238 TOTP Multi-Factor Authentication Lab
- **Pure-Python Cryptographic Generator:** Implements RFC 4226 (HOTP) and RFC 6238 (TOTP) without external crypto dependencies.
- **Live 30-Second Countdown:** Visual synchronous countdown with dynamic time remaining.
- **Standard `otpauth://` URI Generation:** Full compatibility with Google Authenticator, Microsoft Authenticator, and 1Password.
- **Zero-Trust OTP Verification:** Validates one-time passwords with drift tolerance against the active secret.

### 6. 📜 Zero-Trust Policy Engine
- **Dynamic Policy Enforcement:** Toggle and modify active security rules on the fly:
  - *Geo-Fencing & Impossible Travel Velocity Rules*
  - *Privileged SuperAdmin MFA Enforcement*
  - *Dark Web Compromised Credential Revocation*
  - *Automated Dormant Account Lockout*
- **Audit Logging:** Every access evaluation decision (`GRANTED`, `CHALLENGED`, `BLOCKED`) is logged with full risk factor breakdowns.

### 7. 🚨 Threat Defense & Incident Response
- **MITRE ATT&CK Mapping:** Incidents tagged with specific techniques (e.g., `T1078 Valid Accounts`, `T1531 Account Access Removal`, `T1110 Brute Force`).
- **SOC Forensics & Containment Playbooks:** Context-rich incident cards with recommended remediation steps and forensic details.
- **Incident Resolution Flow:** Allows SOC operators to remediate incidents once mitigation steps are completed.

---

## 🏛️ System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser (UI)                       │
│  Glassmorphism SOC Dashboard • Modern CSS Design System     │
│  Interactive Maps & Telemetry • RFC 6238 MFA Authenticator  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON REST APIs
┌──────────────────────────────▼──────────────────────────────┐
│                  FastAPI Application (main.py)              │
│  - Static Asset Serving (/static, /)                        │
│  - Interactive Swagger API Documentation (/docs)            │
│  - High-Performance Async Route Handlers                    │
└──────┬───────────────────────┬───────────────────────┬──────┘
       │                       │                       │
┌──────▼────────────┐  ┌───────▼─────────────┐  ┌──────▼────────────┐
│   Policy Engine   │  │  Identity Risk &    │  │ Crypto Security   │
│ (policy_engine.py)│  │     UEBA Engine     │  │(crypto_security.py│
│ - Security State  │  │  (risk_engine.py)   │  │ - RFC 6238 TOTP   │
│ - Policy Toggles  │  │ - Haversine Distance│  │ - Password Entropy│
│ - Incidents State │  │ - Velocity Check    │  │ - Breach Scanner  │
│ - Containment     │  │ - Risk Level Matrix │  │ - HMAC-SHA1 Core  │
└───────────────────┘  └─────────────────────┘  └───────────────────┘
```

---

## 📂 Project Directory Structure

```text
SecureID-Guardian/
├── backend/
│   ├── crypto_security.py   # RFC 6238 TOTP engine, password entropy auditor, breach search
│   ├── models.py            # Pydantic v2 data models, Enums, and API contracts
│   ├── policy_engine.py     # In-memory security state manager, quarantine, policy toggling
│   ├── risk_engine.py       # UEBA engine, Haversine distance, and velocity travel calculations
│   └── sample_data.py       # Seed data for identities, baseline logs, policies & breaches
├── frontend/
│   ├── app.js               # Frontend controller, view router, simulation handlers, MFA timer
│   ├── index.html           # Semantic HTML5 dashboard layout with full SVG iconography
│   └── styles.css           # Custom dark cyber-themed design system with glassmorphism
├── tests/
│   └── test_backend.py      # Comprehensive unit tests for TOTP, Risk, Entropy, and State
├── main.py                  # FastAPI application entry point, CORS config, and static routing
└── README.md                # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- `pip` (Python package manager)

### 1. Installation

Clone or download the repository to your machine:
```bash
git clone https://github.com/your-username/secureid-guardian.git
cd secureid-guardian
```

Install the required Python dependencies:
```bash
pip install -r requirements.txt
```
*(Or install manually: `pip install fastapi uvicorn pydantic`)*

*(Optional: Install testing tools if desired)*:
```bash
pip install pytest httpx
```

### 2. Running the Application

Start the server using Python:
```bash
python main.py
```

Or run via Uvicorn directly:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The application will start on:
- 🌐 **Web Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- 📑 **Interactive Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- 📖 **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🧪 Running Unit Tests

The project includes unit tests validating cryptographic computations, UEBA risk scoring, Haversine travel calculations, and security state transitions:

```bash
python tests/test_backend.py
```

### What is tested:
- ✅ **RFC 6238 TOTP:** Verification, dynamic truncation, 30-second window, and invalid token rejection.
- ✅ **Password Entropy Auditor:** Weak password dictionary matches, Shannon entropy bit estimation, and brute force thresholds.
- ✅ **Risk & UEBA Engine:** Great-circle Haversine distance calculation and impossible velocity detection (> 20,000 km/h tests).
- ✅ **Security State Management:** Identity quarantine (MITRE T1531), identity restoration, and event simulation.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dashboard/stats` | Retrieve aggregate SOC posture score and key telemetry metrics |
| `GET` | `/api/identities` | List all tracked identities with optional department/risk filtering |
| `GET` | `/api/identities/{id}` | Retrieve profile, risk score, and privilege tier for an identity |
| `POST` | `/api/identities/{id}/quarantine` | Immediately quarantine an identity and revoke all active sessions |
| `POST` | `/api/identities/{id}/unquarantine` | Restore a quarantined identity back to active status |
| `POST` | `/api/identities/{id}/step-up` | Force step-up MFA challenge on the specified identity |
| `GET` | `/api/access-logs` | Retrieve recent UEBA access telemetry logs |
| `POST` | `/api/access-logs/simulate` | Simulate an attack scenario (e.g., `impossible_travel`, `tor_exit_node`) |
| `POST` | `/api/audit/password` | Audit password entropy, complexity, crack time, and breach presence |
| `POST` | `/api/audit/domain-breach` | Query domain or email address against known dark web breach database |
| `GET` | `/api/mfa/generate` | Generate fresh RFC 6238 TOTP secret, initial token, and `otpauth://` URI |
| `POST` | `/api/mfa/verify` | Cryptographically verify a 6-digit TOTP code against a secret |
| `GET` | `/api/policies` | Retrieve all enterprise Zero-Trust security policies |
| `POST` | `/api/policies/{id}/toggle` | Enable or disable a security policy in real-time |
| `GET` | `/api/incidents` | List active and historical security incidents |
| `POST` | `/api/incidents/{id}/resolve` | Mark an incident as resolved by SOC analysts |

---

## 🔒 Security & Architecture Principles

1. **Verify Explicitly:** Always authenticate and authorize based on all available data points (identity, location, device health, service or workload, data classification, and anomalies).
2. **Use Least-Privilege Access:** Limit user access with Just-In-Time and Just-Enough-Access (JIT/JEA), risk-based adaptive policies, and data protection.
3. **Assume Breach:** Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to gain visibility, drive threat detection, and continuously improve defenses.

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
