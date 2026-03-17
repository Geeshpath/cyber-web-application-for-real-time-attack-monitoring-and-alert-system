# AegisX — Real-Time Cyber Attack Monitoring Backend

Full-stack Python/Flask backend for the AegisX cybersecurity dashboard.

## Architecture

```
aegisx-backend/
├── app.py               ← Flask + Socket.IO server (port 8000)
├── auth.py              ← JWT authentication, role-based access
├── database.py          ← SQLite schema & helpers
├── log_generator.py     ← Simulated cybersecurity log emitter
├── pattern_detection.py ← Sliding-window attack pattern engine
├── llm_engine.py        ← Ollama AI explanation engine
├── requirements.txt     ← Python dependencies
├── start.sh             ← One-command startup script
└── aegisx-frontend.html ← Updated frontend (open in browser)
```

## Quick Start

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install & start Ollama (for AI explanations)

```bash
# Install Ollama from https://ollama.com
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (llama3 recommended, ~4GB)
ollama pull llama3

# Ollama runs automatically on http://localhost:11434
```

> **No Ollama?** The backend works without it — the LLM engine has a built-in
> rule-based fallback that provides solid explanations for every pattern type.

### 3. Start the backend

```bash
python app.py
# or
./start.sh
```

Backend starts on **http://localhost:8000**

### 4. Open the frontend

Open `aegisx-frontend.html` in your browser.

---

## REST API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | — | Health check |
| POST | `/auth/signup` | — | Register (individual or org_admin) |
| POST | `/auth/login` | — | Login → JWT |
| GET | `/auth/me` | JWT | Current user info |
| POST | `/auth/org/add-staff` | org_admin | Add staff member |
| POST | `/auth/org/remove-staff` | org_admin | Remove staff member |
| GET | `/auth/org/staff` | org_admin | List org staff |
| GET | `/logs?limit=50&offset=0` | — | Recent logs |
| GET | `/alerts?limit=50&offset=0` | — | Recent alerts |
| POST | `/explain` | — | AI explanation (chat or alert) |
| POST | `/simulate` | — | Trigger attack simulation |

### Example: Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@aegisx.ai","password":"Demo1234!"}'
```

### Example: Simulate brute force
```bash
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d '{"type":"brute_force"}'
```

### Example: AI explanation
```bash
curl -X POST http://localhost:8000/explain \
  -H "Content-Type: application/json" \
  -d '{"question":"What is a port scan attack?"}'
```

---

## WebSocket (Socket.IO)

Connect to `http://localhost:8000` using Socket.IO client.

**Events emitted by server:**
- `alert` → `{ip, pattern_type, severity, score, event_count, explanation, timestamp}`
- `log` → `{ip, event_type, location, user_id, ...}`
- `connected` → connection acknowledgement

**JavaScript example:**
```javascript
const socket = io('http://localhost:8000');
socket.on('alert', (alert) => {
  console.log('New alert:', alert.pattern_type, alert.severity);
});
```

---

## Auth Roles

| Role | Signup field | Capabilities |
|------|-------------|--------------|
| `individual` | `user_type: "individual"` | View logs & alerts for own data |
| `org_admin` | `user_type: "org_admin"` + `org_name` | Full org access, manage staff |
| `org_staff` | Added by admin via `/auth/org/add-staff` | Read-only org alert access |

### Demo account
- Email: `demo@aegisx.ai`
- Password: `Demo1234!`
- Role: `org_admin` (no database entry needed)

---

## Detection Engine

| Pattern | Window | Threshold | Risk Score |
|---------|--------|-----------|------------|
| Brute Force | 60 sec | >5 failed logins / IP | 40–100 |
| Port Scan | 30 sec | >10 distinct ports / IP | 50–95 |
| Geo Anomaly | 5 min | 2+ countries / user | 70 |
| Odd Time | instant | login 00:00–05:00 UTC | 30 |

Severity mapping: Low (<40), Medium (40–59), High (60–79), Critical (80+)

---

## Changing the Ollama Model

Edit `llm_engine.py`:
```python
OLLAMA_MODEL = "llama3"   # change to "mistral", "phi3", "gemma2", etc.
```

Available models: https://ollama.com/library
