The Control API is the management layer of the Antigravity system.
It is responsible for managing projects, API keys, and configuration that is consumed by the Gateway (Worker).

This service does NOT handle user traffic.
It only manages metadata and securely serves configuration to workers.

🧠 Architecture Overview

Antigravity is split into three independent components:

Frontend (Dashboard)
        ↓
Control API (this repo)
        ↓
Worker / Gateway (Data Plane)
        ↓
Customer Backend (Upstream)


Control API responsibilities:

Project management

API key lifecycle (create / revoke)

Secure config distribution to workers

Acts as the single source of truth

✨ Features

🔐 Secure project & API key management

🔄 One API key per project (simple & safe)

🧠 Stateless workers powered by this config

⚡ Instant key revocation (no cache lag)

🧱 Clean separation of control plane & data plane

📦 Tech Stack

FastAPI

PostgreSQL

SQLAlchemy

Pydantic

JWT Authentication

REST API

📁 Project Structure
.
├── main.py            # FastAPI app entry
├── config.py          # Environment & settings
├── models.py          # SQLAlchemy models
├── schemas.py         # Pydantic schemas
├── auth.py            # Auth & JWT logic
├── db.py              # DB connection
├── projects.py        # Project routes
├── keys.py            # API key routes
├── internal/worker.py # Worker config endpoint
└── requirements.txt

🔐 Security Model

Raw API keys are never stored

Only hashed keys exist in the database

Worker access is protected via a shared secret

Internal endpoints are not exposed publicly

🌍 Environment Variables

Create a .env file:

ENV=development

DATABASE_URL=postgresql://user:password@host/dbname

JWT_SECRET_KEY=super-secret-jwt-key
JWT_ALGORITHM=HS256

# Worker authentication
WORKER_SECRET_KEY=super-long-random-string


⚠️ WORKER_SECRET_KEY must match the worker configuration.

▶️ Running Locally
1️⃣ Install dependencies
pip install -r requirements.txt

2️⃣ Run the server
uvicorn main:app --reload


Server will be available at:

http://127.0.0.1:8000

🔗 Important Endpoints
🔹 Authentication

POST /auth/register

POST /auth/login

🔹 Projects

POST /projects

GET /projects

DELETE /projects/{id}

🔹 API Keys

POST /projects/{id}/keys

DELETE /projects/{id}/keys/{key_id}

🔹 Worker Config (Internal)
GET /internal/worker/config
Headers:
x-worker-secret: <WORKER_SECRET_KEY>


Returns all active project configurations for workers.

🧠 Worker Integration

Workers periodically fetch config from this API:

GET /internal/worker/config


The response includes:

Project ID

Upstream URL

API key hashes

Workers keep this in memory and never query the database directly.

🚀 Deployment Notes

Deploy as a long-running backend service

Does NOT need horizontal scaling initially

Database migrations should be handled via Alembic in production

Must be deployed before workers

🧪 Status

✅ MVP Complete

🔄 Actively evolving

🚀 Production-ready foundation

🧠 Design Philosophy

“Control planes should be boring, predictable, and secure.”

This API is intentionally simple:

No traffic handling

No heavy computation

No runtime dependencies on workers
