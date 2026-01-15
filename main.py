from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from config import settings
from db import Base, engine
from auth import router as auth_router
from projects import router as projects_router
from keys import router as keys_router
from metrics import router as metrics_router
from domains import router as domains_router
from worker import router as worker_router
from worker import traffic_router

# =========================
# Lifespan (startup / shutdown)
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    # In production, use Alembic. For now, create tables if invalid.
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown (nothing needed yet)


app = FastAPI(
    title="Control API",
    version="v1",
    lifespan=lifespan,
)


# =========================
# Middleware
# =========================

@app.middleware("http")
async def log_requests(request, call_next):
    print(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Local dev
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",

        # Production frontends
        "https://securex.devlooper.co.in",
        "https://devlooper.co.in",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Routers
# =========================

app.include_router(auth_router)
app.include_router(projects_router)  # /projects
app.include_router(domains_router)   # /projects/{id}/domains
app.include_router(keys_router)      # /projects/{id}/keys
app.include_router(metrics_router)   # /projects/{id}/metrics
app.include_router(worker_router)    # /internal/worker
app.include_router(traffic_router)   # /internal/traffic
    

# =========================
# Health Check
# =========================

@app.get("/health")
def health():
    return {
        "service": settings.SERVICE_NAME,
        "env": settings.ENV,
        "status": "ok",
    }
