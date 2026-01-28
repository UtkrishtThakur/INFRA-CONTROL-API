from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from config import settings
from db import init_db
from auth import router as auth_router
from projects import router as projects_router
from keys import router as keys_router
from metrics import router as metrics_router
from domains import router as domains_router
from worker import router as worker_router
from worker import traffic_router

logger = logging.getLogger("securex.main")

# =========================
# Lifespan (startup / shutdown)
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Control API")
    init_db()   # SAFE: does not crash app if DB is down
    yield
    # Shutdown
    logger.info("Shutting down Control API")

# =========================
# App
# =========================

app = FastAPI(
    title="Control API",
    version="v1",
    lifespan=lifespan,
)

# =========================
# Middleware
# =========================

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
app.include_router(projects_router)
app.include_router(domains_router)
app.include_router(keys_router)
app.include_router(metrics_router)
app.include_router(worker_router)
app.include_router(traffic_router)

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
