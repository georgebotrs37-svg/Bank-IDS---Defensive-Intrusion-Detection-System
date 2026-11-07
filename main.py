import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db, SessionLocal
from backend.models import Analyst
from backend.threat_intel.threat_service import ThreatIntelligenceService
from backend.config import DEFAULT_ANALYSTS
from backend.api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize SQLite tables and seed data
    init_db()
    db = SessionLocal()
    try:
        # Seed Threat Intel IOCs
        threat_service = ThreatIntelligenceService(db)
        threat_service.seed_initial_iocs()

        # Seed Analysts if empty
        if db.query(Analyst).count() == 0:
            for a in DEFAULT_ANALYSTS:
                db.add(Analyst(name=a["name"], role=a["role"], email=a["email"]))
            db.commit()
    finally:
        db.close()
    yield
    # Shutdown logic if any


app = FastAPI(
    title="MR.X BANK SOC SENTINEL - API",
    description="Enterprise Banking Security Operations Center (SOC) & Defensive Intrusion Detection System API",
    version="2.4.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "platform": "MR.X BANK SOC SENTINEL",
        "description": "AI-Powered Defensive Banking Intrusion Detection System & SOC Platform",
        "docs_url": "/docs",
        "health_url": "/api/health",
        "stats_url": "/api/stats"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
